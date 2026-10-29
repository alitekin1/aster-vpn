// Package update verifies an authenticated release manifest before downloading
// and checking the matching Windows installer. It never accepts GitHub tokens.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxInstallerSize int64 = 200 << 20

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Schema      int              `json:"schema"`
	Repository  string           `json:"repository"`
	Version     string           `json:"version"`
	PublishedAt time.Time        `json:"publishedAt"`
	Notes       string           `json:"notes"`
	Assets      map[string]Asset `json:"assets"`
}
type Offer struct {
	Available bool      `json:"available"`
	Version   string    `json:"version"`
	Notes     string    `json:"notes"`
	CheckedAt time.Time `json:"checkedAt"`
	Status    string    `json:"status"`
	Asset     Asset     `json:"-"`
}
type Client struct {
	Repository string
	Key        ed25519.PublicKey
	HTTP       *http.Client
}

func New(repository string) (*Client, error) {
	key, e := base64.StdEncoding.DecodeString(PublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("update signing key is unavailable")
	}
	return &Client{repository, key, &http.Client{Timeout: 120 * time.Second, CheckRedirect: secureRedirect}}, nil
}
func secureRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 || !downloadHost(req.URL) {
		return errors.New("unsafe update redirect")
	}
	return nil
}
func downloadHost(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}
func CompareVersions(a, b string) (int, error) {
	if !versionPattern.MatchString(a) || !versionPattern.MatchString(b) {
		return 0, errors.New("invalid release version")
	}
	aa := strings.Split(a, ".")
	bb := strings.Split(b, ".")
	for i := range aa {
		x, e := strconv.ParseUint(aa[i], 10, 32)
		if e != nil {
			return 0, e
		}
		y, e := strconv.ParseUint(bb[i], 10, 32)
		if e != nil {
			return 0, e
		}
		if x < y {
			return -1, nil
		}
		if x > y {
			return 1, nil
		}
	}
	return 0, nil
}
func (c *Client) get(ctx context.Context, address string, limit int64) ([]byte, error) {
	u, e := url.Parse(address)
	if e != nil || !downloadHost(u) {
		return nil, errors.New("untrusted update URL")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "Aster-Windows-Updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, e := c.HTTP.Do(req)
	if e != nil {
		return nil, errors.New("could not reach the GitHub update service")
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil, errors.New("no published release is available yet")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub update service returned HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("invalid update response size")
	}
	return b, nil
}
func releaseURL(repo, version, name string) string {
	return "https://github.com/" + repo + "/releases/download/v" + version + "/" + name
}
func AssetName(arch string) (string, error) {
	switch arch {
	case "amd64":
		return "Aster-Setup-x64.exe", nil
	case "arm64":
		return "Aster-Setup-ARM64.exe", nil
	}
	return "", errors.New("unsupported Windows architecture")
}
func (c *Client) Check(ctx context.Context, current, arch string) (Offer, error) {
	expectedName, e := AssetName(arch)
	if e != nil {
		return Offer{}, e
	}
	if _, e = CompareVersions(current, current); e != nil {
		return Offer{}, e
	}
	raw, e := c.get(ctx, "https://api.github.com/repos/"+c.Repository+"/releases/latest", 1<<20)
	if e != nil {
		return Offer{}, e
	}
	var r struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Draft || r.Prerelease || !strings.HasPrefix(r.Tag, "v") {
		return Offer{}, errors.New("invalid stable release metadata")
	}
	version := strings.TrimPrefix(r.Tag, "v")
	cmp, e := CompareVersions(version, current)
	if e != nil {
		return Offer{}, e
	}
	offer := Offer{Version: current, CheckedAt: time.Now().UTC(), Status: "Aster is up to date."}
	if cmp <= 0 {
		return offer, nil
	}
	urls := map[string]string{}
	for _, a := range r.Assets {
		if _, exists := urls[a.Name]; exists {
			return Offer{}, errors.New("ambiguous release assets")
		}
		urls[a.Name] = a.URL
	}
	for _, name := range []string{"update.json", "update.json.sig", expectedName} {
		if urls[name] != releaseURL(c.Repository, version, name) {
			return Offer{}, errors.New("release is missing trusted update assets")
		}
	}
	manifest, e := c.get(ctx, urls["update.json"], 64<<10)
	if e != nil {
		return Offer{}, e
	}
	signature, e := c.get(ctx, urls["update.json.sig"], 4096)
	if e != nil {
		return Offer{}, e
	}
	m, e := Verify(manifest, signature, c.Key, c.Repository, version)
	if e != nil {
		return Offer{}, e
	}
	asset, ok := m.Assets[arch]
	if !ok || asset.Name != expectedName || asset.URL != urls[expectedName] {
		return Offer{}, errors.New("no verified installer for this architecture")
	}
	return Offer{Available: true, Version: version, Notes: m.Notes, CheckedAt: time.Now().UTC(), Status: "A newer version is ready to install.", Asset: asset}, nil
}
func Verify(raw, sig []byte, key ed25519.PublicKey, repository, version string) (Manifest, error) {
	signature, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if e != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, raw, signature) {
		return Manifest{}, errors.New("update signature verification failed")
	}
	var m Manifest
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(&struct{}{}) != io.EOF || m.Schema != 1 || m.Repository != repository || m.Version != version || m.PublishedAt.IsZero() {
		return Manifest{}, errors.New("signed update manifest is invalid")
	}
	if _, e := CompareVersions(version, version); e != nil {
		return Manifest{}, e
	}
	for arch, asset := range m.Assets {
		name, e := AssetName(arch)
		if e != nil || asset.Name != name || asset.URL != releaseURL(repository, version, name) || !hashPattern.MatchString(asset.SHA256) || asset.Size <= 0 || asset.Size > MaxInstallerSize {
			return Manifest{}, errors.New("signed installer metadata is invalid")
		}
	}
	return m, nil
}
func (c *Client) Download(ctx context.Context, offer Offer, directory string) (path string, err error) {
	if !offer.Available {
		return "", errors.New("check for a newer version first")
	}
	a := offer.Asset
	if (a.Name != "Aster-Setup-x64.exe" && a.Name != "Aster-Setup-ARM64.exe") || a.Size <= 0 || a.Size > MaxInstallerSize || !hashPattern.MatchString(a.SHA256) {
		return "", errors.New("invalid installer metadata")
	}
	if a.URL != releaseURL(c.Repository, offer.Version, a.Name) {
		return "", errors.New("untrusted installer location")
	}
	u, e := url.Parse(a.URL)
	if e != nil || !downloadHost(u) {
		return "", errors.New("untrusted installer URL")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("User-Agent", "Aster-Windows-Updater")
	res, e := c.HTTP.Do(req)
	if e != nil {
		return "", errors.New("installer download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("installer download returned HTTP %d", res.StatusCode)
	}
	if e = os.MkdirAll(directory, 0700); e != nil {
		return "", e
	}
	stage, e := os.MkdirTemp(directory, "aster-update-")
	if e != nil {
		return "", e
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	path = filepath.Join(stage, a.Name)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, a.Size+1))
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return "", errors.New("could not save the installer")
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("installer integrity check failed; nothing was executed")
	}
	if e = ctx.Err(); e != nil {
		return "", e
	}
	return path, nil
}
