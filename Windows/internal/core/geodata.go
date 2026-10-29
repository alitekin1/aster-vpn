package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Manifest struct {
	Version   string            `json:"version"`
	SHA256    map[string]string `json:"sha256"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

func ActiveAssets(root, bundled string) (string, string) {
	b, e := os.ReadFile(filepath.Join(root, "current.json"))
	var m Manifest
	if e == nil && json.Unmarshal(b, &m) == nil && safeVersion(m.Version) {
		dir := filepath.Join(root, m.Version)
		if VerifyAssets(dir, m.SHA256) == nil {
			return dir, m.Version
		}
	}
	b, _ = os.ReadFile(filepath.Join(bundled, "version.txt"))
	return bundled, strings.TrimSpace(string(b))
}
func safeVersion(v string) bool {
	return v != "." && v != ".." && regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(v)
}
func VerifyAssets(dir string, hashes map[string]string) error {
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		if len(b) < 100 || hex.EncodeToString(h[:]) != strings.ToLower(hashes[name]) {
			return fmt.Errorf("routing database checksum mismatch")
		}
	}
	return nil
}
func UpdateAssets(ctx context.Context, root string) (Manifest, error) {
	client := http.Client{Timeout: 90 * time.Second, CheckRedirect: func(r *http.Request, v []*http.Request) error {
		if r.URL.Scheme != "https" || len(v) > 5 {
			return fmt.Errorf("unsafe database redirect")
		}
		return nil
	}}
	fetch := func(address string, limit int64) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "Aster-Windows/0.1.0")
		res, e := client.Do(req)
		if e != nil {
			return nil, fmt.Errorf("database HTTPS request failed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("database HTTP %d", res.StatusCode)
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
		if e != nil || int64(len(b)) > limit {
			return nil, fmt.Errorf("invalid database response size")
		}
		return b, nil
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	b, e := fetch("https://api.github.com/repos/Chocolate4U/Iran-v2ray-rules/releases/latest", 2<<20)
	if e != nil {
		return Manifest{}, e
	}
	if json.Unmarshal(b, &release) != nil || !safeVersion(release.Tag) {
		return Manifest{}, fmt.Errorf("invalid database release")
	}
	urls := map[string]string{}
	for _, a := range release.Assets {
		u, e := url.Parse(a.URL)
		if e == nil && u.Scheme == "https" && u.Host == "github.com" && strings.HasPrefix(u.Path, "/Chocolate4U/Iran-v2ray-rules/releases/download/") {
			urls[a.Name] = a.URL
		}
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return Manifest{}, e
	}
	stage, e := os.MkdirTemp(root, "staging-")
	if e != nil {
		return Manifest{}, e
	}
	defer os.RemoveAll(stage)
	m := Manifest{release.Tag, map[string]string{}, time.Now()}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if urls[name] == "" || urls[name+".sha256sum"] == "" {
			return Manifest{}, fmt.Errorf("release is missing data or checksums")
		}
		data, e := fetch(urls[name], 64<<20)
		if e != nil {
			return Manifest{}, e
		}
		sum, e := fetch(urls[name+".sha256sum"], 4096)
		if e != nil {
			return Manifest{}, e
		}
		fields := strings.Fields(string(sum))
		h := sha256.Sum256(data)
		if len(fields) == 0 || !strings.EqualFold(fields[0], hex.EncodeToString(h[:])) || len(data) < 100 {
			return Manifest{}, fmt.Errorf("database checksum mismatch; previous data retained")
		}
		m.SHA256[name] = fields[0]
		if e = os.WriteFile(filepath.Join(stage, name), data, 0600); e != nil {
			return Manifest{}, e
		}
	}
	target := filepath.Join(root, m.Version)
	if _, e = os.Stat(target); os.IsNotExist(e) {
		if e = os.Rename(stage, target); e != nil {
			return Manifest{}, e
		}
	}
	if e = VerifyAssets(target, m.SHA256); e != nil {
		return Manifest{}, e
	}
	b, _ = json.Marshal(m)
	if e = AtomicWrite(filepath.Join(root, "current.json"), b); e != nil {
		return Manifest{}, e
	}
	return m, nil
}
