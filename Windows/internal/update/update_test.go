package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type roundtrip func(*http.Request) (*http.Response, error)

func (f roundtrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixture(t *testing.T) (*Client, map[string]string, []byte, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("MZ offline installer fixture; never executed")
	h := sha256.Sum256(data)
	name, _ := AssetName("amd64")
	repo := "fixture/aster"
	asset := Asset{name, releaseURL(repo, "0.3.0", name), hex.EncodeToString(h[:]), int64(len(data))}
	m := Manifest{1, repo, "0.3.0", time.Now().UTC(), "New version", map[string]Asset{"amd64": asset}}
	raw, _ := json.Marshal(m)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	api, _ := json.Marshal(map[string]any{"tag_name": "v0.3.0", "assets": []any{map[string]string{"name": "update.json", "browser_download_url": releaseURL(repo, "0.3.0", "update.json")}, map[string]string{"name": "update.json.sig", "browser_download_url": releaseURL(repo, "0.3.0", "update.json.sig")}, map[string]string{"name": name, "browser_download_url": asset.URL}}})
	responses := map[string]string{"https://api.github.com/repos/" + repo + "/releases/latest": string(api), releaseURL(repo, "0.3.0", "update.json"): string(raw), releaseURL(repo, "0.3.0", "update.json.sig"): sig, asset.URL: string(data)}
	c := &Client{repo, pub, &http.Client{Transport: roundtrip(func(r *http.Request) (*http.Response, error) {
		body, ok := responses[r.URL.String()]
		if !ok {
			t.Fatalf("unexpected URL %s", r.URL)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("GitHub token sent")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	}), CheckRedirect: secureRedirect}}
	return c, responses, raw, key
}
func TestVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"0.2.0", "0.1.9", 1}, {"0.2.0", "0.2.0", 0}, {"0.2.0", "1.0.0", -1}, {"1.10.0", "1.9.9", 1}} {
		got, e := CompareVersions(tc.a, tc.b)
		if e != nil || got != tc.want {
			t.Fatal(tc, got, e)
		}
	}
	for _, bad := range []string{"v1.0.0", "1.0.0-beta", "1.0", "01.0.0", "1.0.0/../../cmd", "4294967296.0.0"} {
		if _, e := CompareVersions(bad, "1.0.0"); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
func TestAuthenticCheckAndDownload(t *testing.T) {
	c, _, _, _ := fixture(t)
	offer, e := c.Check(context.Background(), "0.2.0", "amd64")
	if e != nil || !offer.Available || offer.Version != "0.3.0" {
		t.Fatal(offer, e)
	}
	path, e := c.Download(context.Background(), offer, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil || !strings.HasPrefix(string(b), "MZ") {
		t.Fatal(e)
	}
	public, _ := json.Marshal(offer)
	if strings.Contains(string(public), "sha256") || strings.Contains(string(public), "/releases/download") {
		t.Fatal("executable metadata exposed to UI")
	}
}
func TestRejectTamperedManifestAndWrongKey(t *testing.T) {
	for _, kind := range []string{"manifest", "signature", "key"} {
		t.Run(kind, func(t *testing.T) {
			c, r, _, _ := fixture(t)
			switch kind {
			case "manifest":
				p := releaseURL(c.Repository, "0.3.0", "update.json")
				r[p] = strings.ReplaceAll(r[p], "New version", "Tampered")
			case "signature":
				r[releaseURL(c.Repository, "0.3.0", "update.json.sig")] = "invalid"
			case "key":
				c.Key = make([]byte, ed25519.PublicKeySize)
			}
			if _, e := c.Check(context.Background(), "0.2.0", "amd64"); e == nil {
				t.Fatal("tampered update accepted")
			}
		})
	}
}
func TestRejectInstallerTamperingAndTruncation(t *testing.T) {
	for _, body := range []string{"MZ corrupted", strings.Repeat("x", 1000)} {
		c, r, _, _ := fixture(t)
		offer, e := c.Check(context.Background(), "0.2.0", "amd64")
		if e != nil {
			t.Fatal(e)
		}
		r[offer.Asset.URL] = body
		dir := t.TempDir()
		if p, e := c.Download(context.Background(), offer, dir); e == nil || p != "" {
			t.Fatal("tampered installer accepted")
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatal("failed download was retained")
		}
	}
}
func TestNoDowngradeOrWrongArchitecture(t *testing.T) {
	c, _, _, _ := fixture(t)
	for _, version := range []string{"0.3.0", "1.0.0"} {
		offer, e := c.Check(context.Background(), version, "amd64")
		if e != nil || offer.Available {
			t.Fatal("offered downgrade", offer, e)
		}
	}
	if _, e := c.Check(context.Background(), "0.2.0", "arm64"); e == nil {
		t.Fatal("wrong-architecture installer accepted")
	}
	if _, e := c.Check(context.Background(), "0.2.0", "386"); e == nil {
		t.Fatal("unsupported architecture")
	}
}
func TestRejectForeignURLsAndInvalidSignedMetadata(t *testing.T) {
	c, r, raw, key := fixture(t)
	var m Manifest
	_ = json.Unmarshal(raw, &m)
	a := m.Assets["amd64"]
	a.URL = "https://example.com/malware.exe"
	m.Assets["amd64"] = a
	b, _ := json.Marshal(m)
	r[releaseURL(c.Repository, "0.3.0", "update.json")] = string(b)
	r[releaseURL(c.Repository, "0.3.0", "update.json.sig")] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	if _, e := c.Check(context.Background(), "0.2.0", "amd64"); e == nil {
		t.Fatal("foreign URL accepted even with a valid signature")
	}
	req, _ := http.NewRequest("GET", "http://github.com/file", nil)
	if secureRedirect(req, nil) == nil {
		t.Fatal("HTTP redirect accepted")
	}
	req, _ = http.NewRequest("GET", "https://evil.example/file", nil)
	if secureRedirect(req, nil) == nil {
		t.Fatal("foreign redirect accepted")
	}
}
func TestCancellation(t *testing.T) {
	c, _, _, _ := fixture(t)
	offer, e := c.Check(context.Background(), "0.2.0", "amd64")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Download(ctx, offer, t.TempDir()); e == nil {
		t.Fatal("canceled download accepted")
	}
}
