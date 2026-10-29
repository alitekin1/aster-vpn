// Release tooling keeps private signing keys outside the source tree.
package main

import (
	"aster/windows/internal/buildinfo"
	"aster/windows/internal/update"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func fail(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func keyFrom(path string) ed25519.PrivateKey {
	var b []byte
	var e error
	if v := os.Getenv("ASTER_UPDATE_SIGNING_KEY"); v != "" {
		b = []byte(v)
	} else {
		b, e = os.ReadFile(path)
		fail(e)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		fail(fmt.Errorf("invalid private-key PEM"))
	}
	raw, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	fail(e)
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		fail(fmt.Errorf("expected Ed25519 signing key"))
	}
	return key
}
func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("use keygen or sign"))
	}
	f := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyPath := f.String("key", "", "private key outside the source tree")
	dir := f.String("dir", "../build/windows", "installer directory")
	public := f.String("public", "internal/update/config.go", "public-key Go file")
	notes := f.String("notes", "Easy Windows setup and signed in-app updates.", "release notes")
	fail(f.Parse(os.Args[2:]))
	switch os.Args[1] {
	case "keygen":
		if *keyPath == "" {
			fail(fmt.Errorf("--key is required"))
		}
		if _, e := os.Stat(*keyPath); os.IsNotExist(e) {
			_, key, e := ed25519.GenerateKey(rand.Reader)
			fail(e)
			raw, e := x509.MarshalPKCS8PrivateKey(key)
			fail(e)
			fail(os.MkdirAll(filepath.Dir(*keyPath), 0700))
			out, e := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			fail(e)
			_, e = out.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
			fail(e)
			fail(out.Close())
		}
		key := keyFrom(*keyPath)
		pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		fail(os.WriteFile(*public, []byte("package update\n\n// PublicKey authenticates update manifests; the private key is never shipped.\nconst PublicKey = \""+pub+"\"\n"), 0644))
		fmt.Println("Public verification key written. Private key kept outside the repository.")
	case "sign":
		key := keyFrom(*keyPath)
		expected, e := base64.StdEncoding.DecodeString(update.PublicKey)
		fail(e)
		if !ed25519.PublicKey(expected).Equal(key.Public()) {
			fail(fmt.Errorf("release signing key does not match application verification key"))
		}
		m := update.Manifest{Schema: 1, Repository: buildinfo.Repository, Version: buildinfo.Version, PublishedAt: time.Now().UTC(), Notes: *notes, Assets: map[string]update.Asset{}}
		for _, arch := range []string{"amd64", "arm64"} {
			name, e := update.AssetName(arch)
			fail(e)
			b, e := os.ReadFile(filepath.Join(*dir, name))
			fail(e)
			h := sha256.Sum256(b)
			m.Assets[arch] = update.Asset{Name: name, URL: "https://github.com/" + buildinfo.Repository + "/releases/download/v" + buildinfo.Version + "/" + name, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))}
		}
		b, e := json.MarshalIndent(m, "", "  ")
		fail(e)
		b = append(b, '\n')
		sig := ed25519.Sign(key, b)
		fail(os.WriteFile(filepath.Join(*dir, "update.json"), b, 0644))
		fail(os.WriteFile(filepath.Join(*dir, "update.json.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644))
		fmt.Println("Signed update manifest for v" + buildinfo.Version)
	case "verify":
		raw, e := os.ReadFile(filepath.Join(*dir, "update.json"))
		fail(e)
		sig, e := os.ReadFile(filepath.Join(*dir, "update.json.sig"))
		fail(e)
		pub, e := base64.StdEncoding.DecodeString(update.PublicKey)
		fail(e)
		m, e := update.Verify(raw, sig, ed25519.PublicKey(pub), buildinfo.Repository, buildinfo.Version)
		fail(e)
		if len(m.Assets) != 2 {
			fail(fmt.Errorf("both Windows architectures are required"))
		}
		for _, asset := range m.Assets {
			b, e := os.ReadFile(filepath.Join(*dir, asset.Name))
			fail(e)
			h := sha256.Sum256(b)
			if int64(len(b)) != asset.Size || hex.EncodeToString(h[:]) != asset.SHA256 {
				fail(fmt.Errorf("installer hash/size mismatch: %s", asset.Name))
			}
		}
		fmt.Println("PASS: Ed25519 manifest and both installer hashes/sizes.")

	default:
		fail(fmt.Errorf("unknown release command"))
	}
}
