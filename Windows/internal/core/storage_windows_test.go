package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIEncryptedPersistence(t *testing.T) {
	s := testState(t)
	s.Subscriptions = []Subscription{{ID: "sub", Name: "Private", URL: "https://example.com/secret-token"}}
	path := filepath.Join(t.TempDir(), "state.dat")
	for i := 0; i < 2; i++ {
		if e := SaveState(path, s); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("secret-token")) || bytes.Contains(raw, []byte("servers")) {
		t.Fatal("plaintext state on disk")
	}
	got, e := LoadState(path)
	if e != nil || got.Subscriptions[0].URL != s.Subscriptions[0].URL || got.Servers[0].Outbound == nil {
		t.Fatal("DPAPI roundtrip failed", e)
	}
}
