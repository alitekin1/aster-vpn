package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const uuid = "00000000-0000-4000-8000-000000000001"

func TestImportProtocolsAndTransports(t *testing.T) {
	cases := []struct{ name, input, protocol string }{
		{"vless", "vless://" + uuid + "@example.com:443?security=reality&pbk=public-test-key&sid=ab&type=grpc&serviceName=test#Office", "vless"},
		{"trojan", "trojan://test-password@example.com:443?type=ws&path=%2Fhello", "trojan"},
		{"socks", "socks5://test:password@[::1]:1080", "socks"},
		{"https", "https://test:password@example.com:443", "http"},
		{"ss", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test-password")) + "@example.com:443#Home", "shadowsocks"},
		{"vmess", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"example.com","port":"443","id":"`+uuid+`","aid":"0","net":"ws","tls":"tls","path":"/ws"}`)), "vmess"},
		{"json", `{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"Imported","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1080}]}}]}`, "socks"},
		{"clash", "mixed-port: 7890\nproxies:\n  - name: Hello\n    type: trojan\n    server: example.com\n    port: 443\n    password: test-password\n    network: ws\n    ws-opts:\n      path: /ws\n", "trojan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, e := Parse(tc.input)
			if e != nil {
				t.Fatal(e)
			}
			if len(s) != 1 || s[0].Protocol != tc.protocol || s[0].Outbound == nil {
				t.Fatalf("unexpected import: %+v", s)
			}
			again, e := Parse(tc.input)
			if e != nil || again[0].Fingerprint != s[0].Fingerprint {
				t.Fatal("unstable fingerprint")
			}
			b, _ := json.Marshal(s[0])
			if strings.Contains(string(b), "test-password") || strings.Contains(string(b), uuid) {
				t.Fatal("credential escaped into UI metadata")
			}
		})
	}
}
func TestInvalidImports(t *testing.T) {
	for _, s := range []string{"vless://invalid@example.com:443", "trojan://password@example.com:0", "vless://" + uuid + "@example.com:443?type=h2", "ss://aes-256-gcm:pass@example.com:443?plugin=unsafe", `{"protocol":"socks","settings":{"servers":[{"address":"example.com","port":1},{"address":"other.test","port":2}]}}`, "proxies:\n  - name: bad\n    type: hysteria2\n", strings.Repeat("a", 8*1024*1024+1)} {
		if _, e := Parse(s); e == nil {
			t.Fatalf("accepted invalid input %.100s", s)
		}
	}
}
func TestBase64AndAtomicImport(t *testing.T) {
	s := "trojan://password@example.com:443#A"
	v, e := Parse(base64.RawStdEncoding.EncodeToString([]byte(s + "\n" + s)))
	if e != nil || len(v) != 2 {
		t.Fatal(e)
	}
	if v, e = Parse(s + "\nunsupported://foo"); e == nil || v != nil {
		t.Fatal("partial import accepted")
	}
}
func testState(t *testing.T) State {
	t.Helper()
	v, e := Parse("socks5://127.0.0.1:1080#Local")
	if e != nil {
		t.Fatal(e)
	}
	s := DefaultState()
	s.Servers = v
	s.SelectedServerID = v[0].ID
	return s
}
func TestPolicyPrecedenceBindingAndDNS(t *testing.T) {
	s := testState(t)
	s.Rules = []Rule{{ID: "personal", Name: "Local override", Group: "Personal", Enabled: true, Match: "suffix", Value: "example.ir", Action: "block"}}
	b, e := Compile(s, "Ethernet", []string{"192.168.1.1"})
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Routing   struct{ Rules []Object }
		Outbounds []Object
		DNS       struct{ Servers []Object }
	}
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("invalid JSON")
	}
	var tags []string
	for _, r := range c.Routing.Rules {
		tags = append(tags, r["ruleTag"].(string))
	}
	want := "dns-direct,dns-proxy,dns-capture,personal,preset-ir-domain,preset-ir-ip,preset-private,default"
	if strings.Join(tags, ",") != want {
		t.Fatalf("precedence: %v", tags)
	}
	for _, o := range c.Outbounds {
		if o["protocol"] == "socks" || o["protocol"] == "freedom" {
			st := o["streamSettings"].(map[string]any)
			opt := st["sockopt"].(map[string]any)
			if opt["interface"] != "Ethernet" || opt["domainStrategy"] != "ForceIP" {
				t.Fatal("outbound can loop into VPN")
			}
		}
	}
	if c.DNS.Servers[0]["finalQuery"] != true {
		t.Fatal("DNS can cross privacy boundary")
	}
}
func TestAllModesAndMissingPins(t *testing.T) {
	for _, mode := range []string{"smartIran", "globalProxy", "globalDirect", "custom", "reverse"} {
		s := testState(t)
		s.Settings.Mode = mode
		b, e := Compile(s, "Ethernet", []string{"1.1.1.1"})
		if e != nil {
			t.Fatal(e)
		}
		var c struct{ Routing struct{ Rules []Object } }
		_ = json.Unmarshal(b, &c)
		last := c.Routing.Rules[len(c.Routing.Rules)-1]["outboundTag"].(string)
		direct := mode == "globalDirect" || mode == "reverse"
		if direct != (last == "direct") {
			t.Fatalf("%s fallback %s", mode, last)
		}
	}
	s := testState(t)
	s.Rules = []Rule{{ID: "x", Name: "Pinned", Enabled: true, Match: "suffix", Value: "example.com", Action: "proxy", ServerID: "missing"}}
	if _, e := Compile(s, "Ethernet", []string{"1.1.1.1"}); e == nil {
		t.Fatal("missing pinned server silently accepted")
	}
}
func TestRuleValidation(t *testing.T) {
	for _, r := range []Rule{{Name: "x", Match: "cidr", Value: "1.2.3.4/80", Action: "proxy"}, {Name: "x", Match: "regex", Value: "(?<=x)y", Action: "proxy"}, {Name: "x", Match: "destinationPort", Value: "100-1", Action: "proxy"}, {Name: "x", Match: "suffix", Value: "https://example.com", Action: "direct"}, {Name: "x", Match: "suffix", Value: "example.com", Action: "direct", AdditionalFields: Object{"outboundTag": "bypass"}}} {
		if ValidateRule(r) == nil {
			t.Fatalf("invalid rule accepted %+v", r)
		}
	}
	for _, s := range []string{"tls://1.1.1.1", "https://dns.example.com/dns-query", "https://user:pass@1.1.1.1/dns-query"} {
		if ValidateResolver(s) == nil {
			t.Fatalf("unsafe resolver %s", s)
		}
	}
	s := testState(t)
	if _, e := Compile(s, "Ethernet", nil); e == nil {
		t.Fatal("missing system resolver accepted")
	}
}
func TestMergePreservesPinnedAndFavorites(t *testing.T) {
	s := testState(t)
	s.Servers[0].SubscriptionID = "sub"
	s.Servers[0].Favorite = true
	s.Servers[0].CustomName = "Mine"
	old := s.Servers[0]
	incoming := old
	incoming.ID = ID()
	incoming.Favorite = false
	incoming.CustomName = ""
	s.Merge([]Server{incoming, incoming}, "sub")
	if len(s.Servers) != 1 || s.Servers[0].ID != old.ID || !s.Servers[0].Favorite || s.Servers[0].CustomName != "Mine" {
		t.Fatal("preferences lost")
	}
	s.Rules = []Rule{{ServerID: old.ID}}
	s.Merge(nil, "sub")
	if len(s.Servers) != 1 {
		t.Fatal("pinned server removed")
	}
}
func TestEncryptedPayloadRoundTripAndRedaction(t *testing.T) {
	s := testState(t)
	s.Subscriptions = []Subscription{{ID: "sub", Name: "Test", URL: "https://example.com/secret-token"}}
	b, e := EncodeState(s)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := DecodeState(b)
	if e != nil || restored.Servers[0].Outbound == nil || restored.Subscriptions[0].URL != s.Subscriptions[0].URL {
		t.Fatal("disk secrets not restored")
	}
	ui, _ := json.Marshal(restored)
	if strings.Contains(string(ui), "secret-token") {
		t.Fatal("URL in UI payload")
	}
	for _, raw := range []string{"https://example.com/secret-token", `password: secret-password`, uuid} {
		r := Redact(raw)
		if strings.Contains(r, "secret-") || strings.Contains(r, uuid) {
			t.Fatal("redaction failed")
		}
	}
	p := filepath.Join(t.TempDir(), "state.dat")
	for i := 0; i < 2; i++ {
		if e := AtomicWrite(p, []byte("encrypted-test")); e != nil {
			t.Fatal(e)
		}
	}
	if b, e := os.ReadFile(p); e != nil || string(b) != "encrypted-test" {
		t.Fatal("atomic replace failed")
	}
}
func TestSubscriptionHTTPSAndFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP subscription was fetched") }))
	defer server.Close()
	if _, e := FetchSubscription(context.Background(), server.URL); e == nil {
		t.Fatal("HTTP URL accepted")
	}
}
func TestShadowedRules(t *testing.T) {
	r := []Rule{{Name: "Parent", Match: "suffix", Value: "example.com", Enabled: true}, {Name: "Child", Match: "domain", Value: "a.example.com", Enabled: true}}
	if len(Conflicts(r)) != 1 {
		t.Fatal("shadowing undetected")
	}
}
