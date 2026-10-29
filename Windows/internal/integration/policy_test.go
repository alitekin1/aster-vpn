package integration

import (
	"aster/windows/internal/core"
	"aster/windows/internal/packet"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestWindowsPoliciesInRealXray(t *testing.T) {
	servers, e := core.Parse("socks5://127.0.0.1:1080#Offline policy fixture")
	if e != nil {
		t.Fatal(e)
	}
	assets, e := filepath.Abs("../../../Resources/GeoData")
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name, mode, host, want string
		rules                  []core.Rule
	}{
		{name: "Iran domain direct", mode: "smartIran", host: "nic.ir", want: "direct"},
		{name: "International IP proxy", mode: "smartIran", host: "8.8.8.8", want: "proxy-" + servers[0].ID},
		{name: "Private IP direct", mode: "smartIran", host: "192.168.1.1", want: "direct"},
		{name: "Reverse Iran proxy", mode: "reverse", host: "nic.ir", want: "proxy-" + servers[0].ID},
		{name: "Global direct", mode: "globalDirect", host: "8.8.8.8", want: "direct"},
		{name: "Explicit block before Iran preset", mode: "smartIran", host: "nic.ir", want: "block", rules: []core.Rule{{ID: "block-iran", Name: "Explicit block", Enabled: true, Match: "suffix", Value: "nic.ir", Action: "block"}}},
		{name: "Custom default block", mode: "custom", host: "8.8.8.8", want: "block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := core.DefaultState()
			s.Servers = servers
			s.SelectedServerID = servers[0].ID
			s.Settings.Mode = tc.mode
			s.Rules = tc.rules
			if tc.mode == "custom" {
				s.Settings.DefaultAction = "block"
			}
			raw, e := core.Compile(s, "", []string{"1.1.1.1"})
			if e != nil {
				t.Fatal(e)
			}
			engine, e := packet.New(raw, assets)
			if e != nil {
				t.Fatal("real Xray rejected compiled Windows policy", e)
			}
			defer engine.Close()
			q, _ := json.Marshal(core.Object{"host": tc.host, "port": 443})
			result, e := engine.Inspect(q)
			if e != nil {
				t.Fatal(e)
			}
			var decision struct {
				Outbound string `json:"outbound"`
			}
			if json.Unmarshal(result, &decision) != nil || decision.Outbound != tc.want {
				t.Fatalf("route %s, expected %s", result, tc.want)
			}
		})
	}
}
