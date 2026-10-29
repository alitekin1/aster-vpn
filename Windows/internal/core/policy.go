package core

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func ValidateResolver(s string) error {
	if _, e := netip.ParseAddr(s); e == nil {
		return nil
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("use an IP address or HTTPS DNS URL with an IP host")
	}
	if _, e = netip.ParseAddr(u.Hostname()); e != nil {
		return fmt.Errorf("DNS resolver must use an IP host to avoid bootstrap loops")
	}
	return nil
}
func ValidateSettings(s Settings) error {
	if !contains([]string{"smartIran", "globalProxy", "globalDirect", "reverse", "custom"}, s.Mode) || !contains([]string{"proxy", "direct", "block"}, s.DefaultAction) {
		return fmt.Errorf("invalid routing mode or default action")
	}
	if !contains([]string{"system", "light", "dark"}, s.Theme) {
		return fmt.Errorf("invalid theme")
	}
	if e := ValidateResolver(s.DNS.DirectResolver); e != nil {
		return e
	}
	return ValidateResolver(s.DNS.ProxyResolver)
}
func ValidateRule(r Rule) error {
	if strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Value) == "" {
		return fmt.Errorf("rule name and match value are required")
	}
	if !contains([]string{"proxy", "direct", "block"}, r.Action) {
		return fmt.Errorf("invalid rule action")
	}
	v := strings.TrimSpace(r.Value)
	switch r.Match {
	case "domain", "suffix":
		v = strings.TrimPrefix(v, "*.")
		if strings.ContainsAny(v, " /:*\t\n") || v == "" {
			return fmt.Errorf("enter a domain without scheme or path")
		}
	case "keyword":
	case "regex":
		if _, e := regexp.Compile(v); e != nil {
			return fmt.Errorf("invalid RE2 regular expression")
		}
	case "ip":
		if _, e := netip.ParseAddr(v); e != nil {
			return fmt.Errorf("invalid IP address")
		}
	case "cidr":
		if _, e := netip.ParsePrefix(v); e != nil {
			return fmt.Errorf("invalid CIDR")
		}
	case "geoip", "geosite":
		if !regexp.MustCompile(`^[a-zA-Z0-9@!:_-]+$`).MatchString(v) {
			return fmt.Errorf("invalid geographic category")
		}
	case "destinationPort":
		for _, seg := range strings.Split(v, ",") {
			p := strings.Split(seg, "-")
			if len(p) > 2 {
				return fmt.Errorf("invalid port range")
			}
			last := 0
			for _, b := range p {
				n, e := strconv.Atoi(b)
				if e != nil || n < 1 || n > 65535 || n < last {
					return fmt.Errorf("ports must be 1–65535 in ascending ranges")
				}
				last = n
			}
		}
	case "network":
		if !contains([]string{"tcp", "udp", "tcp,udp"}, v) {
			return fmt.Errorf("network must be tcp, udp or tcp,udp")
		}
	case "applicationProtocol":
		for _, p := range strings.Split(v, ",") {
			if !contains([]string{"http", "tls", "quic", "bittorrent"}, p) {
				return fmt.Errorf("unsupported sniffed protocol")
			}
		}
	default:
		return fmt.Errorf("unsupported match type")
	}
	allowed := []string{"domain", "ip", "port", "sourcePort", "network", "protocol", "source", "inboundTag", "user", "attrs", "localIP", "localPort"}
	for k := range r.AdditionalFields {
		if !contains(allowed, k) {
			return fmt.Errorf("advanced fields may only contain Xray match fields")
		}
	}
	return nil
}
func ruleFields(r Rule) Object {
	v := strings.TrimSpace(r.Value)
	f := Object{}
	switch r.Match {
	case "domain":
		f["domain"] = []string{"full:" + strings.ToLower(v)}
	case "suffix":
		f["domain"] = []string{"domain:" + strings.ToLower(strings.TrimPrefix(v, "*."))}
	case "keyword":
		f["domain"] = []string{"keyword:" + v}
	case "regex":
		f["domain"] = []string{"regexp:" + v}
	case "ip", "cidr":
		f["ip"] = []string{v}
	case "geoip":
		f["ip"] = []string{fallbackPrefix(v, "geoip:")}
	case "geosite":
		f["domain"] = []string{fallbackPrefix(v, "geosite:")}
	case "destinationPort":
		f["port"] = v
	case "network":
		f["network"] = v
	case "applicationProtocol":
		f["protocol"] = strings.Split(v, ",")
	}
	for k, v := range r.AdditionalFields {
		f[k] = v
	}
	return f
}
func fallbackPrefix(s, p string) string {
	if strings.HasPrefix(s, p) {
		return s
	}
	return p + s
}
func Compile(s State, iface string, systemResolvers []string) ([]byte, error) {
	if e := ValidateSettings(s.Settings); e != nil {
		return nil, e
	}
	if s.SelectedServerID == "" {
		return nil, fmt.Errorf("select a server before connecting")
	}
	required := map[string]bool{s.SelectedServerID: true}
	for _, r := range s.Rules {
		if r.Enabled && r.Action == "proxy" && r.ServerID != "" {
			required[r.ServerID] = true
		}
	}
	out := []Object{}
	hosts := []string{}
	for _, v := range s.Servers {
		if !required[v.ID] {
			continue
		}
		if v.Outbound == nil {
			return nil, fmt.Errorf("server credential unavailable")
		}
		delete(required, v.ID)
		o := CloneObject(v.Outbound)
		o["tag"] = "proxy-" + v.ID
		delete(o, "proxySettings")
		delete(o, "dialerProxy")
		st, _ := o["streamSettings"].(map[string]any)
		if st == nil {
			st = Object{}
		} // Never preserve imported bind/proxy socket settings.
		st["sockopt"] = Object{"interface": iface, "domainStrategy": "ForceIP"}
		o["streamSettings"] = st
		out = append(out, o)
		if _, e := netip.ParseAddr(v.Host); e != nil {
			hosts = append(hosts, "full:"+strings.ToLower(v.Host))
		}
	}
	if len(required) > 0 {
		return nil, fmt.Errorf("a routing rule references a missing server")
	}
	tag := func(action, id string) string {
		if action == "proxy" {
			return "proxy-" + fallback(id, s.SelectedServerID)
		}
		return action
	}
	fallbackAction := "proxy"
	switch s.Settings.Mode {
	case "globalDirect", "reverse":
		fallbackAction = "direct"
	case "custom":
		fallbackAction = s.Settings.DefaultAction
	}
	rules := []Object{}
	add := func(id string, f Object, t string) {
		f["type"] = "field"
		f["ruleTag"] = id
		f["outboundTag"] = t
		rules = append(rules, f)
	}
	add("dns-direct", Object{"inboundTag": []string{"dns-direct"}}, "direct")
	dnsProxy := tag("proxy", "")
	if fallbackAction == "direct" && s.Settings.Mode != "reverse" {
		dnsProxy = "direct"
	}
	add("dns-proxy", Object{"inboundTag": []string{"dns-proxy"}}, dnsProxy)
	add("dns-capture", Object{"ip": []string{"198.18.0.1", "fd00:6173:7465::1"}, "port": "53"}, "dns-out")
	direct := []string{s.Settings.DNS.DirectResolver}
	if s.Settings.DNS.UseSystemResolvers {
		direct = systemResolvers
	}
	if len(direct) == 0 {
		return nil, fmt.Errorf("no active adapter DNS found; configure a custom direct resolver")
	}
	for _, v := range append(append([]string{}, direct...), s.Settings.DNS.ProxyResolver) {
		if e := ValidateResolver(v); e != nil {
			return nil, e
		}
	}
	dnsServers := []Object{}
	dnsAdd := func(domains []string, action string) {
		address := s.Settings.DNS.ProxyResolver
		t := "dns-proxy"
		if action == "direct" {
			address = direct[0]
			t = "dns-direct"
		}
		d := Object{"address": address, "tag": t, "finalQuery": true}
		if len(domains) > 0 {
			d["domains"] = domains
			d["skipFallback"] = true
		}
		dnsServers = append(dnsServers, d)
	}
	if len(hosts) > 0 {
		dnsAdd(hosts, "direct")
	}
	for _, r := range s.Rules {
		if !r.Enabled {
			continue
		}
		if e := ValidateRule(r); e != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, e)
		}
		f := ruleFields(r)
		add(r.ID, f, tag(r.Action, r.ServerID))
		var domains []string
		switch a := f["domain"].(type) {
		case []string:
			domains = a
		case []any:
			for _, v := range a {
				domains = append(domains, str(v))
			}
		}
		if len(domains) > 0 {
			dnsAdd(domains, r.Action)
		}
	}
	if s.Settings.Mode == "smartIran" || s.Settings.Mode == "reverse" {
		a := "direct"
		if s.Settings.Mode == "reverse" {
			a = "proxy"
		}
		add("preset-ir-domain", Object{"domain": []string{"geosite:ir", "domain:ir"}}, tag(a, ""))
		add("preset-ir-ip", Object{"ip": []string{"geoip:ir"}}, tag(a, ""))
		add("preset-private", Object{"ip": []string{"geoip:private"}}, "direct")
		dnsAdd([]string{"geosite:ir", "domain:ir"}, a)
	}
	add("default", Object{"network": "tcp,udp"}, tag(fallbackAction, ""))
	dnsAdd(nil, fallbackAction)
	out = append(out, Object{"tag": "direct", "protocol": "freedom", "settings": Object{"domainStrategy": "UseIP"}, "streamSettings": Object{"sockopt": Object{"interface": iface, "domainStrategy": "ForceIP"}}}, Object{"tag": "block", "protocol": "blackhole", "settings": Object{"response": Object{"type": "none"}}}, Object{"tag": "dns-out", "protocol": "dns", "settings": Object{}})
	return json.Marshal(Object{"log": Object{"loglevel": "none"}, "dns": Object{"servers": dnsServers, "disableCache": !s.Settings.DNS.Cache, "queryStrategy": "UseIP", "disableFallbackIfMatch": true}, "routing": Object{"domainStrategy": "IPOnDemand", "domainMatcher": "hybrid", "rules": rules}, "outbounds": out})
}
func Conflicts(rules []Rule) []string {
	out := []string{}
	for i, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, p := range rules[:i] {
			if !p.Enabled {
				continue
			}
			a := strings.ToLower(strings.TrimPrefix(p.Value, "*."))
			b := strings.ToLower(strings.TrimPrefix(r.Value, "*."))
			if p.Match == r.Match && a == b || p.Match == "suffix" && (r.Match == "suffix" || r.Match == "domain") && (b == a || strings.HasSuffix(b, "."+a)) {
				out = append(out, r.Name+" is shadowed by earlier rule "+p.Name)
				break
			}
		}
	}
	return out
}
