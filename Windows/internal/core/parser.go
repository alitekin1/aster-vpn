package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

func decode64(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	b, e := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(s), "="))
	return string(b), e
}
func number(v any) int { n, _ := strconv.Atoi(fmt.Sprint(v)); return n }
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func makeServer(name, host string, port int, proto string, o Object) (Server, error) {
	if host == "" || port < 1 || port > 65535 {
		return Server{}, fmt.Errorf("a valid hostname and port (1–65535) are required")
	}
	if name == "" {
		name = host
	}
	delete(o, "tag")
	b, e := json.Marshal(o)
	if e != nil {
		return Server{}, e
	}
	fp := sha256.Sum256(b)
	return Server{ID: ID(), Name: name, Host: host, Port: port, Protocol: proto, Fingerprint: hex.EncodeToString(fp[:]), Outbound: o}, nil
}
func Parse(input string) ([]Server, error) { return parse(input, 0) }
func parse(input string, depth int) ([]Server, error) {
	if len(input) > 8*1024*1024 {
		return nil, fmt.Errorf("configuration exceeds 8 MB")
	}
	if depth > 2 {
		return nil, fmt.Errorf("invalid nested base64 subscription")
	}
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("paste a server link, Xray JSON or Clash YAML")
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return parseJSON(s)
	}
	if strings.Contains(s, "proxies:") {
		return parseClash(s)
	}
	if !strings.Contains(s, "://") {
		d, e := decode64(s)
		if e != nil {
			return nil, fmt.Errorf("unrecognized configuration")
		}
		return parse(d, depth+1)
	}
	out := []Server{}
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		v, e := parseLink(l)
		if e != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, e)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no servers found")
	}
	return out, nil
}
func parseLink(s string) (Server, error) {
	u, e := url.Parse(s)
	if e != nil {
		return Server{}, fmt.Errorf("malformed server link")
	}
	q := u.Query()
	proto := strings.ToLower(u.Scheme)
	if proto == "vmess" {
		return vmess(strings.TrimPrefix(s, "vmess://"))
	}
	if proto == "ss" {
		return shadowsocks(s)
	}
	if proto == "socks5" {
		proto = "socks"
	}
	if proto != "vless" && proto != "trojan" && proto != "socks" && proto != "http" && proto != "https" {
		return Server{}, fmt.Errorf("unsupported protocol %q", proto)
	}
	port, _ := strconv.Atoi(u.Port())
	host := u.Hostname()
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	o := Object{"protocol": proto}
	switch proto {
	case "vless":
		if !validUUID(user) {
			return Server{}, fmt.Errorf("VLESS requires a valid UUID")
		}
		v := Object{"id": user, "encryption": fallback(q.Get("encryption"), "none")}
		if f := q.Get("flow"); f != "" {
			v["flow"] = f
		}
		o["settings"] = Object{"vnext": []any{Object{"address": host, "port": port, "users": []any{v}}}}
	case "trojan":
		if user == "" {
			return Server{}, fmt.Errorf("Trojan password is missing")
		}
		o["settings"] = Object{"servers": []any{Object{"address": host, "port": port, "password": user}}}
		if q.Get("security") == "" {
			q.Set("security", "tls")
		}
	default:
		v := Object{"address": host, "port": port}
		if user != "" {
			v["users"] = []any{Object{"user": user, "pass": pass}}
		}
		o["settings"] = Object{"servers": []any{v}}
		if proto == "https" {
			proto = "http"
			o["protocol"] = "http"
			q.Set("security", "tls")
		}
	}
	stream, e := streamSettings(q, host)
	if e != nil {
		return Server{}, e
	}
	o["streamSettings"] = stream
	return makeServer(u.Fragment, host, port, proto, o)
}
func fallback(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil
}
func streamSettings(q url.Values, host string) (Object, error) {
	network := fallback(q.Get("type"), fallback(q.Get("net"), "tcp"))
	if !contains([]string{"tcp", "raw", "ws", "grpc", "xhttp", "httpupgrade"}, network) {
		return nil, fmt.Errorf("transport %q is unavailable; legacy h2 requires migration to XHTTP", network)
	}
	security := fallback(q.Get("security"), "none")
	if !contains([]string{"none", "tls", "reality"}, security) {
		return nil, fmt.Errorf("unsupported transport security")
	}
	s := Object{"network": network, "security": security}
	if security != "none" {
		tls := Object{"serverName": fallback(q.Get("sni"), host), "fingerprint": fallback(q.Get("fp"), "chrome")}
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		if security == "reality" {
			if q.Get("pbk") == "" {
				return nil, fmt.Errorf("REALITY requires a public key")
			}
			tls["publicKey"] = q.Get("pbk")
			tls["shortId"] = q.Get("sid")
			tls["spiderX"] = fallback(q.Get("spx"), "/")
		}
		s[security+"Settings"] = tls
	}
	switch network {
	case "ws":
		s["wsSettings"] = Object{"path": fallback(q.Get("path"), "/"), "headers": Object{"Host": fallback(q.Get("host"), host)}}
	case "grpc":
		s["grpcSettings"] = Object{"serviceName": fallback(q.Get("serviceName"), q.Get("path")), "multiMode": q.Get("mode") == "multi", "authority": fallback(q.Get("authority"), q.Get("host"))}
	case "xhttp":
		v := Object{"path": fallback(q.Get("path"), "/"), "host": fallback(q.Get("host"), host), "mode": fallback(q.Get("mode"), "auto")}
		if x := q.Get("extra"); x != "" {
			var extra Object
			if json.Unmarshal([]byte(x), &extra) != nil || extra == nil {
				return nil, fmt.Errorf("invalid XHTTP extra JSON")
			}
			v["extra"] = extra
		}
		s["xhttpSettings"] = v
	case "httpupgrade":
		s["httpupgradeSettings"] = Object{"path": fallback(q.Get("path"), "/"), "host": fallback(q.Get("host"), host)}
	case "tcp", "raw":
		if q.Get("headerType") == "http" {
			s["tcpSettings"] = Object{"header": Object{"type": "http", "request": Object{"path": []string{fallback(q.Get("path"), "/")}, "headers": Object{"Host": []string{fallback(q.Get("host"), host)}}}}}
		}
	}
	return s, nil
}
func vmess(s string) (Server, error) {
	raw, e := decode64(s)
	var v Object
	if e != nil || json.Unmarshal([]byte(raw), &v) != nil || !validUUID(str(v["id"])) || number(v["aid"]) != 0 {
		return Server{}, fmt.Errorf("VMess requires base64 JSON, valid UUID and alterId 0")
	}
	host := str(v["add"])
	q := url.Values{"type": {fallback(str(v["net"]), "tcp")}, "security": {fallback(str(v["tls"]), "none")}}
	for _, k := range []string{"host", "path", "sni", "alpn", "fp"} {
		if x := str(v[k]); x != "" {
			q.Set(k, x)
		}
	}
	stream, e := streamSettings(q, host)
	if e != nil {
		return Server{}, e
	}
	return makeServer(str(v["ps"]), host, number(v["port"]), "vmess", Object{"protocol": "vmess", "settings": Object{"vnext": []any{Object{"address": host, "port": number(v["port"]), "users": []any{Object{"id": v["id"], "alterId": 0, "security": fallback(str(v["scy"]), "auto")}}}}}, "streamSettings": stream})
}
func shadowsocks(s string) (Server, error) {
	raw := strings.TrimPrefix(s, "ss://")
	fragment := ""
	if i := strings.Index(raw, "#"); i >= 0 {
		fragment, _ = url.PathUnescape(raw[i+1:])
		raw = raw[:i]
	}
	if !strings.Contains(raw, "@") {
		d, e := decode64(raw)
		if e != nil {
			return Server{}, fmt.Errorf("invalid Shadowsocks base64")
		}
		raw = d
	}
	u, e := url.Parse("ss://" + raw)
	if e != nil || u.User == nil {
		return Server{}, fmt.Errorf("invalid Shadowsocks link")
	}
	if u.Query().Get("plugin") != "" {
		return Server{}, fmt.Errorf("Shadowsocks plugins are unsupported")
	}
	method := u.User.Username()
	pass, ok := u.User.Password()
	if !ok {
		d, e := decode64(method)
		if e != nil {
			return Server{}, fmt.Errorf("invalid Shadowsocks credentials")
		}
		method, pass, ok = strings.Cut(d, ":")
	}
	if !ok || pass == "" {
		return Server{}, fmt.Errorf("missing Shadowsocks password")
	}
	port, _ := strconv.Atoi(u.Port())
	return makeServer(fragment, u.Hostname(), port, "shadowsocks", Object{"protocol": "shadowsocks", "settings": Object{"servers": []any{Object{"address": u.Hostname(), "port": port, "method": method, "password": pass}}}})
}
func parseJSON(s string) ([]Server, error) {
	var raw any
	if json.Unmarshal([]byte(s), &raw) != nil {
		return nil, fmt.Errorf("invalid Xray JSON")
	}
	var list []any
	switch v := raw.(type) {
	case map[string]any:
		if a, ok := v["outbounds"].([]any); ok {
			list = a
		} else {
			list = []any{v}
		}
	case []any:
		list = v
	default:
		return nil, fmt.Errorf("expected Xray object or outbound list")
	}
	out := []Server{}
	for _, v := range list {
		o, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid outbound")
		}
		p := str(o["protocol"])
		if contains([]string{"freedom", "blackhole", "dns", "loopback"}, p) {
			continue
		}
		if !contains([]string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http"}, p) {
			return nil, fmt.Errorf("unsupported Xray outbound protocol %q", p)
		}
		settings, _ := o["settings"].(map[string]any)
		arr, _ := settings["servers"].([]any)
		if p == "vless" || p == "vmess" {
			arr, _ = settings["vnext"].([]any)
		}
		if len(arr) != 1 {
			return nil, fmt.Errorf("each imported outbound must have exactly one server")
		}
		endpoint, _ := arr[0].(map[string]any)
		server, e := makeServer(str(o["tag"]), str(endpoint["address"]), number(endpoint["port"]), p, o)
		if e != nil {
			return nil, e
		}
		out = append(out, server)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no proxy outbounds found")
	}
	return out, nil
}
func parseClash(s string) ([]Server, error) {
	var v struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.UnmarshalStrict([]byte(s), &v) != nil { // full Clash files have unrelated root keys
		var root map[string]any
		if yaml.Unmarshal([]byte(s), &root) != nil {
			return nil, fmt.Errorf("invalid Clash YAML")
		}
		b, _ := yaml.Marshal(root["proxies"])
		if yaml.Unmarshal(b, &v.Proxies) != nil {
			return nil, fmt.Errorf("invalid Clash proxies")
		}
	}
	out := []Server{}
	for _, p := range v.Proxies {
		proto := str(p["type"])
		host := str(p["server"])
		port := number(p["port"])
		name := str(p["name"])
		q := url.Values{}
		o := Object{}
		if str(p["plugin"]) != "" || str(p["dialer-proxy"]) != "" {
			return nil, fmt.Errorf("Clash plugins and outbound chaining are unsupported")
		}
		switch proto {
		case "ss":
			o = Object{"protocol": "shadowsocks", "settings": Object{"servers": []any{Object{"address": host, "port": port, "method": p["cipher"], "password": p["password"]}}}}
			proto = "shadowsocks"
		case "vless", "vmess":
			if !validUUID(str(p["uuid"])) {
				return nil, fmt.Errorf("Clash %s requires UUID", proto)
			}
			if number(p["alterId"]) != 0 {
				return nil, fmt.Errorf("VMess alterId must be 0")
			}
			user := Object{"id": p["uuid"]}
			if proto == "vless" {
				user["encryption"] = "none"
				if x := str(p["flow"]); x != "" {
					user["flow"] = x
				}
			} else {
				user["security"] = fallback(str(p["cipher"]), "auto")
			}
			o = Object{"protocol": proto, "settings": Object{"vnext": []any{Object{"address": host, "port": port, "users": []any{user}}}}}
		case "trojan":
			o = Object{"protocol": proto, "settings": Object{"servers": []any{Object{"address": host, "port": port, "password": p["password"]}}}}
			q.Set("security", "tls")
		case "socks5", "http":
			if proto == "socks5" {
				proto = "socks"
			}
			endpoint := Object{"address": host, "port": port}
			if x := str(p["username"]); x != "" {
				endpoint["users"] = []any{Object{"user": x, "pass": str(p["password"])}}
			}
			o = Object{"protocol": proto, "settings": Object{"servers": []any{endpoint}}}
		default:
			return nil, fmt.Errorf("unsupported Clash proxy type %q", proto)
		}
		if b, _ := p["tls"].(bool); b {
			q.Set("security", "tls")
		}
		if b, _ := p["skip-cert-verify"].(bool); b {
			return nil, fmt.Errorf("insecure TLS skip-cert-verify is not accepted")
		}
		q.Set("sni", fallback(str(p["servername"]), str(p["sni"])))
		q.Set("type", fallback(str(p["network"]), "tcp"))
		if ws, ok := p["ws-opts"].(map[interface{}]interface{}); ok {
			q.Set("path", str(ws["path"]))
			if h, ok := ws["headers"].(map[interface{}]interface{}); ok {
				q.Set("host", str(h["Host"]))
			}
		}
		if grpc, ok := p["grpc-opts"].(map[interface{}]interface{}); ok {
			q.Set("serviceName", str(grpc["grpc-service-name"]))
		}
		if reality, ok := p["reality-opts"].(map[interface{}]interface{}); ok {
			q.Set("security", "reality")
			q.Set("pbk", str(reality["public-key"]))
			q.Set("sid", str(reality["short-id"]))
		}
		q.Set("fp", str(p["client-fingerprint"]))
		st, e := streamSettings(q, host)
		if e != nil {
			return nil, e
		}
		o["streamSettings"] = st
		server, e := makeServer(name, host, port, proto, o)
		if e != nil {
			return nil, e
		}
		out = append(out, server)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Clash proxy entries")
	}
	return out, nil
}
func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func Endpoint(s Server) string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
