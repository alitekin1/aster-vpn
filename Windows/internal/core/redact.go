package core

import "regexp"

var redactions = []*regexp.Regexp{regexp.MustCompile(`(?i)(vless|vmess|ss|trojan|socks5?|https?)://[^\s"<>]+`), regexp.MustCompile(`(?i)(password|uuid|token|publicKey|shortId|authorization|"id")\s*["\s:=]+[^\s,}"]+`), regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)}

func Redact(s string) string {
	for _, r := range redactions {
		s = r.ReplaceAllString(s, "[redacted]")
	}
	return s
}
