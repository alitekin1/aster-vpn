package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	router "github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func testConfig(t *testing.T, rules []map[string]any) []byte {
	t.Helper()
	rules = append(rules, map[string]any{"type": "field", "ruleTag": "default", "network": "tcp,udp", "outboundTag": "direct"})
	b, err := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestRoutingAndGeodata(t *testing.T) {
	dir := t.TempDir()
	ip, _ := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "IR", Cidr: []*router.CIDR{{Ip: []byte{5, 160, 0, 0}, Prefix: 12}}}}})
	site, _ := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "IR", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "varzesh3.com"}}}}})
	os.WriteFile(filepath.Join(dir, "geoip.dat"), ip, 0600)
	os.WriteFile(filepath.Join(dir, "geosite.dat"), site, 0600)
	rules := []map[string]any{
		{"type": "field", "ruleTag": "override", "domain": []string{"full:force.ir"}, "outboundTag": "block"},
		{"type": "field", "ruleTag": "geo-domain", "domain": []string{"geosite:ir", "domain:ir"}, "outboundTag": "direct"},
		{"type": "field", "ruleTag": "geo-ip", "ip": []string{"geoip:ir"}, "outboundTag": "direct"},
	}
	e, err := newEngine(testConfig(t, rules), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	cases := []struct{ host, rule, action string }{{"force.ir", "override", "block"}, {"bank.ir", "geo-domain", "direct"}, {"www.varzesh3.com", "geo-domain", "direct"}, {"5.160.10.1", "geo-ip", "direct"}, {"openai.com", "default", "direct"}, {"2606:4700::1111", "default", "direct"}}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			q, _ := json.Marshal(map[string]any{"host": c.host, "port": 443})
			out, err := inspect(e.instance, q)
			if err != nil {
				t.Fatal(err)
			}
			var r map[string]string
			json.Unmarshal(out, &r)
			if r["rule"] != c.rule || r["outbound"] != c.action {
				t.Fatalf("got %s", out)
			}
		})
	}
}
func peer(t *testing.T, e *engine) (*stack.Stack, func()) {
	t.Helper()
	link := channel.New(512, 1500, "")
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []struct {
		p      tcpip.NetworkProtocolNumber
		a      tcpip.Address
		prefix int
	}{{ipv4.ProtocolNumber, tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), 24}, {ipv6.ProtocolNumber, tcpip.AddrFrom16([16]byte{0xfd, 0, 0x61, 0x73, 0x74, 0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}), 64}} {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: addr.p, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr.a, PrefixLen: addr.prefix}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	pump := func(from *channel.Endpoint, to *channel.Endpoint) {
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			raw := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkt.DecRef()
			proto := ipv4.ProtocolNumber
			if raw[0]>>4 == 6 {
				proto = ipv6.ProtocolNumber
			}
			incoming := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			to.InjectInbound(proto, incoming)
			incoming.DecRef()
		}
	}
	go pump(link, e.link)
	go pump(e.link, link)
	return s, func() { cancel(); s.Close(); link.Close() }
}
func TestPacketBridgeTCPUDPIPv6(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1:0"
			family := ipv4.ProtocolNumber
			if network == "tcp6" {
				host = "[::1]:0"
				family = ipv6.ProtocolNumber
			}
			listener, err := net.Listen(network, host)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "real-packet-response") }))
			server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			addr := listener.Addr().(*net.TCPAddr)
			var config map[string]any
			json.Unmarshal(testConfig(t, nil), &config)
			config["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"redirect": addr.String()}
			raw, _ := json.Marshal(config)
			e, err := newEngine(raw, "")
			if err != nil {
				t.Fatal(err)
			}
			defer e.close()
			s, stop := peer(t, e)
			defer stop()
			dest := tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
			if network == "tcp6" {
				dest = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: dest, Port: uint16(addr.Port)}, family)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			response, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(response), "real-packet-response") {
				t.Fatalf("unexpected response %q", response)
			}
		})
	}
	t.Run("udp", func(t *testing.T) {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			buf := make([]byte, 1024)
			n, addr, err := listener.ReadFrom(buf)
			if err == nil {
				listener.WriteTo(buf[:n], addr)
			}
		}()
		addr := listener.LocalAddr().(*net.UDPAddr)
		var config map[string]any
		json.Unmarshal(testConfig(t, nil), &config)
		config["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"redirect": addr.String()}
		raw, _ := json.Marshal(config)
		e, err := newEngine(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		defer e.close()
		s, stop := peer(t, e)
		defer stop()
		c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: uint16(addr.Port)}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("packet-udp-echo"))
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "packet-udp-echo" {
			t.Fatal("UDP payload corrupted")
		}
	})
}
func TestLiveUserServer(t *testing.T) {
	if os.Getenv("ASTER_LIVE_TEST") != "1" {
		t.Skip("opt-in test requires user-authorized Keychain server")
	}
	// Secret stays in memory; never report URL, password or exit address.
	raw, err := exec.Command("security", "find-generic-password", "-s", "space.aster.validation", "-a", "user-test-server", "-w").Output()
	if err != nil {
		t.Fatal("Test server unavailable in Keychain")
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("Malformed test server")
	}
	auth, err := base64.StdEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatal("Invalid SS auth")
	}
	pair := strings.SplitN(string(auth), ":", 2)
	if len(pair) != 2 {
		t.Fatal("Invalid SS auth")
	}
	port := 0
	fmt.Sscan(u.Port(), &port)
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"tag": "proxy", "protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": u.Hostname(), "port": port, "method": pair[0], "password": pair[1]}}}}}}
	if iface := os.Getenv("ASTER_TEST_INTERFACE"); iface != "" {
		config["outbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{"sockopt": map[string]any{"interface": iface}}
	}
	b, _ := json.Marshal(config)
	instance, err := core.StartInstance("json", b)
	if err != nil {
		t.Fatal("Xray rejected test config")
	}
	defer instance.Close()
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dest, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, instance, dest)
	}}}
	response, err := client.Get("https://api64.ipify.org?format=json")
	if err != nil {
		t.Fatal("Authenticated proxy HTTPS request failed (credentials redacted)")
	}
	defer response.Body.Close()
	var result map[string]string
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || net.ParseIP(result["ip"]) == nil || response.StatusCode != 200 {
		t.Fatal("Proxy returned invalid HTTPS response")
	}
}

func TestSwiftCompiledPolicyWithRealIranData(t *testing.T) {
	raw, err := os.ReadFile("/tmp/aster-compiled-policy-test.json")
	if err != nil {
		t.Skip("run swift test first to generate compiler fixture")
	}
	assets, err := filepath.Abs("../Resources/GeoData")
	if err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(raw, assets)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	cases := []struct{ host, action string }{{"force.ir", "proxy-"}, {"bankmellat.ir", "direct"}, {"varzesh3.com", "direct"}, {"5.160.1.1", "direct"}, {"192.168.1.1", "direct"}, {"openai.com", "proxy-"}, {"ads.example.net", "block"}, {"fd00::1", "direct"}}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			q, _ := json.Marshal(map[string]any{"host": c.host, "port": 443})
			result, err := inspect(e.instance, q)
			if err != nil {
				t.Fatal(err)
			}
			var r map[string]string
			json.Unmarshal(result, &r)
			if !strings.HasPrefix(r["outbound"], c.action) {
				t.Fatalf("unexpected decision %s", result)
			}
		})
	}
}

func TestLiveUserServerOverPacketBridge(t *testing.T) {
	if os.Getenv("ASTER_LIVE_TEST") != "1" {
		t.Skip("requires opt-in live validation")
	}
	raw, err := exec.Command("security", "find-generic-password", "-s", "space.aster.validation", "-a", "user-test-server", "-w").Output()
	if err != nil {
		t.Fatal("Keychain test server unavailable")
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("Invalid test server")
	}
	auth, err := base64.StdEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatal("Invalid auth")
	}
	pair := strings.SplitN(string(auth), ":", 2)
	if len(pair) != 2 {
		t.Fatal("Invalid auth")
	}
	port := 0
	fmt.Sscan(u.Port(), &port)
	compiled, err := os.ReadFile("/tmp/aster-compiled-policy-test.json")
	if err != nil {
		t.Fatal("Run Swift compiler tests first")
	}
	var config map[string]any
	json.Unmarshal(compiled, &config)
	outbounds := config["outbounds"].([]any)
	tag := outbounds[0].(map[string]any)["tag"]
	outbounds[0] = map[string]any{"tag": tag, "protocol": "shadowsocks", "streamSettings": map[string]any{"network": "tcp", "sockopt": map[string]any{"domainStrategy": "ForceIP"}}, "settings": map[string]any{"servers": []any{map[string]any{"address": u.Hostname(), "port": port, "method": pair[0], "password": pair[1]}}}}
	config["dns"].(map[string]any)["servers"] = []any{map[string]any{"address": "https://1.1.1.1/dns-query", "domains": []string{"full:" + u.Hostname()}, "tag": "dns-direct", "skipFallback": true, "finalQuery": true}, map[string]any{"address": "https://1.1.1.1/dns-query", "tag": "dns-proxy", "finalQuery": true}}
	compiled, _ = json.Marshal(config)
	assets, _ := filepath.Abs("../Resources/GeoData")
	e, err := newEngine(compiled, assets)
	if err != nil {
		t.Fatal("Could not start compiled policy")
	}
	defer e.close()
	s, stop := peer(t, e)
	defer stop()
	// Query the exact tunnel DNS address over a real UDP packet, then use its answer.
	dc, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	dc.SetDeadline(time.Now().Add(20 * time.Second))
	query := new(dns.Msg)
	query.SetQuestion("api64.ipify.org.", dns.TypeA)
	queryBytes, _ := query.Pack()
	dc.Write(queryBytes)
	buf := make([]byte, 4096)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatal("Tunneled split DNS query failed")
	}
	answer := new(dns.Msg)
	if answer.Unpack(buf[:n]) != nil {
		t.Fatal("Invalid DNS response")
	}
	var ip net.IP
	for _, rr := range answer.Answer {
		if a, ok := rr.(*dns.A); ok {
			ip = a.A
			break
		}
	}
	if ip == nil {
		t.Fatal("No DNS A answer")
	}
	client := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.To4()), Port: 443}, ipv4.ProtocolNumber)
	}}}
	response, err := client.Get("https://api64.ipify.org?format=json")
	if err != nil {
		t.Fatal("HTTPS through packet bridge and live SS server failed")
	}
	defer response.Body.Close()
	var r map[string]string
	if json.NewDecoder(response.Body).Decode(&r) != nil || net.ParseIP(r["ip"]) == nil {
		t.Fatal("Invalid proxy HTTPS answer")
	}
}

func TestTCPHalfCloseReceivesResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		payload, _ := io.ReadAll(c)
		if string(payload) == "request-before-eof" {
			c.Write([]byte("response-after-eof"))
		}
	}()
	var config map[string]any
	json.Unmarshal(testConfig(t, nil), &config)
	config["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"redirect": listener.Addr().String()}
	raw, _ := json.Marshal(config)
	e, err := newEngine(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	s, stop := peer(t, e)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 8}), Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("request-before-eof"))
	c.CloseWrite()
	response, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response-after-eof" {
		t.Fatalf("half-close lost response: %q", response)
	}
}

func TestBlockingPacketReaderWakesOnShutdown(t *testing.T) {
	e, err := newEngine(testConfig(t, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	global.Lock()
	global.engine = e
	global.Unlock()
	returned := make(chan int, 1)
	go func() { returned <- int(AsterReadPacket(nil, 0)) }()
	select {
	case n := <-returned:
		t.Fatalf("idle reader woke without a packet: %d", n)
	case <-time.After(120 * time.Millisecond):
	}
	stopped := make(chan struct{})
	go func() { AsterStop(); close(stopped) }()
	select {
	case n := <-returned:
		if n != -1 {
			t.Fatalf("expected stopped reader, got %d", n)
		}
	case <-time.After(2 * time.Second):
		e.cancel()
		t.Fatal("reader did not wake on shutdown")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop deadlocked behind reader")
	}
}
