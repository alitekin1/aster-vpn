package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	rsession "github.com/xtls/xray-core/features/routing/session"
	_ "github.com/xtls/xray-core/main/distro/all"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type engine struct {
	instance *core.Instance
	stack    *stack.Stack
	link     *channel.Endpoint
	ctx      context.Context
	cancel   context.CancelFunc
	upload   atomic.Uint64
	download atomic.Uint64
	active   atomic.Int64
	slots    chan struct{}
}

var global struct {
	sync.RWMutex
	engine *engine
}

func newEngine(config []byte, assets string) (*engine, error) {
	if assets != "" {
		os.Setenv("xray.location.asset", assets)
	}
	instance, err := core.StartInstance("json", config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &engine{instance: instance, ctx: ctx, cancel: cancel, link: channel.New(512, 1500, ""), slots: make(chan struct{}, 4096)}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	e.stack = s
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		select {
		case e.slots <- struct{}{}:
		default:
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			<-e.slots
			return
		}
		id := r.ID()
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		go e.forward(conn, id, false)
	}).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		r := udp.NewForwarderRequest(s, id, pkt)
		select {
		case e.slots <- struct{}{}:
		default:
			return false
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			<-e.slots
			return false
		}
		conn := gonet.NewUDPConn(&wq, ep)
		go e.forward(conn, r.ID(), true)
		return true
	})
	if err := s.CreateNIC(1, e.link); err != nil {
		e.close()
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	return e, nil
}
func (e *engine) forward(local net.Conn, id stack.TransportEndpointID, isUDP bool) {
	defer local.Close()
	defer func() { <-e.slots }()
	e.active.Add(1)
	defer e.active.Add(-1)
	dest := xnet.TCPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort))
	source := xnet.TCPDestination(xnet.IPAddress(id.RemoteAddress.AsSlice()), xnet.Port(id.RemotePort))
	if isUDP {
		dest.Network = xnet.Network_UDP
		source.Network = xnet.Network_UDP
	}
	ctx := session.ContextWithInbound(e.ctx, &session.Inbound{Tag: "packet", Name: "tun", Source: source})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled: true, OverrideDestinationForProtocol: []string{"http", "tls", "quic"}, RouteOnly: true,
	}})
	remote, err := core.Dial(ctx, e.instance, dest)
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-e.ctx.Done():
			local.Close()
			remote.Close()
		case <-done:
		}
	}()
	defer close(done)
	if isUDP {
		var lastActivity atomic.Int64
		lastActivity.Store(time.Now().UnixNano())
		go func() {
			idleTimer := time.NewTimer(60 * time.Second)
			defer idleTimer.Stop()
			for {
				select {
				case <-done:
					return
				case <-e.ctx.Done():
					return
				case <-idleTimer.C:
					remaining := 60*time.Second - time.Since(time.Unix(0, lastActivity.Load()))
					if remaining <= 0 {
						local.Close()
						remote.Close()
						return
					}
					idleTimer.Reset(remaining)
				}
			}
		}()
		copyUDP := func(dst, src net.Conn) {
			b := make([]byte, 65535)
			for {
				n, err := src.Read(b)
				if n > 0 {
					lastActivity.Store(time.Now().UnixNano())
					if _, werr := dst.Write(b[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}
		finished := make(chan struct{}, 1)
		go func() { copyUDP(remote, local); finished <- struct{}{} }()
		copyUDP(local, remote)
		local.Close()
		remote.Close()
		<-finished
	} else {
		finished := make(chan struct{}, 1)
		go func() {
			io.Copy(remote, local)
			if c, ok := remote.(interface{ CloseWrite() error }); ok {
				c.CloseWrite()
			} else {
				remote.Close()
			}
			finished <- struct{}{}
		}()
		io.Copy(local, remote)
		local.Close()
		remote.Close()
		<-finished
	}
}
func (e *engine) close() {
	e.cancel()
	if e.stack != nil {
		e.stack.Close()
	}
	if e.link != nil {
		e.link.Close()
	}
	e.instance.Close()
}
func errString(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

//export AsterStart
func AsterStart(config, assets *C.char) *C.char {
	global.Lock()
	defer global.Unlock()
	if global.engine != nil {
		return errString(errors.New("engine already running"))
	}
	e, err := newEngine([]byte(C.GoString(config)), C.GoString(assets))
	if err != nil {
		return errString(err)
	}
	global.engine = e
	return nil
}

//export AsterStop
func AsterStop() {
	global.Lock()
	defer global.Unlock()
	if global.engine != nil {
		global.engine.close()
		global.engine = nil
	}
}

//export AsterWritePacket
func AsterWritePacket(data unsafe.Pointer, count C.int) C.int {
	if count < 20 || count > 65535 {
		return -1
	}
	global.RLock()
	defer global.RUnlock()
	e := global.engine
	if e == nil {
		return -1
	}
	raw := C.GoBytes(data, count)
	var proto tcpip.NetworkProtocolNumber
	switch raw[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return -1
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	e.link.InjectInbound(proto, pkt)
	pkt.DecRef()
	e.upload.Add(uint64(count))
	return count
}

//export AsterReadPacket
func AsterReadPacket(out unsafe.Pointer, capacity C.int) C.int {
	global.RLock()
	e := global.engine
	global.RUnlock()
	if e == nil {
		return -1
	}
	// Block until a packet or shutdown; no 20 Hz idle timer. Release the lifecycle
	// lock before waiting so Stop can cancel this reader without a deadlock.
	pkt := e.link.ReadContext(e.ctx)
	if pkt == nil {
		return -1
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	raw := view.AsSlice()
	if len(raw) > int(capacity) {
		return -1
	}
	copy(unsafe.Slice((*byte)(out), int(capacity)), raw)
	e.download.Add(uint64(len(raw)))
	return C.int(len(raw))
}

//export AsterStats
func AsterStats() *C.char {
	global.RLock()
	defer global.RUnlock()
	e := global.engine
	if e == nil {
		return C.CString(`{"upload":0,"download":0,"active":0}`)
	}
	return C.CString(fmt.Sprintf(`{"upload":%d,"download":%d,"active":%d}`, e.upload.Load(), e.download.Load(), e.active.Load()))
}

//export AsterInspect
func AsterInspect(query *C.char) *C.char {
	global.RLock()
	defer global.RUnlock()
	if global.engine == nil {
		return C.CString(`{"error":"Connect to inspect the active policy."}`)
	}
	result, err := inspect(global.engine.instance, []byte(C.GoString(query)))
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return C.CString(string(b))
	}
	return C.CString(string(result))
}
func inspect(instance *core.Instance, query []byte) ([]byte, error) {
	var q struct {
		Host     string `json:"host"`
		Port     uint16 `json:"port"`
		Network  string `json:"network"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(query, &q); err != nil {
		return nil, err
	}
	if q.Host == "" {
		return nil, errors.New("enter a domain or IP")
	}
	if q.Port == 0 {
		q.Port = 443
	}
	target := xnet.TCPDestination(xnet.ParseAddress(q.Host), xnet.Port(q.Port))
	if q.Network == "udp" {
		target.Network = xnet.Network_UDP
	}
	ctx := &rsession.Context{Inbound: &session.Inbound{Tag: "packet"}, Outbound: &session.Outbound{Target: target}, Content: &session.Content{Protocol: q.Protocol}}
	route, err := instance.GetFeature(routing.RouterType()).(routing.Router).PickRoute(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"outbound": route.GetOutboundTag(), "rule": route.GetRuleTag(), "host": q.Host, "note": "Actual Xray first-match decision. IP-only inputs cannot identify encrypted domains; domain queries may resolve through the configured split DNS."})
}

//export AsterProbe
func AsterProbe(outbound *C.char) *C.char {
	global.RLock()
	e := global.engine
	if e == nil {
		global.RUnlock()
		return C.CString(`{"error":"Connect before testing exit addresses."}`)
	}
	// Do not hold lifecycle lock during a remote request. Stop cancels its context.
	ctx, cancel := context.WithTimeout(e.ctx, 12*time.Second)
	global.RUnlock()
	defer cancel()
	tag := C.GoString(outbound)
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
		dialCtx = session.SetForcedOutboundTagToContext(dialCtx, tag)
		target, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			return nil, err
		}
		return core.Dial(dialCtx, e.instance, target)
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://api64.ipify.org?format=json", nil)
	response, err := (&http.Client{Transport: transport, Timeout: 12 * time.Second}).Do(request)
	if err != nil {
		return C.CString(`{"error":"Exit IP HTTPS request failed."}`)
	}
	defer response.Body.Close()
	var result map[string]string
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result) != nil || net.ParseIP(result["ip"]) == nil {
		return C.CString(`{"error":"Invalid IP service response."}`)
	}
	raw, _ := json.Marshal(result)
	return C.CString(string(raw))
}

//export AsterFree
func AsterFree(p unsafe.Pointer) { C.free(p) }
func main()                      {}
