package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"aster/windows/internal/core"
	"aster/windows/internal/packet"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type PacketEngine interface {
	Close()
	WritePacket([]byte) error
	ReadPacket() []byte
	Stats() packet.Stats
	Inspect([]byte) ([]byte, error)
	Probe(string) ([]byte, error)
}
type Uplink struct {
	Name      string
	LUID      winipcfg.LUID
	Resolvers []string
}

func FindUplink() (Uplink, error) {
	routes, e := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if e != nil {
		return Uplink{}, e
	}
	best := ^uint64(0)
	var result Uplink
	for _, r := range routes {
		p := r.DestinationPrefix.Prefix()
		if p.Bits() != 0 {
			continue
		}
		iface, e := net.InterfaceByIndex(int(r.InterfaceIndex))
		if e != nil || iface.Flags&net.FlagUp == 0 || iface.Name == "Aster" {
			continue
		}
		row, e := r.InterfaceLUID.IPInterface(windows.AF_INET)
		if e != nil {
			continue
		}
		cost := uint64(r.Metric) + uint64(row.Metric)
		if cost >= best {
			continue
		}
		best = cost
		result = Uplink{Name: iface.Name, LUID: r.InterfaceLUID}
	}
	if result.Name == "" {
		return Uplink{}, fmt.Errorf("no active IPv4 internet adapter; connect Wi-Fi or Ethernet first")
	}
	dns, e := result.LUID.DNS()
	if e != nil {
		return Uplink{}, e
	}
	for _, a := range dns {
		if !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			result.Resolvers = append(result.Resolvers, a.String())
		}
	}
	return result, nil
}

type Tunnel struct {
	Device  tun.Device
	Engine  PacketEngine
	LUID    winipcfg.LUID
	Uplink  string
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	Failure chan error
}

func Start(s core.State, assets string) (t *Tunnel, err error) {
	uplink, e := FindUplink()
	if e != nil {
		return nil, e
	}
	// Compile before capture. All outbound sockets, including DIRECT DNS, are
	// pinned to the selected physical interface by Xray's Windows sockopts.
	config, e := core.Compile(s, uplink.Name, uplink.Resolvers)
	if e != nil {
		return nil, e
	}
	engine, e := packet.New(config, assets)
	if e != nil {
		return nil, fmt.Errorf("Xray could not start this policy; check the imported configuration and routing databases")
	}
	dev, e := tun.CreateTUN("Aster", 1500)
	if e != nil {
		engine.Close()
		return nil, fmt.Errorf("cannot create VPN adapter; run Aster as administrator and ensure wintun.dll is beside it: %w", e)
	}
	t = &Tunnel{Device: dev, Engine: engine, LUID: winipcfg.LUID(dev.(*tun.NativeTun).LUID()), Uplink: uplink.Name, done: make(chan struct{}), Failure: make(chan error, 1)}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()
	if e = t.LUID.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix("198.18.0.2/30"), netip.MustParsePrefix("fd00:6173:7465::2/126")}); e != nil {
		return t, e
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, e := t.LUID.IPInterface(family)
		if e != nil {
			return t, e
		}
		row.NLMTU = 1500
		row.UseAutomaticMetric = false
		row.Metric = 0
		row.DadTransmits = 0
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if e = row.Set(); e != nil {
			return t, e
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if e = t.LUID.SetDNS(family, []netip.Addr{netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("fd00:6173:7465::1")}, nil); e != nil {
			return t, e
		}
	}
	t.wg.Add(2)
	go t.read()
	go t.write()
	// The /1 routes capture IPv4 and IPv6 without replacing any original default
	// route. Cleanup touches only the dedicated Aster interface.
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		p := netip.MustParsePrefix(prefix)
		next := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			next = netip.IPv6Unspecified()
		}
		if e = t.LUID.AddRoute(p, next, 0); e != nil {
			return t, e
		}
	}
	return t, nil
}
func (t *Tunnel) fail(e error) {
	select {
	case <-t.done:
		return
	default:
	}
	select {
	case t.Failure <- e:
	default:
	}
}
func (t *Tunnel) read() {
	defer t.wg.Done()
	buf := make([]byte, 65535)
	sizes := make([]int, 1)
	for {
		n, e := t.Device.Read([][]byte{buf}, sizes, 0)
		if e != nil {
			t.fail(e)
			return
		}
		if n > 0 {
			if e = t.Engine.WritePacket(buf[:sizes[0]]); e != nil {
				t.fail(e)
				return
			}
		}
	}
}
func (t *Tunnel) write() {
	defer t.wg.Done()
	for {
		b := t.Engine.ReadPacket()
		if b == nil {
			return
		}
		if _, e := t.Device.Write([][]byte{b}, 0); e != nil {
			t.fail(e)
			return
		}
	}
}
func (t *Tunnel) Close() {
	t.once.Do(func() {
		close(t.done)
		_ = t.LUID.FlushRoutes(windows.AF_UNSPEC)
		_ = t.LUID.FlushDNS(windows.AF_INET)
		_ = t.LUID.FlushDNS(windows.AF_INET6)
		t.Engine.Close()
		_ = t.Device.Close()
		t.wg.Wait()
	})
}
func Measure(ctx context.Context, s core.Server, iface string) (float64, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if iface != "" {
		d.Control = bindControl(iface)
	}
	start := time.Now()
	c, e := d.DialContext(ctx, "tcp", core.Endpoint(s))
	if e != nil {
		return 0, errors.New("TCP handshake failed or timed out")
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}
