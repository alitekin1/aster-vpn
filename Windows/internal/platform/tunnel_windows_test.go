package platform

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net/netip"
	"os"
	"testing"
)

// Explicitly enabled on the target computer. This creates a separate temporary
// adapter but does not install default or /1 routes and never carries user traffic.
func TestWintunAdapterConfiguration(t *testing.T) {
	if os.Getenv("ASTER_WINDOWS_ADAPTER_TEST") != "1" {
		t.Skip("run Test-Windows.ps1 -AdapterTest as administrator on Windows")
	}
	dev, e := tun.CreateTUN("Aster validation", 1500)
	if e != nil {
		t.Fatal(e)
	}
	defer dev.Close()
	luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())
	defer luid.FlushRoutes(windows.AF_UNSPEC)
	defer luid.FlushIPAddresses(windows.AF_UNSPEC)
	if e = luid.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix("198.19.255.2/30"), netip.MustParsePrefix("fd00:6173:7466::2/126")}); e != nil {
		t.Fatal(e)
	}
	servers := []netip.Addr{netip.MustParseAddr("198.19.255.1"), netip.MustParseAddr("fd00:6173:7466::1")}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if e = luid.SetDNS(family, servers, nil); e != nil {
			t.Fatalf("set DNS family %d: %v", family, e)
		}
		defer luid.FlushDNS(family)
	}
	got, e := luid.DNS()
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range servers {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Fatalf("DNS address missing: %s", want)
		}
	}
	destination := netip.MustParsePrefix("198.19.255.99/32")
	if e = luid.AddRoute(destination, netip.IPv4Unspecified(), 0); e != nil {
		t.Fatal(e)
	}
	if _, e = luid.Route(destination, netip.IPv4Unspecified()); e != nil {
		t.Fatal("test route not installed", e)
	}
	if e = luid.DeleteRoute(destination, netip.IPv4Unspecified()); e != nil {
		t.Fatal(e)
	}
}
