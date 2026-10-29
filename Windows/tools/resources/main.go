package main

import (
	"aster/windows/internal/buildinfo"
	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
	"image/png"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	f, e := os.Open("../Sources/AsterApp/Assets.xcassets/AppIcon.appiconset/icon-256.png")
	if e != nil {
		log.Fatal(e)
	}
	img, e := png.Decode(f)
	f.Close()
	if e != nil {
		log.Fatal(e)
	}
	ico, e := winres.NewIconFromResizedImage(img, []int{16, 24, 32, 48, 64, 128, 256})
	if e != nil {
		log.Fatal(e)
	}
	if e = os.MkdirAll("../build/windows", 0755); e != nil {
		log.Fatal(e)
	}
	iconFile, e := os.Create("../build/windows/Aster.ico")
	if e != nil {
		log.Fatal(e)
	}
	if e = ico.SaveICO(iconFile); e != nil {
		log.Fatal(e)
	}
	iconFile.Close()
	rs := winres.ResourceSet{}
	if e = rs.SetIcon(winres.ID(1), ico); e != nil {
		log.Fatal(e)
	}
	var v [4]uint16
	for i, p := range strings.Split(buildinfo.Version, ".") {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil {
			log.Fatal(e)
		}
		v[i] = uint16(n)
	}
	rs.SetManifest(winres.AppManifest{Identity: winres.AssemblyIdentity{Name: "Aster.Windows", Version: v}, Description: "Aster — Your traffic. Your rules.", ExecutionLevel: winres.RequireAdministrator, DPIAwareness: winres.DPIPerMonitorV2, Compatibility: winres.Win10AndAbove, UseCommonControlsV6: true, LongPathAware: true})
	vi := version.Info{FileVersion: v, ProductVersion: v}
	vi.Set(0, version.ProductName, "Aster")
	vi.Set(0, version.FileVersion, buildinfo.Version+".0")
	vi.Set(0, version.ProductVersion, buildinfo.Version)
	vi.Set(0, version.FileDescription, "Aster VPN for Windows")
	rs.SetVersionInfo(vi)
	for _, a := range []winres.Arch{winres.ArchAMD64, winres.ArchARM64} {
		f, e := os.Create("cmd/aster/resources_windows_" + string(a) + ".syso")
		if e != nil {
			log.Fatal(e)
		}
		e = rs.WriteObject(f, a)
		f.Close()
		if e != nil {
			log.Fatal(e)
		}
	}
}
