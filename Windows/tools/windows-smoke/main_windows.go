// Windows CI fixture utility. Uses a local unauthenticated SOCKS placeholder and
// never connects the VPN or prints the encrypted payload.
package main

import (
	"aster/windows/internal/core"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	path := filepath.Join(os.Args[2], "state.dat")
	switch os.Args[1] {
	case "seed":
		s := core.DefaultState()
		servers, e := core.Parse("socks5://127.0.0.1:9#Installer smoke fixture")
		if e != nil {
			panic(e)
		}
		s.Servers = servers
		s.SelectedServerID = servers[0].ID
		s.Settings.Theme = "dark"
		if e = core.SaveState(path, s); e != nil {
			panic(e)
		}
	case "verify":
		s, e := core.LoadState(path)
		if e != nil || len(s.Servers) != 1 || s.Servers[0].Name != "Installer smoke fixture" || s.Settings.Theme != "dark" || s.Servers[0].Outbound == nil {
			panic("installer did not preserve encrypted settings")
		}
	default:
		os.Exit(2)
	}
	fmt.Println("Encrypted installer fixture: " + os.Args[1] + " passed.")
}
