# Windows port — third-party notices

The original `../THIRD_PARTY_NOTICES.md` applies to the Xray/gVisor engine and Iran datasets. Their licenses are included in release `Licenses/`. All pinned Go module licenses are copied into that directory. Modified Xray source files and the half-close patch are included in `SourcePatches/`.

Additional Windows dependencies:

- [go-webview2](https://github.com/jchv/go-webview2), MIT, pinned by `go.mod`/`go.sum`.
- [go-winloader](https://github.com/jchv/go-winloader), MIT, used to load the embedded WebView2 loader. The loader itself is packaged by go-webview2 under the included Microsoft license.
- [lxn/win](https://github.com/lxn/win), BSD-3-Clause, Windows API bindings.
- [WireGuard for Windows](https://git.zx2c4.com/wireguard-windows/), MIT for winipcfg; [wireguard-go](https://git.zx2c4.com/wireguard-go/), MIT for the TUN API.
- [Wintun 0.14.1 official signed binaries](https://www.wintun.net/), distributed under the binary license included as `Wintun-LICENSE.txt`. The build checks the upstream published SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
- [Go Windows resources](https://github.com/tc-hib/winres), MIT, build-time resource generation.
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/), installed independently under Microsoft's terms; the full runtime is not bundled.

The engine retains its original upstream source and MPL notices. Module versions and integrity hashes are recorded in `go.mod` and `go.sum`; Go's standard notices apply to statically linked dependencies. Preserve all included notices when redistributing.
