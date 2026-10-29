# Aster for Windows

Windows 10/11 desktop port of Aster, using the same pinned, patched Xray and gVisor packet engine as the macOS application. The embedded local interface reproduces the eight macOS pages, blue routing paths, app icon, adaptive light/dark surfaces and real measurements. Native Windows window, system tray, file dialogs, UAC and DPAPI; WebView2 renders the interface. No browser tab or local HTTP server is required.

## Install and update

Download and run the latest `Aster-Setup-x64.exe` (Intel/AMD) or `Aster-Setup-ARM64.exe` (ARM Windows) from [GitHub Releases](https://github.com/alitekin1/aster-vpn/releases/latest). Setup installs the app, Start menu/Desktop shortcuts, uninstaller and WebView2 if needed. Import your connection in Servers, select it and Connect.

In Settings, **Check for updates** discovers newer stable releases. **Download & install** authenticates and installs the matching update, preserves settings and restarts Aster. See [update trust and publishing](UPDATES.md). Version 0.1.0 requires this first manual installer upgrade.

Closing keeps the VPN in the tray; Quit disconnects it. Ctrl+K toggles the connection and Ctrl+I imports. Reconnect & Apply activates policy changes. Portable ZIP packages remain available for diagnostics/development: extract all files and keep `wintun.dll` / `GeoData` beside `Aster.exe`.

The app/setup are not commercially Authenticode-signed, so Windows may show an unknown-publisher prompt. Updates are authenticated separately with Ed25519. Wintun is the upstream signed binary.

## Capabilities

- VLESS, VMess AEAD, Shadowsocks SIP002, Trojan, SOCKS5 and HTTP/HTTPS links; base64 lists, Xray outbound JSON and supported Clash proxy entries.
- TCP/raw, WebSocket, gRPC, XHTTP and HTTPUpgrade transports, TLS and REALITY.
- Smart Iran, Global Proxy, Global Direct, Reverse and Custom modes, with ordered PROXY/DIRECT/BLOCK rules. All existing match kinds, groups, pinned proxy servers, advanced match JSON and shadow warnings.
- HTTPS subscriptions with bounded responses, secure redirects, manual/automatic refresh, deduplication, retained favorites and pinned servers. Failed fetches preserve the previous list.
- Split DNS, adapter/custom direct DNS, proxy DNS and cache controls; resolver IP literals prevent bootstrap loops.
- IPv4/IPv6 Wintun packet capture, real byte charts, actual Xray routing inspector, forced direct/proxy HTTPS exit checks, DNS lookup, TCP handshake measurement, fastest selection and redacted diagnostic export.
- Per-user Windows DPAPI protects the complete saved payload in `%APPDATA%\Aster\state.dat`. Credentials and subscription URLs are excluded from UI snapshots and diagnostics. Browser inputs are not persisted. No analytics.
- Coalesced default-route notifications reconnect after network changes; optional alternate-server recovery handles adapter/start failures. Failed proxy authentication remains visible and may require selecting another server manually.
- Verified routing database pair updates; automatic downloads defer in Battery Saver. Charts stop sampling while hidden or outside Overview, with 3-second sampling in Battery Saver.

## Networking behavior

All Xray proxy and DIRECT sockets use the active adapter's `IP_UNICAST_IF`/`IPV6_UNICAST_IF` socket options. Four /1 routes capture IPv4 and IPv6 traffic without overwriting the user's default routes. The Aster interface receives its own addresses and DNS; cleanup touches only that dedicated interface. Use one system VPN at a time on Windows. Smart Iran uses the same bundled Iran GeoIP/GeoSite datasets as macOS. Explicit rules precede presets; infrastructure DNS tags precede personal rules.

Limitations carried from the original engine include no raw ICMP forwarding, per-app firewall, FakeDNS or native DNS-over-TLS. Browser-managed DoH and encrypted hostnames can limit domain visibility. Arbitrary Clash rule engines/plugins and multiple endpoints in a single imported Xray outbound are rejected explicitly.

Windows-specific differences: there is no persistent system service or strict-capture firewall kill switch. Administrator consent is requested when launching the app; standard users who enter a different administrator account use that account's DPAPI store. Quit releases capture; failure recovery can briefly release it. Startup-at-login registration is not implemented. Proxy and DIRECT IPv6 require a working IPv6 uplink; Windows x64 installation, launch, upgrade and encrypted-state preservation are verified in CI. Live egress, DNS leakage, sleep/resume, interactive UAC and physical ARM64/driver behavior require the target checks in VERIFICATION.md.

## Build from source

Requires Go 1.26+ and Python 3, with internet for pinned modules and the official Wintun archive. The compiler can run on macOS, Linux or Windows; no Windows C compiler is used.

```sh
cd Windows
./scripts/build.sh                    # x64 and ARM64
./scripts/build.sh --arch amd64        # x64 only
```

On Windows: `powershell -File Windows/scripts/build.ps1`. Builds land in `build/windows/Aster-Windows-x64.zip` and `Aster-Windows-ARM64.zip`. No source credentials or saved app settings are copied into packages. The build embeds the original icon, version and UAC/DPI manifest, verifies Wintun's published SHA-256, bundles routing data/licenses and emits a complete package checksum file.

`tools/sync_engine.py` deterministically extracts the portable Go portion and packet tests from `Engine/main.go` / `main_test.go`; those macOS files remain authoritative and unchanged. Generated files are excluded from source control. The C entry points are replaced with typed Go packet methods; forwarding, sniffing, cancellation, counters, half-close handling and Xray queries are shared verbatim. Engine dependency patches are prepared identically to the macOS build.

```sh
python3 tools/sync_engine.py
go test -race ./internal/core ./internal/packet ./internal/integration
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/aster
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/aster
```

See `VERIFICATION.md` for exact evidence and Windows checks, and `THIRD_PARTY_NOTICES.md` for sources and licenses.

Build installers with `python3 Windows/tools/build_installers.py` after installing NSIS 3+. Signed releases use the tooling and GitHub Actions workflow documented in [UPDATES.md](UPDATES.md).
