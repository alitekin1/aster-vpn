# Windows verification

This port is built on a macOS ARM64 host. Windows executables can be cross-compiled here; Windows kernel driver, UAC, tray, DPAPI and end-to-end egress behavior cannot be executed here.

## Automated checks on the build host

Verified on 2026-10-29:

- `go test -race -v ./internal/core ./internal/packet ./internal/integration`: passed. Importers, policy precedence, split DNS and socket-binding configuration, pinned references, subscription merge behavior, state encoding, redaction and atomic file replacement passed.
- Original packet bridge cases passed for serialized IPv4 TCP, IPv6 TCP and UDP, TCP half-close and blocking-reader shutdown. The two credential-dependent live tests and the missing Swift-fixture test were explicitly skipped.
- Seven Windows-compiled routing policy scenarios were loaded into real Xray with the bundled Iran databases: Iranian domain DIRECT, international IP PROXY, private IP DIRECT, reverse Iran PROXY, Global Direct, personal BLOCK before geographic presets and custom BLOCK default all passed. These inspect actual router decisions without using a live proxy.
- Browser UI smoke test passed across all eight pages, both themes, 1120×820 and 960×660 layouts, import error state/secret clearing, rename/favorite, add/toggle rule and DNS editing, with no JavaScript runtime errors. It uses explicit test fixtures, not a real Windows tunnel.
- Both x64 and ARM64 Windows GUI executables cross-compiled. `go vet` passed for native application, platform and core packages for both targets. Windows UAC/DPI manifests and the original Aster icon are embedded.
- Wintun archive verified against its upstream SHA-256. Final archives and packaged files are checksum-verified by the build validation.

Not executed on the macOS host: Windows-specific behavior. The later Windows CI evidence below covers DPAPI and installation/launch/upgrade/uninstall; driver capture, interactive tray/UAC/dialog behavior, live egress, DNS leakage, failure recovery and sleep/wake remain separate target checks.
 Tests use nonsecret fixtures and local loopback servers; no saved user credentials or current system VPN are used. Portable engine tests reuse the macOS engine tests, including real serialized IPv4/IPv6 TCP packets, UDP and TCP half-close. Native Windows packages include a Windows core test executable to check DPAPI on the target computer.

## Windows installer / update release 0.2.0

On 2026-10-29, the [Windows release workflow](https://github.com/alitekin1/aster-vpn/actions/runs/40933914248) passed on a Windows x64 runner:

- Native core/DPAPI and portable packet/policy/update tests.
- Both architecture builds and NSIS installer compilation.
- Actual silent installation into Program Files and numeric file version verification.
- Real WebView2 application launch and installer shutdown handshake.
- Silent replacement while Aster was running, graceful old-process exit and automatic launch of the installed copy.
- Verification that encrypted server/settings data survived upgrade and uninstall.
- Uninstall registration/removal and complete installed executable removal.
- Ed25519 manifest signing/verification and both installer size/hash checks before publishing.

A separate opt-in test queried the unauthenticated public release API, verified its Ed25519 manifest, downloaded both actual installers and verified their full size/SHA-256 successfully.

The stable installers are in [release v0.2.0](https://github.com/alitekin1/aster-vpn/releases/tag/v0.2.0). Installer execution was tested on x64; ARM64 binaries were cross-compiled and verified, not run on ARM hardware. Interactive UAC/SmartScreen and first-time WebView2 download still need checks on a clean physical Windows computer. Live VPN traffic, external leak observation, recovery and sleep/wake remain separate from installer CI.

## On the target Windows computer

1. Extract the correct architecture archive. Run `Test-Windows.ps1`: validate every packaged checksum, Authenticode on Wintun, and core/DPAPI round-trip tests. This script does not establish live VPN connectivity. In an elevated PowerShell window, optionally run `Test-Windows.ps1 -AdapterTest` to create a separate temporary validation adapter and check IPv4/IPv6 addresses, both DNS families and a dedicated /32 route. That test installs no default or /1 capture routes.
2. Launch Aster, accept UAC. Verify WebView2, keyboard navigation, light/dark mode, 100/150/200% DPI, tray close/open/connect/disconnect/quit and diagnostic Save dialog.
3. With an authorized server, import/select/connect. Check a successful forced proxy HTTPS probe. Compare DIRECT and PROXY addresses; do not infer success from adapter status or TCP latency alone.
4. For Smart Iran, inspect a known Iranian domain, an Iranian IPv4 address, a private address and an international domain. Compare actual HTTPS egress and packet captures for each. Test explicit BLOCK and pinned-proxy rules; reconnect to apply saved changes.
5. Verify IPv4 TCP, IPv6 TCP and UDP from applications that do not honor proxy settings. Use an external observer for DNS and IPv6 leakage; test split DNS and browser-managed DoH separately.
6. Verify switching Wi-Fi/Ethernet, losing the uplink, sleep/wake, manual disconnect during recovery, failed authentication, corrupted state/data and missing driver/runtime. Confirm failure messaging and route cleanup.
7. Record `Get-NetRoute -InterfaceAlias Aster`, `Get-NetIPAddress -InterfaceAlias Aster` and `Get-DnsClientServerAddress -InterfaceAlias Aster` while connected, then verify the Aster capture routes disappear after disconnect/quit. Existing physical-adapter DNS/default routes must remain unchanged.
8. Observe long-running transfers, idle CPU, memory, datagram load and battery behavior. Inspect exported diagnostics for secret material. Code-sign the application and complete review before public distribution.

Do not treat unperformed steps as passed. There is no Windows strict-capture kill switch; an interruption can release capture.
