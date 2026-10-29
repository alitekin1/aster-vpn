# Windows installation and updates

Install `Aster-Setup-x64.exe` or `Aster-Setup-ARM64.exe` from the latest GitHub release. Setup uses Program Files, creates Desktop/Start menu shortcuts and registers an uninstaller. It checks the installed WebView2 Runtime and runs the bundled Microsoft bootstrapper if required. The bootstrapper's Microsoft Authenticode signature is verified before execution. An internet connection is required if the runtime is missing.

Settings → Application updates → Check for updates queries the public GitHub release API without a token. Download & install fetches the verified installer, quits gracefully, installs silently and restarts Aster. The VPN disconnects briefly during replacement. Servers/settings remain in the account's DPAPI-encrypted AppData store. Uninstall also retains this store. A portable build's in-app update migrates it to the installed Program Files copy.

The update trust chain is HTTPS → exact repository/tag/architecture → Ed25519-signed `update.json` → installer SHA-256 and byte length. The verifier rejects unsupported architectures, downgrades, prereleases, foreign URLs, insecure redirects, malformed versions, altered manifests and corrupt/truncated installers. Private repository tokens are never embedded. The public key is in `internal/update/config.go`; the private key is excluded from all source and release files.

Aster 0.1.0 must be upgraded once using Setup; it predates the updater. Quit the old portable version from its tray menu if Setup asks. Later installed versions support graceful unattended replacement. A failed integrity check leaves the running application untouched.

## Publishing the next version

1. Change `internal/buildinfo/version.go`, update `RELEASE_NOTES.md` and run the tests. Application resource/version information and installer/update metadata use that same version.
2. Push the reviewed source to the `main` branch of the release repository.
3. Run the GitHub Actions workflow **Publish signed Windows release**. It builds x64/ARM64 installers, tests native installation/upgrade/uninstallation with encrypted settings, signs metadata and publishes all assets after validation.

The workflow requires repository secret `ASTER_UPDATE_SIGNING_KEY`, a PEM-encoded Ed25519 private key matching the embedded public key. It is available only to the publishing job. Never regenerate it as part of a routine build, commit it or put it in app settings. Losing it requires an explicit key-rotation migration through a version that trusts the new key.

Local publishing is also supported:

```sh
python3 Windows/tools/build.py
python3 Windows/tools/build_installers.py
cd Windows
go run ./tools/release sign --key /secure/location/update-signing-key.pem
python3 tools/verify_release.py
```

Upload both installers, `update.json`, `update.json.sig` and `SHA256SUMS-Release.txt` to a stable release tagged `vVERSION`. Publish only after the native Windows installer tests pass. The local source publication script builds an allowlisted copy and scans it for secrets; it excludes app state, credentials, logs, personal planning files, signing keys, provisioning and unrelated Git history.

The installer and app are currently unsigned under Windows Authenticode, so Windows can show an unknown-publisher prompt. Ed25519 authenticates updates inside Aster; it does not remove that Windows prompt. Wintun remains the upstream signed driver.
