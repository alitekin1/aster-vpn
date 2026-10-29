Aster 0.2.0 adds a quick Windows installer and authenticated in-app updates.

- Run Setup to install Aster, its shortcuts and its uninstaller. WebView2 is installed only when needed.
- Settings → Application updates → Check for updates discovers new stable releases. Download & install verifies the signed release manifest and installer hash, installs the matching architecture and restarts Aster.
- Updates and uninstall preserve encrypted user settings and server credentials.
- Keeps the existing Xray engine, Smart Iran routing and Aster interface.

Use x64 for Intel/AMD Windows and ARM64 for ARM Windows. This repository contains no VPN subscription or access credentials; bring your own connection. The app/setup executables are not commercially Authenticode-signed. Update authenticity is protected separately with Ed25519 signatures.
