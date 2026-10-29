# Aster for Windows

A Windows Xray VPN client with Smart Iran routing, an installer and authenticated in-app updates.

- [Download x64 setup](https://github.com/alitekin1/aster-vpn/releases/latest/download/Aster-Setup-x64.exe) for Intel/AMD Windows.
- [Download ARM64 setup](https://github.com/alitekin1/aster-vpn/releases/latest/download/Aster-Setup-ARM64.exe) for ARM Windows.
- [Installation and features](Windows/README.md)
- [Update security and publishing](Windows/UPDATES.md)
- [Verification](Windows/VERIFICATION.md)

Settings -> Application updates -> Check for updates downloads and installs verified releases without a GitHub token. Updates preserve your encrypted settings. The VPN briefly disconnects while updating.

No VPN access, subscription URLs, user settings, logs, signing private keys or unrelated local history are included. Bring your own server configuration. Only the Windows source, shared packet engine, build resources and upstream routing datasets are published.

Build with Go 1.26+, Python 3 and NSIS 3+: `python Windows/tools/build.py`, then `python Windows/tools/build_installers.py`. See the update guide for signed publishing.
