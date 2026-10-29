# Third-party components

- [Xray-core v26.3.27](https://github.com/XTLS/Xray-core/tree/v26.3.27), Mozilla Public License 2.0. Built from the pinned Go module, with Aster's half-close adaptations in `Engine/patches`. Preserve source availability and MPL notices when distributing binaries; include the exact adapted source and transitive license notices with your release.
- [gVisor](https://github.com/google/gvisor), Apache License 2.0, pinned by Xray. Copyright The gVisor Authors.
- [Yams 6.2.2](https://github.com/jpsim/Yams/tree/6.2.2), MIT License, including its LibYAML dependency and notices.
- [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules), bundled full datasets from release `202610200935`. See its repository license, data-source attribution and downstream redistribution requirements. The data incorporates additional upstream GeoIP/GeoSite sources; release packaging must preserve those terms.
- Go module dependencies and exact checksums are recorded in `Engine/go.mod` / `Engine/go.sum`; Swift dependencies in `Package.resolved`.

This file identifies source provenance, not a substitute for full license texts and data-source attribution in a distributed release. Aster is not affiliated with Apple, XTLS, gVisor, or the Iran routing database maintainers.
