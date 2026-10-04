# Atlas for OpenWrt

Atlas 0.21 beta: per-source permission for private list servers and local symlinks, URL query support, extensionless lists, repeatable router configuration benchmark.

[Release and tested packages](https://github.com/Nissanstels1/Atlas/releases/tag/v0.21.0-beta)

Requires OpenWrt 24.10.1 or newer. Use IPK with opkg and APK with apk. APK is unsigned and needs an explicit --allow-untrusted installation option. Source and test coverage are in the release ZIP.

Windows: 248 passed / 15 skipped. Linux: 252 passed / 11 skipped. Real symlink and private HTTP source tests passed. 100-section configuration passed 20 sing-box 1.12.17 checks in a local Linux VM. Physical-router throughput, long-term stability and superiority over Podkop on every parameter are not yet demonstrated.

Primary endpoint: GitHub Releases. Alternate endpoint: raw.githubusercontent.com/Nissanstels1/Atlas/main/mirror/v0.21.0-beta/. These endpoints use the same hosting provider and are not independent hosting.

Previous releases remain available.
