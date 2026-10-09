#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run this installer as root on OpenWrt.'; exit 1; }
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'Automatic full installation currently supports x86_64 and ARM64.'; exit 1;; esac
umask 077
directory=$(mktemp -d /tmp/atlas-bootstrap.XXXXXX)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
base=https://github.com/Nissanstels1/Atlas/releases/download/v0.28.3-beta
wget -q -O "$directory/install-release.sh" "$base/install-release.sh"
actual=$(sha256sum "$directory/install-release.sh" | awk '{print $1}')
[ "$actual" = '63bc588105e12aff89e9dff8713cc112a7130a7bb02517b593e90cde58e63497' ] || { echo 'Installer checksum mismatch. Nothing installed.'; exit 1; }
if command -v opkg >/dev/null 2>&1; then
    sh "$directory/install-release.sh" "$base"
elif command -v apk >/dev/null 2>&1; then
    # Release APKs are unsigned; each downloaded package is checked against SHA256SUMS.
    sh "$directory/install-release.sh" "$base" --allow-untrusted
else echo 'No supported package manager.'; exit 1
fi
