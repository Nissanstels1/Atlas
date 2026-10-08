#!/bin/sh
# Install or upgrade a locally supplied native package on OpenWrt.
set -eu
if [ "${1:-}" = "--help" ] || [ "$#" -lt 2 ]; then
    echo 'Usage: install-package.sh package.ipk|package.apk SHA256SUMS [--allow-untrusted]'
    echo 'Uses the existing OpenWrt package manager. A backup of Atlas state is retained.'
    exit 0
fi
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run as root on OpenWrt.'; exit 1; }
package=$1
manifest=$2
allow_untrusted=${3:-}
[ "$#" -le 3 ] && { [ -z "$allow_untrusted" ] || [ "$allow_untrusted" = '--allow-untrusted' ]; } || { echo 'Unknown option.'; exit 1; }
[ -f "$package" ] && [ -f "$manifest" ] || { echo 'Package or checksum manifest missing.'; exit 1; }
. /etc/openwrt_release
printf '%s\n' "${DISTRIB_RELEASE:-}" | awk -F. '
    NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        if ($1 > 24 || ($1 == 24 && ($2 > 10 || ($2 == 10 && $3 >= 1)))) exit 0
        exit 1
    }
    { exit 1 }
' || { echo 'Requires a stable OpenWrt release >= 24.10.1; snapshot compatibility must be checked separately.'; exit 1; }
name=$(basename "$package")
case "$name" in
    luci-app-atlas*.ipk) command -v opkg >/dev/null 2>&1 || { echo 'This IPK needs opkg; use a native APK here.'; exit 1; }; manager=opkg ;;
    luci-app-atlas*.apk) command -v apk >/dev/null 2>&1 || { echo 'This APK needs apk; use an IPK here.'; exit 1; }; manager=apk ;;
    *) echo 'Expected a luci-app-atlas IPK or APK package.'; exit 1 ;;
esac
expected=$(awk -v name="$name" '$2 == name || $2 == "*" name {print $1}' "$manifest")
actual=$(sha256sum "$package" | awk '{print $1}')
[ -n "$expected" ] && [ "$actual" = "$expected" ] || { echo 'SHA256 does not match the manifest.'; exit 1; }
umask 077
mkdir -p /etc/atlas
chmod 700 /etc/atlas
if [ -f /etc/atlas/state.json ]; then
    cp /etc/atlas/state.json /etc/atlas/upgrade-backup.json
    chmod 600 /etc/atlas/upgrade-backup.json
fi
if [ "$manager" = opkg ]; then
    [ -z "$allow_untrusted" ] || { echo '--allow-untrusted applies only to APK.'; exit 1; }
    opkg update
    opkg install "$package"
else
    apk update
    if [ "$allow_untrusted" = '--allow-untrusted' ]; then
        apk add --allow-untrusted "$package"
    else
        apk add "$package"
    fi
fi
python3 - <<'PY'
import re, subprocess, sys
output=subprocess.check_output(['/usr/bin/sing-box','version'],text=True)
match=re.search(r'version (\d+)\.(\d+)\.',output)
if not match or tuple(map(int,match.groups())) < (1,12):
    sys.exit('Atlas requires sing-box >= 1.12. Update the engine; Atlas was not started.')
import ssl, urllib.request, fcntl, ipaddress, http.client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PY
printf '%s\n' 'Package installed. Refresh LuCI, review rules, then start Atlas. Installation alone does not verify routing.'
