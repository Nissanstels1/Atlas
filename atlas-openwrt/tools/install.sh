#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root on the OpenWrt router.'; exit 1; }
[ -f /etc/openwrt_release ] || { echo 'This installer is for OpenWrt only.'; exit 1; }
ATLAS_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$ATLAS_SOURCE/root/usr/lib/atlas/core.py" ] || { echo 'Unpack the complete source archive first.'; exit 1; }
if [ -f /usr/lib/atlas/atlas.py ]; then
    echo 'Atlas is already installed. Use the package manager/SDK for upgrades; standalone installer will not overwrite it.'
    exit 1
fi
if command -v apk >/dev/null 2>&1; then
    apk update
    apk add luci-base rpcd python3-light python3-logging python3-urllib python3-openssl python3-uuid python3-codecs python3-cryptography ca-bundle sing-box kmod-tun kmod-nft-tproxy kmod-nft-socket kmod-nft-queue firewall4 ip-full
elif command -v opkg >/dev/null 2>&1; then
    opkg update
    opkg install luci-base rpcd python3-light python3-logging python3-urllib python3-openssl python3-uuid python3-codecs python3-cryptography ca-bundle sing-box kmod-tun kmod-nft-tproxy kmod-nft-socket kmod-nft-queue firewall4 ip-full
else
    echo 'Neither apk nor opkg found.'; exit 1
fi
python3 - <<'PY'
import re, subprocess,sys
out=subprocess.check_output(['/usr/bin/sing-box','version'],text=True)
m=re.search(r'version (\d+)\.(\d+)\.',out)
if not m or tuple(map(int,m.groups())) < (1,12):
    sys.exit('Atlas needs sing-box 1.12 or newer; update the engine before installing.')
import ssl,urllib.request,fcntl,ipaddress,http.client
PY
umask 077
mkdir -p /etc/atlas
chmod 700 /etc/atlas
# Only Atlas-owned paths are copied; network/dhcp/firewall configuration is untouched.
cp -R "$ATLAS_SOURCE/root/usr" "$ATLAS_SOURCE/root/www" /
mkdir -p /etc/init.d /etc/uci-defaults /etc/hotplug.d/iface /lib/upgrade/keep.d
cp "$ATLAS_SOURCE/root/etc/init.d/atlas" /etc/init.d/atlas
cp "$ATLAS_SOURCE/root/etc/uci-defaults/90-atlas" /etc/uci-defaults/90-atlas
cp "$ATLAS_SOURCE/root/etc/hotplug.d/iface/95-atlas" /etc/hotplug.d/iface/95-atlas
cp "$ATLAS_SOURCE/root/lib/upgrade/keep.d/atlas" /lib/upgrade/keep.d/atlas
if [ ! -f /etc/atlas/state.json ]; then
    cp "$ATLAS_SOURCE/root/etc/atlas/state.json" /etc/atlas/state.json
fi
chmod 600 /etc/atlas/state.json
chmod 755 /etc/init.d/atlas /etc/uci-defaults/90-atlas /etc/hotplug.d/iface/95-atlas /usr/libexec/rpcd/atlas
chmod 755 /www/luci-static/resources/atlas /www/luci-static/resources/view/atlas
chmod 644 /www/luci-static/resources/atlas/atlas.css /www/luci-static/resources/view/atlas/overview.js
/etc/uci-defaults/90-atlas
rm -f /etc/uci-defaults/90-atlas
/etc/init.d/rpcd restart
printf '%s\n' 'Atlas installed. Open LuCI → Services → Atlas. Add a subscription, refresh, test servers, then start.'
