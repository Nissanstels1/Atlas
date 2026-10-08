#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run as root on OpenWrt.'; exit 1; }
if command -v opkg >/dev/null 2>&1 && opkg status luci-app-atlas 2>/dev/null | grep -q 'Status:.*installed'; then
    echo 'Atlas is package-managed. Use: opkg remove luci-app-atlas'; exit 1
fi
if command -v apk >/dev/null 2>&1 && apk info -e luci-app-atlas >/dev/null 2>&1; then
    echo 'Atlas is package-managed. Use: apk del luci-app-atlas'; exit 1
fi
# Only for standalone installation. Keep subscriptions and last good config for reinstall.
[ ! -x /etc/init.d/atlas ] || /etc/init.d/atlas stop
[ ! -x /etc/init.d/atlas ] || /etc/init.d/atlas disable
[ ! -f /etc/crontabs/root ] || sed -i '/atlas[.]py scheduled/d' /etc/crontabs/root
rm -f /lib/upgrade/keep.d/atlas
rm -f /etc/init.d/atlas /etc/uci-defaults/90-atlas /etc/hotplug.d/iface/95-atlas /usr/libexec/rpcd/atlas
rm -f /usr/share/rpcd/acl.d/atlas.json /usr/share/luci/menu.d/luci-app-atlas.json
rm -f /www/luci-static/resources/view/atlas/overview.js /www/luci-static/resources/atlas/atlas.css
rm -f /usr/lib/atlas/atlas.py /usr/lib/atlas/core.py /usr/lib/atlas/outbounds.py /usr/lib/atlas/backups.py /usr/lib/atlas/probes.py /usr/lib/atlas/sections.py
rm -f /usr/lib/atlas/planner.py
rm -f /usr/lib/atlas/firewall_diag.py
rm -f /usr/lib/atlas/version.py
/etc/init.d/rpcd restart
printf '%s\n' 'Atlas removed. /etc/atlas remains (contains secrets); dependencies were kept.'
