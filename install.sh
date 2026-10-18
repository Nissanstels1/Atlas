#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run this installer as root on OpenWrt.'; exit 1; }
case "$(uname -m)" in x86_64|aarch64) ;; *) echo 'Automatic full installation currently supports x86_64 and ARM64.'; exit 1;; esac
umask 077
directory=$(mktemp -d /tmp/atlas-bootstrap.XXXXXX)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
base=https://github.com/Nissanstels1/Atlas/releases/download/v0.29.0-beta
wget -q -O "$directory/install-release.sh" "$base/install-release.sh"
actual=$(sha256sum "$directory/install-release.sh" | awk '{print $1}')
[ "$actual" = '63bc588105e12aff89e9dff8713cc112a7130a7bb02517b593e90cde58e63497' ] || { echo 'Installer checksum mismatch. Nothing installed.'; exit 1; }
if command -v opkg >/dev/null 2>&1; then
    opkg update
    opkg install python3-light python3-ctypes python3-logging python3-urllib python3-openssl python3-uuid python3-codecs python3-cryptography
    [ -x /usr/bin/python3 ] || { echo 'Python interpreter is missing. Check firmware feeds and package installation errors.'; exit 1; }
    sh "$directory/install-release.sh" "$base"
elif command -v apk >/dev/null 2>&1; then
    apk update
    apk add python3-light python3-ctypes python3-logging python3-urllib python3-openssl python3-uuid python3-codecs python3-cryptography
    [ -x /usr/bin/python3 ] || { echo 'Python interpreter is missing. Check firmware feeds and package installation errors.'; exit 1; }
    # Release APKs are unsigned; each downloaded package is checked against SHA256SUMS.
    sh "$directory/install-release.sh" "$base" --allow-untrusted
else echo 'No supported package manager.'; exit 1
fi
# Install the verified post-release fixes from one immutable source revision.
repair_ref=3697bbad6080b0f305208845806245023472ae58
wget -q -O "$directory/repair.sh" "https://raw.githubusercontent.com/Nissanstels1/Atlas/$repair_ref/atlas-openwrt/tools/repair-nanopi-audit.sh"
actual=$(sha256sum "$directory/repair.sh" | awk '{print $1}')
[ "$actual" = '39beaeb77b6e913766afe6e3d55f4ccf4ad29d8d8098be0af12a77586534d921' ] || { echo 'Post-release repair checksum mismatch. Installation incomplete.'; exit 1; }
# Pin the repair's source downloads too; future main changes cannot mix revisions.
/usr/bin/python3 - "$directory/repair.sh" "$repair_ref" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
p.write_text(p.read_text().replace('/Atlas/main/','/Atlas/'+sys.argv[2]+'/'))
PY
sh "$directory/repair.sh"
/usr/bin/python3 -c 'from pathlib import Path; p=Path("/tmp/luci-indexcache"); p.unlink() if p.is_file() else None'
/etc/init.d/rpcd restart
# A visible LuCI menu alone does not mean the backend was installed successfully.
if ! /usr/libexec/rpcd/atlas list > "$directory/methods.json"; then
    echo 'Atlas backend could not start. See the Python error above; installation is incomplete.'
    exit 1
fi
/usr/bin/python3 -c 'import json,sys; methods=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(methods,dict) and "status" in methods else 1)' "$directory/methods.json" || { echo 'Atlas backend returned invalid RPC methods.'; exit 1; }
attempt=0
# procd can take 10 seconds to stop the previous rpcd before registering plugins.
while [ "$attempt" -lt 30 ]; do
    objects=$(ubus list atlas 2>/dev/null || true)
    if [ "$objects" = atlas ]; then
        echo 'Atlas backend verified: RPC object atlas is registered.'
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done
echo 'Atlas files installed, but RPC object atlas is unavailable. Run /usr/libexec/rpcd/atlas list and check rpcd logs.'
exit 1
