#!/bin/sh
# Install an Atlas release (and optional offline dependencies) from an explicit HTTPS mirror.
set -eu
base=${1:-}
case "$base" in https://*) ;; *) echo 'Usage: install-release.sh https://mirror.example/release/ [--allow-untrusted]'; exit 1;; esac
case "$base" in *'@'*|*'?'*|*'#'*|*' '*|*'\'*) echo 'Use a plain HTTPS base URL without credentials/query.'; exit 1;; esac
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run as root on OpenWrt.'; exit 1; }
. /etc/openwrt_release
printf '%s\n' "${DISTRIB_RELEASE:-}" | awk -F. '
    NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        if ($1 > 24 || ($1 == 24 && ($2 > 10 || ($2 == 10 && $3 >= 1)))) exit 0
        exit 1
    }
    { exit 1 }
' || { echo 'Requires a stable OpenWrt release >= 24.10.1.'; exit 1; }
allow=${2:-}
[ "$#" -le 2 ] && { [ -z "$allow" ] || [ "$allow" = '--allow-untrusted' ]; } || exit 1
if command -v opkg >/dev/null 2>&1; then manager=opkg; suffix=ipk
elif command -v apk >/dev/null 2>&1; then manager=apk; suffix=apk
else echo 'No supported package manager.'; exit 1; fi
[ "$manager" = apk ] || [ -z "$allow" ] || { echo 'Trust override applies only to APK.'; exit 1; }
umask 077
directory=$(mktemp -d /tmp/atlas-release.XXXXXX)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
wget -q -O "$directory/SHA256SUMS" "${base%/}/SHA256SUMS"
[ "$(wc -c < "$directory/SHA256SUMS")" -le 1048576 ] || { echo 'Checksum manifest too large.'; exit 1; }
machine=$(uname -m)
awk -v suffix="$suffix" -v machine="$machine" '
    NF == 2 && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ && $2 ~ /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/ && $2 ~ ("\\." suffix "$") {
        if ($2 ~ /^atlas-engine[_-]/) {
            arch = machine == "x86_64" ? "x86_64" : (machine == "aarch64" ? "aarch64_generic" : "")
            if (arch == "") next
            if (suffix == "ipk" && $2 !~ ("_" arch "\\.ipk$")) next
            if (suffix == "apk" && !($2 ~ ("_" arch "\\.apk$") || (arch == "x86_64" && $2 ~ /^atlas-engine-[0-9.]+-r[0-9]+\.apk$/))) next
        }
        if ($2 !~ /^(luci-app-atlas|atlas-engine)[_-]/) next
        print $1, $2
    }
' "$directory/SHA256SUMS" > "$directory/packages"
grep -q " luci-app-atlas.*\.$suffix$" "$directory/packages" || { echo 'Mirror has no Atlas package for this package manager.'; exit 1; }
[ "$(grep -c " luci-app-atlas.*\.$suffix$" "$directory/packages")" = 1 ] || { echo 'Mirror has multiple Atlas versions.'; exit 1; }
[ "$(grep -c " atlas-engine.*\.$suffix$" "$directory/packages" || true)" -le 1 ] || { echo 'Mirror has multiple engine versions.'; exit 1; }
case "$machine" in x86_64|aarch64)
    grep -q " atlas-engine.*\.$suffix$" "$directory/packages" || { echo 'Mirror has no matching Atlas Engine.'; exit 1; }
esac
while read -r expected name; do
    wget -q -O "$directory/$name" "${base%/}/$name"
    actual=$(sha256sum "$directory/$name" | awk '{print $1}')
    [ "$actual" = "$expected" ] || { echo "SHA256 mismatch: $name"; exit 1; }
done < "$directory/packages"
if [ "$manager" = opkg ]; then
    architectures=$(opkg print-architecture)
    case "$machine" in
        x86_64) printf '%s\n' "$architectures" | grep -q '^arch x86_64 ' || { echo 'Firmware does not accept x86_64 packages.'; exit 1; };;
        aarch64) printf '%s\n' "$architectures" | grep -q '^arch aarch64_generic ' || { echo 'Firmware does not accept aarch64_generic packages.'; exit 1; };;
    esac
fi
mkdir -p /etc/atlas
chmod 700 /etc/atlas
if [ -f /etc/atlas/state.json ]; then cp /etc/atlas/state.json /etc/atlas/upgrade-backup.json; chmod 600 /etc/atlas/upgrade-backup.json; fi
# Package managers skip already satisfied dependencies; mirrors may include them for offline use.
if [ "$manager" = opkg ]; then
    opkg update
    opkg install luci
    opkg install "$directory"/*.ipk
elif [ "$allow" = '--allow-untrusted' ]; then
    apk update
    apk add luci
    apk add --allow-untrusted "$directory"/*.apk
else
    apk update
    apk add luci
    apk add "$directory"/*.apk
fi
rm -f /tmp/luci-indexcache
[ ! -x /etc/init.d/rpcd ] || /etc/init.d/rpcd restart
[ ! -x /etc/init.d/uhttpd ] || /etc/init.d/uhttpd start
echo 'Atlas installed. Open LuCI -> Services -> Atlas. Add a subscription and apply settings.'
