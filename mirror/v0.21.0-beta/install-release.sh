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
awk -v suffix="$suffix" '
    NF == 2 && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ && $2 ~ /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/ && $2 ~ ("\\." suffix "$") {print $1, $2}
' "$directory/SHA256SUMS" > "$directory/packages"
grep -q " luci-app-atlas.*\.$suffix$" "$directory/packages" || { echo 'Mirror has no Atlas package for this package manager.'; exit 1; }
while read -r expected name; do
    wget -q -O "$directory/$name" "${base%/}/$name"
    actual=$(sha256sum "$directory/$name" | awk '{print $1}')
    [ "$actual" = "$expected" ] || { echo "SHA256 mismatch: $name"; exit 1; }
done < "$directory/packages"
mkdir -p /etc/atlas
chmod 700 /etc/atlas
if [ -f /etc/atlas/state.json ]; then cp /etc/atlas/state.json /etc/atlas/upgrade-backup.json; chmod 600 /etc/atlas/upgrade-backup.json; fi
# Package managers skip already satisfied dependencies; mirrors may include them for offline use.
if [ "$manager" = opkg ]; then
    opkg install "$directory"/*.ipk
elif [ "$allow" = '--allow-untrusted' ]; then
    apk add --allow-untrusted "$directory"/*.apk
else
    apk add "$directory"/*.apk
fi
echo 'Atlas installed or upgraded. Refresh LuCI and validate settings before starting.'
