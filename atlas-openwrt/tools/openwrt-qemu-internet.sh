#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 /path/to/openwrt-x86-64-combined-ext4.img [atlas.ipk]" >&2
    exit 2
fi

image=$1
package=${2:-}
qemu=${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}
ssh_port=${ATLAS_QEMU_SSH_PORT:-2222}
web_port=${ATLAS_QEMU_WEB_PORT:-8080}

if ! command -v "$qemu" >/dev/null 2>&1; then
    echo "qemu-system-x86_64 is required (Debian/Ubuntu: qemu-system-x86)." >&2
    exit 1
fi
for tool in python3 e2fsck resize2fs; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is required to prepare a disposable 512 MiB ext4 test disk." >&2
        exit 1
    fi
done
if [ ! -r "$image" ]; then
    echo "OpenWrt image is not readable: $image" >&2
    exit 1
fi
if [ -n "$package" ] && [ ! -r "$package" ]; then
    echo "Atlas package is not readable: $package" >&2
    exit 1
fi

echo "Starting OpenWrt with QEMU user-mode NAT; eth1 is the internet-facing WAN."
echo "LuCI host port: http://127.0.0.1:$web_port  |  SSH host port: 127.0.0.1:$ssh_port"
if [ -n "$package" ]; then
    echo "Copy the package to the guest from another terminal with:"
    echo "  scp -P $ssh_port '$package' root@127.0.0.1:/tmp/atlas.ipk"
    echo "Then install on the guest: opkg install /tmp/atlas.ipk"
fi
echo "Guest connectivity check: wget -O /dev/null https://www.gstatic.com/generate_204"
echo "Stop the VM with Ctrl-A, then X. An expanded temporary disk is used in snapshot mode and removed on exit."

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/atlas-qemu.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM
expanded="$tmpdir/openwrt-expanded.img"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$script_dir/expand_openwrt_ext4.py" "$image" "$expanded" --size-mib 512

"$qemu" -machine q35 -accel kvm:tcg -m 512 -nographic \
    -drive "file=$expanded,format=raw,if=virtio,snapshot=on" \
    -device e1000,netdev=lan0 -netdev "user,id=lan0,net=192.168.1.0/24,hostfwd=tcp:127.0.0.1:$ssh_port-192.168.1.1:22,hostfwd=tcp:127.0.0.1:$web_port-192.168.1.1:80" \
    -device e1000,netdev=wan0 -netdev user,id=wan0,net=192.0.2.0/24
