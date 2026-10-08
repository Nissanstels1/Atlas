#!/usr/bin/env python3
"""Make a disposable, larger raw OpenWrt x86 ext4 disk without editing source."""
import argparse
import struct
from pathlib import Path
import shutil
import subprocess
import tempfile

SECTOR = 512
EXT4_MAGIC = b'\x53\xef'


def expand(source, destination, size_mib=512):
    raw = Path(source).read_bytes()
    if len(raw) < SECTOR or raw[510:512] != b'\x55\xaa':
        raise ValueError('Expected a raw x86 disk with an MBR partition table')
    entry = None
    for index in range(4):
        offset = 446 + 16 * index
        kind = raw[offset + 4]
        start, count = struct.unpack_from('<II', raw, offset + 8)
        fs_offset = start * SECTOR + 1024 + 56
        if kind == 0x83 and count and raw[fs_offset:fs_offset + 2] == EXT4_MAGIC:
            entry = (offset, start, count)
            break
    if entry is None:
        raise ValueError('No ext4 partition was found in the OpenWrt image')
    entry_offset, start, old_count = entry
    new_bytes = size_mib * 1024 * 1024
    prefix = raw[:start * SECTOR]
    if new_bytes <= old_count * SECTOR:
        raise ValueError('Requested expanded partition must be larger than the original')
    with tempfile.TemporaryDirectory(prefix='atlas-ext4-') as tmp:
        root = Path(tmp) / 'root.ext4'
        with root.open('wb') as target:
            target.write(raw[start * SECTOR:(start + old_count) * SECTOR])
            target.truncate(new_bytes)
        check = subprocess.run(['e2fsck', '-fy', str(root)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if check.returncode not in (0, 1):
            raise RuntimeError('e2fsck failed: ' + check.stdout[-1000:])
        subprocess.run(['resize2fs', str(root)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        mbr = bytearray(prefix)
        struct.pack_into('<I', mbr, entry_offset + 12, new_bytes // SECTOR)
        out = Path(destination)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('wb') as target, root.open('rb') as source_fs:
            target.write(mbr)
            shutil.copyfileobj(source_fs, target, 1024 * 1024)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('output')
    parser.add_argument('--size-mib', type=int, default=512)
    args = parser.parse_args()
    print(expand(args.image, args.output, args.size_mib))


if __name__ == '__main__':
    main()
