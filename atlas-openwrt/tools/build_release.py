#!/usr/bin/env python3
"""Create the reproducible OpenWrt package, source bundle and checksums."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    match = re.search(r'^PKG_VERSION:=(\d+\.\d+\.\d+)$', (ROOT / 'Makefile').read_text(), re.M)
    if not match:
        raise SystemExit('Could not read PKG_VERSION from Makefile')
    version = match.group(1)
    release = re.search(r'^PKG_RELEASE:=(\d+)$', (ROOT / 'Makefile').read_text(), re.M).group(1)
    subprocess.run([sys.executable, str(ROOT / 'tools/build_ipk.py')], check=True)
    package = DIST / ('luci-app-atlas_%s-%s_all.ipk' % (version, release))
    archive = DIST / ('atlas-openwrt-%s-beta.zip' % version)
    apk = DIST / ('luci-app-atlas-%s-r%s.apk' % (version, release))
    packages = [package] + ([apk] if apk.is_file() else [])
    if not package.is_file():
        raise SystemExit('Package builder did not create ' + package.name)

    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(ROOT.rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo'):
                continue
            relative = path.relative_to(ROOT)
            if relative.parts[0] == 'dist' and path not in packages:
                continue
            info = zipfile.ZipInfo('atlas-openwrt/' + relative.as_posix(), (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
            bundle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    checksums = ['%s  %s' % (digest(path), path.name) for path in packages + [archive]]
    (DIST / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
    print(package)
    print(archive)
    print(DIST / 'SHA256SUMS')


if __name__ == '__main__':
    main()
