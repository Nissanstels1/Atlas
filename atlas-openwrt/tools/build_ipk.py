#!/usr/bin/env python3
"""Build an architecture-independent OpenWrt opkg package (no router or SDK needed)."""
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / 'Makefile').read_text()
VERSION = re.search(r'^PKG_VERSION:=(\d+\.\d+\.\d+)$', MAKEFILE, re.M).group(1) + '-' + re.search(r'^PKG_RELEASE:=(\d+)$', MAKEFILE, re.M).group(1)
DEPS = 'luci-base, rpcd, python3-light, python3-logging, python3-urllib, python3-openssl, python3-uuid, python3-codecs, python3-cryptography, ca-bundle, sing-box, kmod-tun, kmod-nft-tproxy, kmod-nft-socket, kmod-nft-queue, firewall4, ip-full'

def tgz(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data) if data is not None else 0
            if data is None:
                info.type = tarfile.DIRTYPE
            info.mode = mode
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return gzip.compress(stream.getvalue(), mtime=0)

files = []
for file in sorted((ROOT / 'root').rglob('*')):
    if '__pycache__' in file.parts or file.suffix == '.pyc':
        continue
    path = file.relative_to(ROOT / 'root').as_posix()
    if file.is_dir():
        files.append(('./' + path + '/', None, 0o700 if path == 'etc/atlas' else 0o755))
        continue
    if not file.is_file():
        continue
    mode = 0o755 if path.startswith(('etc/init.d/','etc/uci-defaults/','etc/hotplug.d/','usr/libexec/rpcd/')) else 0o644
    if path == 'etc/atlas/state.json':
        mode = 0o600
    files.append(('./' + path, file.read_bytes(), mode))
control = f'''Package: luci-app-atlas
Version: {VERSION}
Architecture: all
Maintainer: Atlas contributors
Section: luci
Priority: optional
License: MIT
Depends: {DEPS}
Installed-Size: {sum(len(data or b'') for _, data, _ in files)}
Description: Atlas subscriptions and selective routing for sing-box (beta)
 Requires sing-box >= 1.12.0. Config generation was checked with sing-box 1.12.12 and 1.12.22; physical router testing is required.
'''
postinst = '''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
[ ! -f /etc/uci-defaults/90-atlas ] || { /etc/uci-defaults/90-atlas && rm -f /etc/uci-defaults/90-atlas; }
/etc/init.d/rpcd restart
/etc/init.d/rpcd start
exit 0
'''
prerm = '''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
[ "${PKG_UPGRADE:-0}" = 1 ] && exit 0
[ "${1:-}" = upgrade ] && exit 0
/etc/init.d/atlas stop
/etc/init.d/atlas disable
sed -i '/atlas[.]py scheduled/d' /etc/crontabs/root
exit 0
'''
control_archive = tgz([('./control',control.encode(),0o644),('./conffiles',b'/etc/atlas/state.json\n',0o644),
                       ('./postinst',postinst.encode(),0o755),('./prerm',prerm.encode(),0o755)])
# OpenWrt opkg consumes the historical gzip-compressed tar IPK. Debian ar archives
# look plausible and pass `ar t`, but OpenWrt 24.10 opkg rejects them as malformed.
payload = tgz([('./debian-binary',b'2.0\n',0o644),('./control.tar.gz',control_archive,0o644),
               ('./data.tar.gz',tgz(files),0o644)])
dist = ROOT / 'dist'
dist.mkdir(exist_ok=True)
path = dist / f'luci-app-atlas_{VERSION}_all.ipk'
path.write_bytes(payload)
(dist/'SHA256SUMS').write_text(hashlib.sha256(payload).hexdigest()+'  '+path.name+'\n')
print(path)
