#!/usr/bin/env python3
"""Install the verified Atlas interface without changing network settings."""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.request

FILES = (
    ('root/www/luci-static/resources/view/atlas/overview.js',
     'cf0d9175b03c929d1b6af01a770df982ed10003eab270a29407aad33c1c10c73'),
    ('root/www/luci-static/resources/view/atlas/overview_cf0d9175.js',
     'cf0d9175b03c929d1b6af01a770df982ed10003eab270a29407aad33c1c10c73'),
    ('root/usr/share/luci/menu.d/luci-app-atlas.json',
     '317b7f016b0ad625864106bc071936fa4c7493a67428a25c47ede947df005e46'),
)


def download(url):
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read(1048577)


def atomic_write(path, content, mode):
    fd, temporary = tempfile.mkstemp(prefix='.atlas-ui-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(ref, root=Path('/'), fetch=download):
    if not re.fullmatch(r'[0-9a-f]{40}', ref):
        raise ValueError('A full source commit is required')
    base = 'https://raw.githubusercontent.com/Nissanstels1/Atlas/' + ref + '/atlas-openwrt/'
    staged = []
    for relative, expected in FILES:
        content = fetch(base + relative)
        if len(content) > 1048576 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError('Interface checksum mismatch; no files changed')
        target = Path(root) / relative[len('root/'):]
        staged.append((target, content))
    originals = {}
    for target, _ in staged:
        if target.exists() and not target.is_file():
            raise ValueError('Interface target is not a file')
        originals[target] = ((target.read_bytes(), stat.S_IMODE(target.stat().st_mode))
                             if target.exists() else None)
    changed = []
    try:
        # The menu is switched last, after the new view has been installed.
        for target, content in staged:
            old = originals[target]
            atomic_write(target, content, old[1] if old else 0o644)
            changed.append(target)
    except BaseException:
        for target in reversed(changed):
            old = originals[target]
            if old is None:
                target.unlink(missing_ok=True)
            else:
                atomic_write(target, old[0], old[1])
        raise
    print('Verified Atlas interface installed.')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: install-ui-refresh.py COMMIT')
    install(sys.argv[1])
