#!/usr/bin/env python3
"""Build the native IPK/APK using an explicitly supplied official OpenWrt SDK."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sdk', type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--update-feeds', action='store_true', help='Resolve dependencies using the SDK feeds configuration')
    args = parser.parse_args()
    sdk = args.sdk.resolve()
    if not sys.platform.startswith('linux'):
        parser.error('Официальный SDK требует Linux; используйте Linux host или native-sdk workflow')
    if sdk == ROOT or ROOT in sdk.parents:
        parser.error('SDK должен находиться вне дерева исходников Atlas')
    if not (sdk / 'include/package.mk').is_file() or not (sdk / 'rules.mk').is_file():
        parser.error('Укажите распакованный официальный OpenWrt SDK')
    if not 1 <= args.jobs <= 32:
        parser.error('jobs должен быть от 1 до 32')
    target = sdk / 'package/atlas'
    if target.exists():
        parser.error('package/atlas уже существует: используйте чистый SDK')
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns('dist', '__pycache__', '*.pyc', '.git'))
    if args.update_feeds:
        subprocess.run(['./scripts/feeds', 'update', '-a'], cwd=sdk, check=True)
        subprocess.run(['./scripts/feeds', 'install', '-a'], cwd=sdk, check=True)
    with (sdk / '.config').open('a') as config:
        config.write('\nCONFIG_PACKAGE_luci-app-atlas=m\n')
    subprocess.run(['make', 'defconfig'], cwd=sdk, check=True)
    subprocess.run(['make', 'package/atlas/compile', 'V=s', '-j%d' % args.jobs], cwd=sdk, check=True)
    packages = sorted(p for suffix in ('*.apk', '*.ipk') for p in (sdk / 'bin').rglob(suffix)
                      if p.name.startswith('luci-app-atlas'))
    if not packages:
        raise SystemExit('SDK не создал пакет Atlas; сборка не подтверждена')
    destination = ROOT / 'dist/sdk'
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for package in packages:
        saved = destination / package.name
        shutil.copy2(package, saved)
        records.append({'file': saved.name, 'sha256': hashlib.sha256(saved.read_bytes()).hexdigest(),
                        'format': saved.suffix[1:]})
        print(saved)
    (destination / 'SHA256SUMS').write_text(''.join('%s  %s\n' % (x['sha256'], x['file']) for x in records), encoding='utf-8')
    (destination / 'build-results.json').write_text(json.dumps({'sdk': sdk.name, 'packages': records,
        'built': True, 'installed_on_router': False}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
