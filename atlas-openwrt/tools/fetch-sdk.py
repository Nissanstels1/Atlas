#!/usr/bin/env python3
"""Fetch an official SDK with SHA256 verification, for a Linux x86/64 host."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sdk_filename(index, release, target):
    prefix = 'openwrt-sdk-' + release + '-' + target.replace('/', '-')
    names = sorted(set(re.findall(re.escape(prefix) + r'_[A-Za-z0-9_.-]+\.Linux-x86_64\.tar\.(?:zst|xz)', index)))
    if len(names) != 1:
        raise ValueError('Официальный каталог не содержит единственный подходящий SDK')
    return names[0]


def expected_hash(sums, filename):
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip('*') == filename and re.fullmatch('[a-fA-F0-9]{64}', parts[0]):
            return parts[0].lower()
    raise ValueError('SDK отсутствует в официальном SHA256 manifest')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release');parser.add_argument('target');parser.add_argument('destination',type=Path)
    args=parser.parse_args()
    if not sys.platform.startswith('linux'):parser.error('Распаковка официального SDK требует Linux')
    if not re.fullmatch(r'\d+\.\d+\.\d+',args.release) or not re.fullmatch('[a-z0-9_-]+/[a-z0-9_-]+',args.target):
        parser.error('Нужны версия вида 24.10.1 и target вида x86/64')
    destination=args.destination.resolve()
    if destination == ROOT or ROOT in destination.parents:parser.error('SDK должен быть вне дерева Atlas')
    destination.mkdir(parents=True,exist_ok=True)
    base='https://downloads.openwrt.org/releases/%s/targets/%s/'%(args.release,args.target)
    with urllib.request.urlopen(base,timeout=60) as response:index=response.read(2*1024*1024).decode()
    filename=sdk_filename(index,args.release,args.target)
    with urllib.request.urlopen(base+'sha256sums',timeout=60) as response:sums=response.read(4*1024*1024).decode()
    expected=expected_hash(sums,filename)
    archive=destination/filename;partial=destination/(filename+'.part')
    if archive.exists():
        with archive.open('rb') as source:
            digest=hashlib.file_digest(source,'sha256').hexdigest() if hasattr(hashlib,'file_digest') else hashlib.sha256(source.read()).hexdigest()
        if digest!=expected:raise SystemExit('Существующий SDK не совпадает с официальной контрольной суммой')
    else:
        digest=hashlib.sha256();size=0
        try:
            with urllib.request.urlopen(base+filename,timeout=60) as response,partial.open('wb') as output:
                while True:
                    block=response.read(1024*1024)
                    if not block:break
                    size+=len(block)
                    if size>2*1024**3:raise ValueError('SDK превышает предел 2 ГиБ')
                    digest.update(block);output.write(block)
            if digest.hexdigest()!=expected:raise ValueError('Контрольная сумма SDK не совпадает')
            os.replace(partial,archive)
        except Exception:
            partial.unlink(missing_ok=True)
            raise
    listing=subprocess.run(['tar','-tf',str(archive)],check=True,capture_output=True,text=True).stdout.splitlines()
    roots=set()
    for name in listing:
        path=Path(name)
        if path.is_absolute() or '..' in path.parts or not path.parts:raise SystemExit('Небезопасный путь в SDK архиве')
        roots.add(path.parts[0])
    if len(roots)!=1:raise SystemExit('В SDK архиве нет единственного корневого каталога')
    sdk=destination/roots.pop()
    if sdk.exists():raise SystemExit('SDK уже распакован; используйте чистый каталог')
    subprocess.run(['tar','-xf',str(archive),'-C',str(destination)],check=True)
    print(sdk)


if __name__=='__main__':main()
