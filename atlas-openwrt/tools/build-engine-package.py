#!/usr/bin/env python3
"""Package a Linux x86_64 or aarch64 engine as optional Atlas sidecar."""
import argparse,gzip,io,subprocess,tarfile,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def archive(entries):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.GNU_FORMAT) as tar:
        for name,data,mode in entries:
            info=tarfile.TarInfo(name);info.mode=mode;info.mtime=0
            if data is None:info.type=tarfile.DIRTYPE
            else:info.size=len(data)
            tar.addfile(info,io.BytesIO(data) if data is not None else None)
    return gzip.compress(output.getvalue(),mtime=0)
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('license',type=Path);parser.add_argument('--sdk',type=Path);parser.add_argument('--release',type=int,default=1);args=parser.parse_args()
    if not 1<=args.release<=999:parser.error('Invalid release')
    architecture='x86_64'
    name='atlas-engine';version='1.13.21';release=str(args.release);dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    data=args.binary.read_bytes()
    if len(data)<64 or data[:4]!=b'\x7fELF' or data[4]!=2 or data[5]!=1:parser.error('Expected little-endian ELF64 binary')
    machine=int.from_bytes(data[18:20],'little')
    if machine==183:architecture='aarch64_generic'
    elif machine!=62:parser.error('Expected x86_64 or aarch64 binary')
    entries=[('./usr/',None,0o755),('./usr/lib/',None,0o755),('./usr/lib/atlas-engine/',None,0o755),('./usr/lib/atlas-engine/bin/',None,0o755),('./usr/lib/atlas-engine/bin/atlas-engine',data,0o755),('./usr/share/',None,0o755),('./usr/share/doc/',None,0o755),('./usr/share/doc/atlas-engine/',None,0o755),('./usr/share/doc/atlas-engine/COPYING',args.license.read_bytes(),0o644)]
    control=('Package: atlas-engine\nVersion: '+version+'-'+release+'\nArchitecture: '+architecture+'\nMaintainer: Atlas\nLicense: GPL-3.0-or-later\nDepends: ca-bundle, kmod-tun\nDescription: Optional Atlas TUN engine with URLTest and XHTTP extensions\n').encode()
    ipk=dist/('atlas-engine_'+version+'-'+release+'_'+architecture+'.ipk')
    ipk.write_bytes(archive([('./debian-binary',b'2.0\n',0o644),('./control.tar.gz',archive([('./control',control,0o644)]),0o644),('./data.tar.gz',archive(entries),0o644)]));print(ipk)
    if args.sdk:
        apk=args.sdk.resolve()/'staging_dir/host/bin/apk'
        with tempfile.TemporaryDirectory(prefix='atlas-engine-') as directory:
            root=Path(directory)/'files';root.mkdir()
            for path,content,mode in entries:
                target=root/path.removeprefix('./')
                if content is None:target.mkdir(parents=True,exist_ok=True)
                else:target.write_bytes(content)
                target.chmod(mode)
            target=dist/('atlas-engine-'+version+'-r'+release+('' if architecture=='x86_64' else '_'+architecture)+'.apk')
            subprocess.run([str(apk),'mkpkg','--info','name:'+name,'--info','version:'+version+'-r'+release,'--info','arch:'+architecture,'--info','license:GPL-3.0-or-later','--info','description:Atlas optional TUN engine with URLTest and XHTTP','--info','depends:ca-bundle kmod-tun','--files',str(root),'--output',str(target)],check=True);print(target)
if __name__=='__main__':main()
