#!/usr/bin/env python3
"""Package architecture-independent Atlas with the official SDK apk-tools.

This avoids compiling dependencies, which are installed from OpenWrt feeds.
The package layout and hooks follow OpenWrt include/package-pack.mk.
"""
import argparse,hashlib,os,re,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('sdk',type=Path);a=p.parse_args()
    apk=a.sdk.resolve()/'staging_dir/host/bin/apk'
    if os.name!='posix' or not apk.is_file():p.error('Linux and official OpenWrt SDK apk-tools are required')
    make=(ROOT/'Makefile').read_text();version=re.search(r'PKG_VERSION:=(\S+)',make)[1];release=re.search(r'PKG_RELEASE:=(\S+)',make)[1]
    deps=re.search(r'  DEPENDS:=(.+)',make)[1].replace('+','').strip()
    name='luci-app-atlas';dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    output=dist/(name+'-'+version+'-r'+release+'.apk')
    with tempfile.TemporaryDirectory(prefix='atlas-apk-') as tmp:
        base=Path(tmp);files=base/'files';shutil.copytree(ROOT/'root',files,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        for item in files.rglob('*'):item.chmod(0o755 if item.is_dir() else 0o644)
        (files/'etc/atlas').chmod(0o700);(files/'etc/atlas/state.json').chmod(0o600)
        for path in ('etc/init.d/atlas','etc/uci-defaults/90-atlas','etc/hotplug.d/iface/95-atlas','usr/libexec/rpcd/atlas'):(files/path).chmod(0o755)
        meta=files/'lib/apk/packages';meta.mkdir(parents=True,exist_ok=True)
        (meta/(name+'.conffiles')).write_text('/etc/atlas/state.json\n')
        state=files/'etc/atlas/state.json'
        (meta/(name+'.conffiles_static')).write_text('/etc/atlas/state.json '+hashlib.sha256(state.read_bytes()).hexdigest()+'\n')
        listing=sorted('/'+x.relative_to(files).as_posix() for x in files.rglob('*') if x.is_file())
        (meta/(name+'.list')).write_text('\n'.join(listing)+'\n')
        scripts=[]
        for hook,definition,default in [('post-install','postinst','default_postinst'),('pre-deinstall','prerm','default_prerm')]:
            body=re.search(r'define Package/luci-app-atlas/'+definition+r'\n(.*?)\nendef',make,re.S)[1].replace('$$','$')
            body='\n'.join(line for line in body.splitlines() if not line.startswith('#!'))
            # Atlas has no alternatives, users, modules or overlay to process.
            # default_postinst starts every listed service, even when disabled
            # on upgrade. Use our explicit hooks, matching the IPK builder.
            text='#!/bin/sh\n'+body+'\n'
            path=base/hook;path.write_text(text);scripts+=['--script',hook+':'+str(path)]
            if hook=='post-install':
                upgrade=base/'post-upgrade';upgrade.write_text('#!/bin/sh\nexport PKG_UPGRADE=1\n'+text.split('\n',1)[1]);scripts+=['--script','post-upgrade:'+str(upgrade)]
        args=[str(apk),'mkpkg','--info','name:'+name,'--info','version:'+version+'-r'+release,'--info','arch:noarch','--info','license:MIT','--info','description:Atlas subscriptions and section routing for sing-box','--info','depends:'+deps,'--files',str(files),'--output',str(output)]+scripts
        subprocess.run(args,check=True)
    print(output)
if __name__=='__main__':main()
