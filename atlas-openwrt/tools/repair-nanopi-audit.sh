#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] && [ -f /etc/openwrt_release ] || { echo 'Run as root on OpenWrt.'; exit 1; }
umask 077
directory=$(mktemp -d /tmp/atlas-audit-repair.XXXXXX)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
/usr/bin/python3 - "$directory" <<'PY'
import hashlib,os,shutil,sys,urllib.request
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
from version import VERSION
if VERSION!='0.29.0':raise SystemExit('This repair requires Atlas 0.29.0; no files changed.')
files={'root/usr/lib/atlas/atlas.py': '395c7b4e59021d5b9e653200d130775dd9c3a79e8c9145c11ff8c452107ab220', 'root/usr/lib/atlas/core.py': '0a6c150f61042192e05c93d2358df39d0bc2466ed4e4c4fd2de9a1927611e339', 'root/usr/lib/atlas/public_dns.py': '4b89247d875dfd71d8c96de5d8b124d612afa0d47b5374af7c7a1e68e59b895d', 'root/usr/lib/atlas/start_guard.py': 'fdbeaf61ac0ee49f7444a4d03ea5353780149a1f8a91d9604d8d7ff8609c13f1', 'root/www/luci-static/resources/view/atlas/overview.js': '66ec63f4654b8b3494d565a19b8a3fd518b31440173c6c32b4ddf2ef98b15680', 'root/www/luci-static/resources/atlas/atlas.css': 'b8882f71d16e4edccb3d1c09f2c589b82df2b9dca7d599ccf0127b749b939f19', 'root/etc/init.d/atlas': 'f8bf2f57c3285e1349961f8a9c476976a80343984ee1be031c03a9119935c17d', 'root/etc/init.d/atlas-dns-restore': '262cdf274d5f92f49036890cca917bf84a0f9e8576e059481397daaf7bed03ea', 'root/etc/uci-defaults/90-atlas': '83a35298bb04f0011f4f8b726ddfe53995268f9fb7d285d1b0127c70ee2204dd', 'root/usr/share/luci/menu.d/luci-app-atlas.json': '60c1cfbf115c9f3dd6436ca09b6c76ec54d2f28ac686b8b16b7cecf795d40b0a', 'root/www/luci-static/resources/view/atlas/overview_66ec63f4.js': '66ec63f4654b8b3494d565a19b8a3fd518b31440173c6c32b4ddf2ef98b15680'}
directory=Path(sys.argv[1]);backup=Path('/etc/atlas/audit-repair-original')
backup.mkdir(mode=0o700,exist_ok=True)
staged=[]
for relative,expected in files.items():
    request=urllib.request.Request('https://raw.githubusercontent.com/Nissanstels1/Atlas/main/atlas-openwrt/'+relative)
    with urllib.request.urlopen(request,timeout=30) as response:
        content=response.read(1048577)
    if len(content)>1048576 or hashlib.sha256(content).hexdigest()!=expected:
        raise SystemExit('Repair checksum mismatch; no files changed.')
    target=Path('/'+relative.removeprefix('root/'))
    if target.suffix=='.py':compile(content,str(target),'exec')
    staged.append((target,content))
# Downloads and compilation finish before changing any installed file.
original={target:target.read_bytes() if target.exists() else None for target,_ in staged}
changed=[]
try:
    for target,content in staged:
        saved=backup/target.relative_to('/')
        if original[target] is not None and not saved.exists():
            saved.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            saved.write_bytes(original[target]);saved.chmod(0o600)
        pending=target.with_name('.'+target.name+'.audit-new')
        pending.write_bytes(content);pending.chmod(0o755 if str(target).startswith(("/etc/init.d/","/etc/uci-defaults/")) else 0o644)
        os.replace(pending,target);changed.append(target)
except BaseException:
    for target in changed:
        if original[target] is None:target.unlink(missing_ok=True)
        else:
            pending=target.with_name('.'+target.name+'.audit-restore')
            pending.write_bytes(original[target]);pending.chmod(0o755 if str(target).startswith(("/etc/init.d/","/etc/uci-defaults/")) else 0o644);os.replace(pending,target)
    raise
print('Audit repair installed. Routing was not restarted. Reload LuCI with Ctrl+F5.')
PY

/etc/init.d/atlas-dns-restore enable
