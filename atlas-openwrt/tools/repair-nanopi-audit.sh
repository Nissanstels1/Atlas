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
files={'root/usr/lib/atlas/atlas.py': '1ff6c245b9deba0fe2ee755fc0eec6b8b7a3df1f7132a6cf5814320c65bce165', 'root/usr/lib/atlas/core.py': '32b09dc8f066b61cb0d4d3a883742e3da4819c1f54c87c085f9ab4326a1f90ee', 'root/usr/lib/atlas/public_dns.py': '4b89247d875dfd71d8c96de5d8b124d612afa0d47b5374af7c7a1e68e59b895d', 'root/www/luci-static/resources/view/atlas/overview.js': 'dae1d5e62f132dce5c2388c7e42eacd19ee0335971107dd7c80732e0a90f5020', 'root/www/luci-static/resources/atlas/atlas.css': 'c94479f516f72744e37e4f4a58d4e1f1136c10dd2337c74adcc2443d03fdd440', 'root/etc/init.d/atlas': '35ab2921faf63daa8968e3c69318802ac699095ab14adc42c2180119d421c2c8', 'root/www/luci-static/resources/view/atlas/overview_dae1d5e6.js': 'dae1d5e62f132dce5c2388c7e42eacd19ee0335971107dd7c80732e0a90f5020', 'root/usr/share/luci/menu.d/luci-app-atlas.json': '6a99f06740972eda2bfd21f2e3724663d5be7fe17345f85336c87fd16c99509d'}
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
        pending.write_bytes(content);pending.chmod(0o755 if str(target)=="/etc/init.d/atlas" else 0o644)
        os.replace(pending,target);changed.append(target)
except BaseException:
    for target in changed:
        if original[target] is None:target.unlink(missing_ok=True)
        else:
            pending=target.with_name('.'+target.name+'.audit-restore')
            pending.write_bytes(original[target]);pending.chmod(0o755 if str(target)=="/etc/init.d/atlas" else 0o644);os.replace(pending,target)
    raise
print('Audit repair installed. Routing was not restarted. Reload LuCI with Ctrl+F5.')
PY
