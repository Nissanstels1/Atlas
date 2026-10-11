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
files={'root/usr/lib/atlas/atlas.py': 'c2ea9ecc247116121c0997c32a47aa850023858a9dd691f907e4ffe92d3889d4', 'root/usr/lib/atlas/core.py': '4af0a65903502064ca48b7ebd835871536c394c3c4150cb20bc0e94d1cd631ab', 'root/usr/lib/atlas/public_dns.py': '4b89247d875dfd71d8c96de5d8b124d612afa0d47b5374af7c7a1e68e59b895d', 'root/www/luci-static/resources/view/atlas/overview.js': '1307deb76c56cf6a319ffb4c74a536e96840d36e24c7032a9fb2c4f2c2295b0f', 'root/www/luci-static/resources/atlas/atlas.css': '6964efd9c1c7d11fad191a12750e6a3e31e1194ca21ad08a6433f6d5a7881ff8'}
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
        pending.write_bytes(content);pending.chmod(0o644)
        os.replace(pending,target);changed.append(target)
except BaseException:
    for target in changed:
        if original[target] is None:target.unlink(missing_ok=True)
        else:
            pending=target.with_name('.'+target.name+'.audit-restore')
            pending.write_bytes(original[target]);pending.chmod(0o644);os.replace(pending,target)
    raise
print('Audit repair installed. Routing was not restarted. Reload LuCI with Ctrl+F5.')
PY
