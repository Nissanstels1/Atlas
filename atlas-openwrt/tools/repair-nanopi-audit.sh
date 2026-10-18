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
files={'root/usr/lib/atlas/atlas.py': '0ef0ea760bfe7783bea27dbcfb5696a204c0f50da05b751f0a37d4f2276e18bf', 'root/usr/lib/atlas/core.py': 'c4573a856edc5b8e2c78a33cb94e482b4cfb6a4b0013327a202d7d8e1909cb85', 'root/usr/lib/atlas/public_dns.py': '4b89247d875dfd71d8c96de5d8b124d612afa0d47b5374af7c7a1e68e59b895d', 'root/usr/lib/atlas/start_guard.py': 'dfa40bebbeac4f8f2777837d4250d925d1072aaf082428480223dbc219c24713', 'root/www/luci-static/resources/view/atlas/overview.js': 'fa1f55649d38a3429c1061f1892008fdef91ddfad1014a0f819b310c372bfa2f', 'root/www/luci-static/resources/atlas/atlas.css': 'cac2cbd01d7784a07e877f4d6bbd958cdf1a784f62d68ca69e2d898319ac4b32', 'root/etc/init.d/atlas': 'f8bf2f57c3285e1349961f8a9c476976a80343984ee1be031c03a9119935c17d', 'root/etc/init.d/atlas-dns-restore': '262cdf274d5f92f49036890cca917bf84a0f9e8576e059481397daaf7bed03ea', 'root/etc/uci-defaults/90-atlas': '83a35298bb04f0011f4f8b726ddfe53995268f9fb7d285d1b0127c70ee2204dd', 'root/usr/share/luci/menu.d/luci-app-atlas.json': '2ce3b4c1f208cbf70eaab7b38a63d1b24c1f8ce029f85b57b3f249e7bfc05e24', 'root/usr/lib/atlas/engine_features.py': '83ecc5e3a600545e7dcfe33d005e9839c7633008cbb81cedbf8dc50f5d3a940d', 'root/usr/lib/atlas/download_policy.py': 'd243ba0ecae4efa01a7bd985f28e954bafb8cc43bcec2addd2c4c714c8fcbb85', 'root/usr/lib/atlas/sections.py': 'a939bd765a3b699b545dc05e6f0e62aa13f8be7f5d246ad316ad96d4e3c4b258', 'root/www/luci-static/resources/view/atlas/overview_fa1f5564.js': 'fa1f55649d38a3429c1061f1892008fdef91ddfad1014a0f819b310c372bfa2f'}
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
