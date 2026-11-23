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
files={'root/usr/lib/atlas/connection_rules.py': '06eb2ef4fadbec02698cc7a497f88d528dc047ea5b9cdf1c0a74405a6ccda484', 'root/usr/lib/atlas/public_suffix_list.dat': 'ad9facd4717b68c83669990c0c3aa6e752f1b986cd39cc4fa563f9ba64738ced', 'root/usr/lib/atlas/core.py': 'e569fa42a41750d71c74ea3374410ade3c7d491ebc3626c98e53f451cd6babcf', 'root/usr/lib/atlas/atlas.py': 'f18cfd6be03234df256712e49c042e1514befe52c848b1a248c45a5ae5e7caf9', 'root/usr/lib/atlas/public_dns.py': '4b89247d875dfd71d8c96de5d8b124d612afa0d47b5374af7c7a1e68e59b895d', 'root/usr/lib/atlas/start_guard.py': 'dfa40bebbeac4f8f2777837d4250d925d1072aaf082428480223dbc219c24713', 'root/www/luci-static/resources/view/atlas/overview.js': '6238bd8892db242a1e6ef4cd27b1a6a01b5867577fb820151f6fe03d18466adf', 'root/www/luci-static/resources/atlas/atlas.css': '2a98be7466b155959707d2e8db18007c25c499f4dabb89a23c919ec84e8fa6e4', 'root/etc/init.d/atlas': 'f8bf2f57c3285e1349961f8a9c476976a80343984ee1be031c03a9119935c17d', 'root/etc/init.d/atlas-dns-restore': '262cdf274d5f92f49036890cca917bf84a0f9e8576e059481397daaf7bed03ea', 'root/etc/uci-defaults/90-atlas': '83a35298bb04f0011f4f8b726ddfe53995268f9fb7d285d1b0127c70ee2204dd', 'root/usr/share/luci/menu.d/luci-app-atlas.json': 'ae5e6b9f0484d4fc39d12e482eaf450bf2358c161349b2129e247cf4269550f4', 'root/usr/lib/atlas/engine_features.py': '83ecc5e3a600545e7dcfe33d005e9839c7633008cbb81cedbf8dc50f5d3a940d', 'root/usr/lib/atlas/download_policy.py': 'd243ba0ecae4efa01a7bd985f28e954bafb8cc43bcec2addd2c4c714c8fcbb85', 'root/usr/lib/atlas/sections.py': 'a939bd765a3b699b545dc05e6f0e62aa13f8be7f5d246ad316ad96d4e3c4b258', 'root/usr/share/rpcd/acl.d/atlas.json': 'c8a468e89fd28d76110b3b08ea1395d501143b9f8358eb241c5ea0c6ffc7dd79', 'root/usr/lib/atlas/backups.py': '4ea42be7ea33ef79d4f9777a5eed8eef46dd09aef865597bc2f0bb2c1fe2f2da', 'root/usr/lib/atlas/adaptive_routing.py': 'a85b690eea831ff76780a8ed1a57d3c9ff6f0286ad4e213bb133d89ebf312dfa', 'root/www/luci-static/resources/view/atlas/overview_6238bd88.js': '6238bd8892db242a1e6ef4cd27b1a6a01b5867577fb820151f6fe03d18466adf'}
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
