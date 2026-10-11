#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.'; exit 1; }
python3 - <<'PY'
from pathlib import Path
import os,shutil,tempfile,time
p=Path('/usr/lib/atlas/atlas.py')
old="item.setdefault(cache_key, prior.get(cache_key, [] if cache_key in ('domains','cidrs') else 0 if cache_key == 'updated' else ''))"
new="item[cache_key]=prior.get(cache_key, [] if cache_key in ('domains','cidrs') else 0 if cache_key in ('updated','count') else False if cache_key in ('srs_cached','source_cached') else '')"
code=p.read_text()
if new in code:
    print('List-save repair already installed.')
elif code.count(old)==1:
    fixed=code.replace(old,new)
    compile(fixed,str(p),'exec')
    backup=p.with_name('atlas.py.list-save-backup-'+str(time.time_ns()))
    shutil.copy2(p,backup)
    fd,name=tempfile.mkstemp(prefix='.atlas-repair-',dir=p.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(fixed);f.flush();os.fsync(f.fileno())
        os.chmod(name,p.stat().st_mode&0o777)
        os.replace(name,p)
    finally:
        if os.path.exists(name):os.unlink(name)
    print('List-save repair installed. Backup:',backup)
else:
    raise SystemExit('Unrecognized Atlas code. Nothing changed; use the current release package.')
PY
/etc/init.d/rpcd restart
echo 'Reopen Atlas and save the routing rules. Atlas routing was not restarted.'
