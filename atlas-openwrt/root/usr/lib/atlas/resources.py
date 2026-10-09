"""Read-only resource snapshot: no database opens, directory scans or history writes."""
import os,re,stat
from pathlib import Path

MIB=1024*1024
def snapshot(config, meminfo=Path('/proc/meminfo')):
    result={'cache':{},'system':{},'warnings':[]}
    try:
        # Kernel pseudo-file is small; cap even when used with a test fixture.
        with meminfo.open() as handle:data=handle.read(65536)
        values={key:int(value)*1024 for key,value in re.findall(r'^(MemTotal|MemAvailable):\s+(\d+)\s+kB$',data,re.M)}
        if 'MemTotal' in values:result['system']['total_bytes']=values['MemTotal']
        if 'MemAvailable' in values:
            result['system']['available_bytes']=values['MemAvailable']
            if values['MemAvailable']<64*MIB:result['warnings'].append('Мало доступной памяти: менее 64 МиБ')
    except (OSError,ValueError):pass
    experimental=config.get('experimental',{}) if isinstance(config,dict) else {}
    cache=experimental.get('cache_file',{}) if isinstance(experimental,dict) else {}
    if not isinstance(cache,dict):return result
    if not cache.get('enabled'):return result
    name=cache.get('path')
    if not isinstance(name,str) or not name.startswith('/') or '\x00' in name:return result
    path=Path(name)
    try:
        info=path.lstat()
        if stat.S_ISREG(info.st_mode):
            result['cache']['size_bytes']=info.st_size
            if hasattr(info,'st_blocks'):result['cache']['allocated_bytes']=info.st_blocks*512
            if info.st_size>=64*MIB:result['warnings'].append('Кэш достиг 64 МиБ; проверьте его рост и свободное место')
        elif stat.S_ISLNK(info.st_mode):
            result['warnings'].append('Кэш является символической ссылкой: размер не проверен')
    except FileNotFoundError:result['cache']['size_bytes']=0
    except OSError:pass
    try:
        disk=os.statvfs(path.parent)
        free=disk.f_bavail*disk.f_frsize
        result['cache']['free_bytes']=free
        if free<64*MIB:result['warnings'].append('На разделе кэша осталось менее 64 МиБ')
    except (OSError,AttributeError):pass
    return result
