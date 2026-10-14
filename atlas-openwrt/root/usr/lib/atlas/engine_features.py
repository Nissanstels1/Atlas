"""Optional engine capabilities, with a bounded in-process version snapshot."""
from collections import OrderedDict
import json
import os
import re
import subprocess
import tempfile
import time

_version_cache = OrderedDict()


def version_info(binary=None):
    """Reuse successful version output only while the same executable exists.

    CLI requests live in separate processes. No cache file survives an upgrade
    or reboot; stat identity also detects a replacement during a long worker.
    """
    binary = os.fspath(binary or binary_path())
    identity = None
    try:
        stat = os.stat(binary)
        identity = (os.path.realpath(binary), stat.st_dev, stat.st_ino,
                    stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_mode)
    except OSError:
        _version_cache.clear()
    now = time.monotonic()
    cached = _version_cache.get(identity) if identity is not None else None
    if cached and 0 <= now - cached[0] < 30:
        _version_cache.move_to_end(identity)
        return {'version': cached[1], 'features': list(cached[2])}
    try:
        value = subprocess.run([binary, 'version'], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=3)
        if value.returncode:
            return {'version': None, 'features': []}
        lines = value.stdout[:16384].splitlines()
        version = lines[0][:100] if lines else None
        raw = next((x.partition(':')[2] for x in lines if x.startswith('Features:')), '')
        features = sorted(set(x.strip() for x in raw.split(',') if re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', x.strip())))[:128]
        if identity is not None and version:
            _version_cache[identity] = (now, version, tuple(features))
            _version_cache.move_to_end(identity)
            while len(_version_cache) > 4:
                _version_cache.popitem(last=False)
        return {'version': version, 'features': features}
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return {'version': None, 'features': []}


def binary_path():
    return os.environ.get('ATLAS_ENGINE_BINARY') or ('/usr/lib/atlas-engine/bin/atlas-engine' if os.access('/usr/lib/atlas-engine/bin/atlas-engine',os.X_OK) else '/usr/bin/sing-box')


def capabilities(binary=None):
    return version_info(binary)['features']


def decode_link(link, binary=None):
    binary = binary or binary_path()
    if len(link.encode('utf-8')) > 16384 or any(x in link for x in ('\x00','\r','\n')):
        raise ValueError('Некорректная или слишком длинная ссылка')
    if 'tools.decode-link' not in capabilities(binary):
        raise ValueError('Для xhttp/splithttp нужен движок с tools.decode-link (podkop-engine r11+); штатный sing-box не поддерживает этот импорт')
    try:
        with tempfile.TemporaryFile() as output:
            value = subprocess.run([binary, 'tools', 'decode-link', '--compact', link], stdout=output, stderr=subprocess.DEVNULL, timeout=5)
            output.seek(0); data=output.read(32769)
        if value.returncode or len(data)>32768: raise ValueError()
        result=json.loads(data)
        if not isinstance(result,dict): raise ValueError()
        return result
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise ValueError('Движок не смог разобрать ссылку; настройки не изменены') from None


def validate_options(value, validate_url):
    result=dict(value)
    reserve=result.setdefault('urltest_fallbacks', [])
    mode=result.setdefault('urltest_download_check', 'default')
    url=result.setdefault('urltest_download_url', '')
    if not isinstance(reserve,list) or len(reserve)>1024 or any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{32}',x) for x in reserve) or len(set(reserve))!=len(reserve):
        raise ValueError('Резерв URLTest: уникальные ID профилей по порядку, не более 1024')
    if mode not in ('default','off','custom') or not isinstance(url,str):
        raise ValueError('Некорректный режим проверки скачивания')
    if mode=='custom':result['urltest_download_url']=validate_url(url)
    elif url:raise ValueError('URL скачивания задаётся только в режиме custom')
    return result


def extend_group(group, options, features, prefix='', custom=False):
    reserve=options.get('urltest_fallbacks',[])
    mode=options.get('urltest_download_check','default')
    if not reserve and mode=='default':return
    if custom and mode=='custom' and 'clash.download_test' not in features:raise ValueError('Проверка скачивания с критериями Atlas требует Atlas Engine r3 с clash.download_test')
    if reserve:
        if 'urltest.fallbacks' not in features:raise ValueError('Движок не поддерживает резервные выходы URLTest')
        tags=[prefix+x for x in reserve]
        if any(tag not in group['outbounds'] for tag in tags):raise ValueError('Резервный профиль отсутствует в активном пуле: проверьте фильтры, подписку и лимит узлов')
        primary=[x for x in group['outbounds'] if x not in tags]
        if not primary:raise ValueError('URLTest требует хотя бы один основной профиль')
        group['outbounds']=primary;group['fallbacks']=tags
    if mode!='default':
        if 'urltest.download_url' not in features:raise ValueError('Движок не поддерживает проверку скачивания URLTest')
        group['download_url']=options['urltest_download_url'] if mode=='custom' and not custom else ''
