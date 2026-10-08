"""Optional engine capabilities. No package-name assumptions or persistent cache."""
import json
import os
import re
import subprocess
import tempfile


def binary_path():
    return os.environ.get('ATLAS_ENGINE_BINARY') or ('/usr/lib/atlas-engine/bin/atlas-engine' if os.access('/usr/lib/atlas-engine/bin/atlas-engine',os.X_OK) else '/usr/bin/sing-box')


def capabilities(binary=None):
    binary = binary or binary_path()
    try:
        value = subprocess.run([binary, 'version'], capture_output=True, text=True, timeout=3)
        if value.returncode: return []
        lines = value.stdout[:16384].splitlines()
        raw = next((x.partition(':')[2] for x in lines if x.startswith('Features:')), '')
        return sorted(set(x.strip() for x in raw.split(',') if re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', x.strip())))[:128]
    except (OSError, subprocess.TimeoutExpired):
        return []


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
