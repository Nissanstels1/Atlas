"""Atlas: strict subscription normalization and sing-box configuration generation."""
import base64
import copy
import hashlib
import ipaddress
import json
import posixpath
import re
import time
import secrets
import socket
import uuid
import engine_features
from outbounds import outbound_graph, namespace_graph, validate_references
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_BYTES = 4 * 1024 * 1024
MAX_NODES = 512
MAX_ACTIVE_NODES = 1024
MAX_SUBSCRIPTIONS = 64
MAX_TOTAL_NODES = 4096
MAX_RULE_LISTS = float("inf")
MAX_RULE_LIST_ENTRIES = float("inf")
MAX_TOTAL_RULE_LIST_ENTRIES = float("inf")
KNOWN_DOH_DOMAINS = ['dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'dns.quad9.net',
                     'dns.adguard-dns.com', 'doh.opendns.com', 'dns.nextdns.io', 'doh.cleanbrowsing.org']
SUPPORTED = {'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'anytls', 'socks', 'http'}

class AtlasError(ValueError):
    pass

def b64(text):
    try:
        raw = re.sub(r'\s+', '', text).encode('ascii')
        return base64.b64decode(raw + b'=' * (-len(raw) % 4), altchars=b'-_', validate=True).decode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise AtlasError('Некорректный Base64') from exc

def text(value, limit=512):
    value = str(value)
    if len(value) > limit or any(ord(c) < 32 for c in value):
        raise AtlasError('Недопустимая строка')
    return value

def host(value):
    value = text(value, 253).strip().rstrip('.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            value = value.encode('idna').decode('ascii')
        except UnicodeError as exc:
            raise AtlasError('Некорректный адрес сервера') from exc
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            raise AtlasError('Некорректный адрес сервера')
        return value.lower()

def port(value):
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise AtlasError('Некорректный порт') from exc
    if not 1 <= result <= 65535:
        raise AtlasError('Порт вне диапазона')
    return result

def section_dns_resolver(value):
    """Parse an operator-supplied per-VPN DNS URI without credentials or query data."""
    value = text(value, 512).strip()
    if not value:
        return ''
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        server = host(parsed.hostname or '')
        server_port = parsed.port
    except (ValueError, AtlasError) as exc:
        raise AtlasError('Некорректный DNS URI для VPN секции') from exc
    if scheme not in ('udp', 'tls', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AtlasError('DNS resolver секции: используйте udp://, tls:// или https:// без логина и query')
    if scheme == 'https':
        path = parsed.path or '/dns-query'
        if not path.startswith('/') or any(ch in path for ch in ('\\', '\x00')) or len(path) > 255:
            raise AtlasError('Некорректный путь DoH для VPN секции')
    else:
        if parsed.path not in ('', '/'):
            raise AtlasError('UDP/DoT resolver не должен содержать путь')
        path = ''
    default_port = {'udp': 53, 'tls': 853, 'https': 443}[scheme]
    server_port = port(server_port or default_port)
    authority = '[%s]' % server if ':' in server else server
    if server_port != default_port:
        authority += ':%d' % server_port
    return '%s://%s%s' % (scheme, authority, path)

def dns_server_from_uri(value, tag, detour):
    parsed = urlsplit(section_dns_resolver(value))
    scheme = parsed.scheme
    server = host(parsed.hostname or '')
    server_port = parsed.port or {'udp':53,'tls':853,'https':443}[scheme]
    result = {'type': scheme, 'tag': tag, 'server': server, 'server_port': server_port, 'detour': detour}
    if scheme == 'https':
        result['path'] = parsed.path or '/dns-query'
    if scheme in ('https', 'tls'):
        result['tls'] = {'enabled': True, 'server_name': server}
    return result

def subscription_url(value):
    value = text(value, 16384)
    if value.startswith('happ://crypt5/'):
        from happ import decrypt_link, HappError
        try:
            value = decrypt_link(value)
        except HappError as exc:
            raise AtlasError(str(exc)) from exc
    value = text(value, 4096)
    p = urlsplit(value)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment:
        raise AtlasError('Нужен HTTPS URL без логина и фрагмента')
    host(p.hostname)
    if p.port is not None:
        port(p.port)
    return value

def subscription_headers(value):
    """Validate provider headers entered by the router administrator."""
    if value in (None, ''):
        return {}
    if not isinstance(value, str) or len(value.encode('utf-8')) > 8192:
        raise AtlasError('Заголовки подписки должны занимать не больше 8 КиБ')
    headers, seen = {}, set()
    forbidden = {'host', 'content-length', 'transfer-encoding', 'connection', 'proxy-connection',
                 'proxy-authorization', 'keep-alive', 'upgrade', 'te', 'trailer', 'accept-encoding',
                 'if-none-match', 'if-modified-since'}
    for line in value.splitlines():
        if not line.strip():
            continue
        key, sep, raw = line.partition(':')
        key = key.strip()
        raw = raw.strip()
        folded = key.lower()
        if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", key):
            raise AtlasError('Заголовок задаётся строкой «Имя: значение»')
        if folded in forbidden:
            raise AtlasError('Заголовок %s изменять нельзя' % key)
        if folded in seen:
            raise AtlasError('Заголовок %s указан дважды' % key)
        if len(raw) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
            raise AtlasError('Недопустимое значение заголовка %s' % key)
        try:
            raw.encode('latin-1')
        except UnicodeEncodeError as exc:
            raise AtlasError('Значение заголовка %s должно содержать только символы HTTP/1' % key) from exc
        if not raw:
            raise AtlasError('Значение заголовка %s пустое' % key)
        seen.add(folded)
        headers[key] = raw
        if len(headers) > 16:
            raise AtlasError('Можно указать до 16 заголовков')
    return headers

def rule_set_format(item):
    return 'binary' if item['format']=='srs' else 'source' if item['format']=='json' or item.get('source_cached') else ''


def rule_list_url(value, allow_private=False):
    value = text(value, 2048)
    p = urlsplit(value)
    if p.scheme == 'file':
        if p.netloc or p.query or p.fragment or '%' in p.path or not p.path.startswith('/'):
            raise AtlasError('Локальный список: file:/// с абсолютным путём к файлу')
        return value
    if p.scheme not in ('https','http') or not p.hostname or p.username or p.password:
        raise AtlasError('Для списка правил нужен публичный HTTP/HTTPS URL без credentials')
    hostname = host(p.hostname)
    if not allow_private and ('.' not in hostname or hostname.endswith(('.local','.localhost','.lan','.internal'))):
        raise AtlasError('URL списка должен использовать публичное DNS-имя')
    return value

def tls_from_query(q, default=False):
    security = q.get('security', 'tls' if default else 'none')
    if security in ('', 'none'):
        return None
    if security not in ('tls', 'reality'):
        raise AtlasError('Неподдерживаемый тип TLS')
    if q.get('allowInsecure', q.get('insecure', '0')).lower() in ('1', 'true'):
        raise AtlasError('Узел требует отключения проверки TLS')
    tls = {'enabled': True}
    if q.get('sni') or q.get('peer'):
        tls['server_name'] = host(q.get('sni') or q['peer'])
    if q.get('alpn'):
        tls['alpn'] = [text(x, 40) for x in q['alpn'].split(',')]
    if q.get('fp'):
        tls['utls'] = {'enabled': True, 'fingerprint': text(q['fp'], 32)}
    if security == 'reality':
        pbk, sid = q.get('pbk', ''), q.get('sid', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', pbk) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}', sid):
            raise AtlasError('Некорректный ключ Reality или short ID')
        tls['reality'] = {'enabled': True, 'public_key': pbk, 'short_id': sid}
        tls.setdefault('utls', {'enabled': True, 'fingerprint': 'chrome'})
    return tls

def transport_from_query(q):
    kind = q.get('type', 'tcp')
    if kind in ('tcp', 'raw', 'none', ''):
        if q.get('headerType', 'none') not in ('none', ''):
            raise AtlasError('TCP header camouflage не поддерживается')
        return None
    if kind == 'ws':
        tr = {'type': 'ws', 'path': text(q.get('path', '/'), 2048)}
        if q.get('host'):
            tr['headers'] = {'Host': text(q['host'])}
        return tr
    if kind == 'grpc':
        if q.get('mode', 'gun') not in ('gun', ''):
            raise AtlasError('Поддерживается только gRPC gun')
        return {'type': 'grpc', 'service_name': text(q.get('serviceName', ''))}
    if kind in ('http', 'h2'):
        return {'type': 'http', 'host': [host(x) for x in q.get('host', '').split(',') if x], 'path': text(q.get('path', '/'), 2048)}
    raise AtlasError('Транспорт %s не поддерживается' % text(kind, 32))

def uri_node(line):
    parsed=urlsplit(line)
    if parsed.scheme in ('vless','trojan') and dict(parse_qsl(parsed.query)).get('type') in ('xhttp','splithttp'):
        try: raw=engine_features.decode_link(line)
        except ValueError as exc: raise AtlasError(str(exc)) from exc
        if raw.get('type') != parsed.scheme or raw.get('transport',{}).get('type') != 'xhttp':
            raise AtlasError('Движок вернул другой протокол или транспорт')
        return normalize(raw, unquote(parsed.fragment) or parsed.hostname)
    if line.startswith('vmess://'):
        try:
            v = json.loads(b64(line[8:].split('#')[0]))
        except (ValueError, TypeError) as exc:
            raise AtlasError('Некорректный VMess JSON') from exc
        q = {'type': v.get('net', 'tcp'), 'path': v.get('path', '/'), 'host': v.get('host', ''),
             'security': v.get('tls') or 'none', 'sni': v.get('sni', ''), 'fp': v.get('fp', ''),
             'headerType': v.get('type', 'none'), 'serviceName': v.get('path', '')}
        node = {'type': 'vmess', 'server': host(v.get('add', '')), 'server_port': port(v.get('port')),
                'uuid': str(uuid.UUID(v.get('id', ''))), 'security': v.get('scy', 'auto'), 'alter_id': int(v.get('aid', 0))}
        name = text(v.get('ps') or node['server'], 160)
    else:
        p = urlsplit(line)
        kind = {'ss': 'shadowsocks', 'hy2': 'hysteria2', 'socks5': 'socks', 'socks4': 'socks', 'socks4a': 'socks'}.get(p.scheme, p.scheme)
        if kind not in SUPPORTED:
            raise AtlasError('Неподдерживаемый протокол')
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        auth = unquote(p.username or '')
        if p.password is not None:
            auth += ':' + unquote(p.password)
        name = text(unquote(p.fragment) or p.hostname or kind, 160)
        if kind == 'shadowsocks':
            if q.get('plugin'):
                raise AtlasError('Shadowsocks plugins не поддерживаются')
            body = line[5:].split('#')[0].split('?')[0].rstrip('/')
            if '@' not in body:
                body = b64(body)
            auth, address = body.rsplit('@', 1)
            if ':' not in auth:
                auth = b64(auth)
            method, password = unquote(auth).split(':', 1)
            p = urlsplit('ss://' + address)
            node = {'type': kind, 'server': host(p.hostname or ''), 'server_port': port(p.port),
                    'method': text(method, 80), 'password': text(password, 1024)}
        elif kind in ('socks', 'http'):
            node = {'type': kind, 'server': host(p.hostname or ''), 'server_port': port(p.port)}
            username, password = unquote(p.username or ''), unquote(p.password or '')
            if username:
                node['username'] = text(username, 256)
            if p.password is not None:
                node['password'] = text(password, 1024)
            if kind == 'socks':
                node['version'] = {'socks4':'4','socks4a':'4a'}.get(p.scheme, q.get('version', '5'))
        elif kind == 'tuic':
            if ':' not in auth:
                raise AtlasError('TUIC требует UUID и пароль')
            uid, password = auth.split(':', 1)
            node = {'type': kind, 'server': host(p.hostname or ''), 'server_port': port(p.port or 443),
                    'uuid': str(uuid.UUID(uid)), 'password': text(password, 1024),
                    'congestion_control': text(q.get('congestion_control', q.get('cc', 'cubic')), 32),
                    'udp_relay_mode': text(q.get('udp_relay_mode', 'native'), 32)}
        else:
            node = {'type': kind, 'server': host(p.hostname or ''), 'server_port': port(p.port or 443)}
            if kind == 'vless':
                node['uuid'] = str(uuid.UUID(auth))
                if q.get('encryption', 'none') != 'none':
                    raise AtlasError('VLESS encryption не поддерживается')
                if q.get('flow'):
                    if q['flow'] != 'xtls-rprx-vision':
                        raise AtlasError('Неподдерживаемый VLESS flow')
                    node['flow'] = q['flow']
            else:
                if not auth:
                    raise AtlasError('Пустой пароль')
                node['password'] = text(auth, 1024)
            if kind == 'hysteria2' and q.get('obfs'):
                if q['obfs'] != 'salamander' or not q.get('obfs-password'):
                    raise AtlasError('Неподдерживаемый Hysteria2 obfs')
                node['obfs'] = {'type': 'salamander', 'password': text(q['obfs-password'])}
    if node['type'] not in ('shadowsocks', 'socks', 'http'):
        tls = tls_from_query(q, node['type'] in ('trojan', 'hysteria2', 'tuic', 'anytls'))
        if tls:
            node['tls'] = tls
        if node['type'] in ('vless', 'vmess', 'trojan'):
            tr = transport_from_query(q)
            if tr:
                node['transport'] = tr
    return normalize(node, name)

# Remote JSON is data, never a complete configuration. Reject unknown fields,
# especially detour, bind_interface, routing_mark and certificate file paths.
FIELDS = {'type', 'tag', 'server', 'server_port', 'uuid', 'password', 'username', 'version', 'method', 'flow', 'security',
          'alter_id', 'tls', 'transport', 'obfs', 'packet_encoding', 'congestion_control', 'udp_relay_mode', 'network'}

def normalize(raw, name=None):
    if not isinstance(raw, dict) or raw.get('type') not in SUPPORTED:
        raise AtlasError('Неподдерживаемый outbound')
    if set(raw) - FIELDS:
        raise AtlasError('Outbound содержит неподдерживаемые поля')
    node = copy.deepcopy(raw)
    name = text(name or node.pop('tag', None) or node.get('server', 'Узел'), 160)
    node.pop('tag', None)
    node['server'] = host(node.get('server', ''))
    node['server_port'] = port(node.get('server_port'))
    if node['type'] in ('vless', 'vmess', 'tuic'):
        node['uuid'] = str(uuid.UUID(node.get('uuid', '')))
    if node['type'] in ('tuic', 'trojan', 'hysteria2', 'shadowsocks', 'anytls'):
        if not isinstance(node.get('password'), str) or not node['password']:
            raise AtlasError('Пустой пароль')
        text(node['password'], 1024)
    if node['type'] in ('socks', 'http'):
        if 'username' in node:
            node['username'] = text(node['username'], 256)
        if 'password' in node:
            if 'username' not in node:
                raise AtlasError('Пароль прокси без имени пользователя не поддерживается')
            text(node['password'], 1024)
        if node['type'] == 'socks':
            node.setdefault('version', '5')
            if node['version'] not in ('4', '4a', '5'):
                raise AtlasError('Версия SOCKS должна быть 4, 4a или 5')
    tls = node.get('tls')
    if tls:
        allowed = {'enabled', 'server_name', 'alpn', 'utls', 'reality'}
        if not isinstance(tls, dict) or set(tls) - allowed:
            raise AtlasError('Неподдерживаемые TLS параметры')
        if type(tls.get('enabled', True)) is not bool or not tls.get('enabled', True):
            raise AtlasError('TLS должен быть включён и проверять сертификат')
        if 'server_name' in tls:
            tls['server_name'] = host(tls['server_name'])
        if 'alpn' in tls:
            if not isinstance(tls['alpn'], list) or not 1 <= len(tls['alpn']) <= 8:
                raise AtlasError('Некорректный список ALPN')
            tls['alpn'] = [text(x, 40) for x in tls['alpn']]
        for key, fields in [('utls', {'enabled', 'fingerprint'}), ('reality', {'enabled', 'public_key', 'short_id'})]:
            if key in tls and (not isinstance(tls[key], dict) or set(tls[key]) - fields):
                raise AtlasError('Неподдерживаемые TLS параметры')
            if key in tls and type(tls[key].get('enabled', True)) is not bool:
                raise AtlasError('Некорректный TLS флаг')
        if 'utls' in tls:
            if not tls['utls'].get('enabled', True):
                raise AtlasError('uTLS должен быть включён')
            tls['utls']['fingerprint'] = text(tls['utls'].get('fingerprint', 'chrome'), 32)
        if 'reality' in tls:
            reality = tls['reality']
            if not reality.get('enabled', True) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', reality.get('public_key', '')) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}', reality.get('short_id', '')):
                raise AtlasError('Некорректный Reality ключ или short ID')
    if node['type'] == 'tuic' and not tls:
        raise AtlasError('TUIC требует TLS')
    if node['type'] in ('trojan', 'hysteria2', 'anytls') and not tls:
        raise AtlasError('%s требует TLS' % node['type'])
    if node['type'] == 'vmess':
        if type(node.get('alter_id', 0)) is not int or not 0 <= node.get('alter_id', 0) <= 65535:
            raise AtlasError('Некорректный VMess alter_id')
        node['security'] = text(node.get('security', 'auto'), 32)
    if 'flow' in node and (node['type'] != 'vless' or node['flow'] != 'xtls-rprx-vision'):
        raise AtlasError('Неподдерживаемый поток узла')
    if 'network' in node and node['network'] not in ('tcp', 'udp'):
        raise AtlasError('Узел поддерживает только TCP или UDP')
    if node['type'] == 'tuic':
        if node.get('congestion_control', 'cubic') not in ('cubic', 'new_reno', 'bbr'):
            raise AtlasError('Некорректный алгоритм перегрузки TUIC')
        if node.get('udp_relay_mode', 'native') not in ('native', 'quic'):
            raise AtlasError('Некорректный UDP relay режим TUIC')
    tr = node.get('transport')
    if tr:
        allowed = {'ws': {'type','path','headers','max_early_data','early_data_header_name'},
                   'grpc': {'type','service_name'}, 'http': {'type','host','path'}}
        if isinstance(tr,dict) and tr.get('type')=='xhttp':
            encoded=json.dumps(tr,allow_nan=False)
            if len(encoded.encode('utf-8'))>32768:raise AtlasError('Слишком большой xhttp transport')
            def inspect(value,depth=0):
                if depth>16:raise AtlasError('Слишком глубокие параметры xhttp')
                if isinstance(value,dict):
                    for key,child in value.items():
                        if key.endswith(('_path','_file')) and key not in ('path',):raise AtlasError('Файловые параметры xhttp запрещены')
                        if key in ('detour','bind_interface','routing_mark','network_namespace','route','inbounds','outbounds') or (key in ('insecure','skip_cert_verify') and child is True):raise AtlasError('Запрещённый параметр xhttp')
                        inspect(child,depth+1)
                elif isinstance(value,list):
                    for child in value:inspect(child,depth+1)
            inspect(tr)
            allowed['xhttp']=set(tr)

        if not isinstance(tr, dict) or tr.get('type') not in allowed or set(tr) - allowed[tr['type']]:
            raise AtlasError('Неподдерживаемый транспорт')
        if node['type'] not in ('vless', 'vmess', 'trojan'):
            raise AtlasError('Этот протокол не поддерживает V2Ray transport')
        if tr['type'] == 'ws':
            tr['path'] = text(tr.get('path', '/'), 2048)
            headers = tr.get('headers', {})
            if not isinstance(headers, dict) or len(headers) > 16 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
                raise AtlasError('Некорректные заголовки WebSocket')
            tr['headers'] = {text(k, 64): text(v, 512) for k, v in headers.items()}
        if tr['type'] == 'grpc':
            tr['service_name'] = text(tr.get('service_name', ''), 256)
        if tr['type'] == 'http':
            if not isinstance(tr.get('host', []), list) or len(tr.get('host', [])) > 16:
                raise AtlasError('Некорректный список HTTP host')
            tr['host'] = [host(x) for x in tr.get('host', [])]
            tr['path'] = text(tr.get('path', '/'), 2048)
    if 'obfs' in node:
        if not isinstance(node['obfs'], dict) or set(node['obfs']) - {'type','password'}:
            raise AtlasError('Неподдерживаемый obfs')
        if node['type'] != 'hysteria2' or node['obfs'].get('type') != 'salamander' or not node['obfs'].get('password'):
            raise AtlasError('Поддерживается только Hysteria2 salamander obfs')
        node['obfs']['password'] = text(node['obfs']['password'], 1024)
    digest = hashlib.sha256(json.dumps(node, sort_keys=True).encode()).hexdigest()[:16]
    return {'id': digest, 'name': name, 'outbound': node}

def normalize_editor_node(raw, name=None):
    """Administrator JSON input; protocol schema is checked by the real engine.

    Composite graphs belong in sections; a profile is a single independently
    selectable outbound. Subscription downloads keep their strict normalizer.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get('type'), str):
        raise AtlasError('Профиль JSON требует поле type')
    if raw['type'] in ('direct','block','dns','selector','urltest'):
        raise AtlasError('Селекторы и связанные outbound задаются в редакторе секции')
    name = text(name or raw.get('tag') or raw.get('server') or raw['type'], 160)
    try:
        graph = outbound_graph(dict(raw, tag='entry'))
    except ValueError as exc:
        raise AtlasError(str(exc)) from exc
    node = graph[0]
    node.pop('tag')
    encoded = json.dumps(node, sort_keys=True, allow_nan=False)
    return {'id': hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16], 'name': name, 'outbound': node}


def normalize_custom(raw, name=None):
    """Import an extra sing-box outbound from JSON without accepting route overrides."""
    if isinstance(raw, dict) and raw.get('type') in SUPPORTED:
        return normalize(raw, name)
    if not isinstance(raw, dict) or not isinstance(raw.get('type'), str):
        raise AtlasError('Пользовательский outbound должен быть JSON объектом с type')
    kind = raw['type'].lower()
    if not re.fullmatch('[a-z][a-z0-9_-]{0,31}', kind) or kind in ('direct','block','dns','selector','urltest'):
        raise AtlasError('Этот тип outbound не разрешён в пуле профилей')
    if len(raw) > 64:
        raise AtlasError('Слишком много полей в custom outbound')
    forbidden = {'detour','bind_interface','routing_mark','network_namespace','domain_resolver',
                 'outbounds','inbounds','route','dns','listen','certificate_path','certificate_file',
                 'private_key_path','key_path','ca_file'}
    def inspect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in forbidden or (key in ('insecure','skip_cert_verify') and child is True):
                    raise AtlasError('Custom outbound содержит запрещённое поле %s' % key)
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
    inspect(raw)
    try:
        encoded = json.dumps(raw, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise AtlasError('Некорректный JSON custom outbound') from exc
    if len(encoded.encode('utf-8')) > 32768:
        raise AtlasError('Custom outbound ограничен 32 КиБ')
    node = copy.deepcopy(raw)
    name = text(name or node.pop('tag', None) or node.get('server', kind), 160)
    node.pop('tag', None)
    if 'server' in node:
        node['server'] = host(node['server'])
    if 'server_port' in node:
        node['server_port'] = port(node['server_port'])
    digest = hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]
    return {'id': digest, 'name': name, 'outbound': node}

class _AtlasYAMLLoader(__import__('yaml').SafeLoader):
    """Safe, bounded YAML loader for Clash; aliases and duplicate keys are rejected."""
    def __init__(self, stream):
        super().__init__(stream)
        self._atlas_depth = 0
        self._atlas_nodes = 0

    def compose_node(self, parent, index):
        import yaml
        if self.check_event(yaml.AliasEvent):
            raise AtlasError('YAML aliases не поддерживаются в целях безопасности')
        self._atlas_nodes += 1
        self._atlas_depth += 1
        if self._atlas_nodes > 40000 or self._atlas_depth > 64:
            raise AtlasError('YAML превышает лимит структуры')
        try:
            return super().compose_node(parent, index)
        finally:
            self._atlas_depth -= 1

    def construct_mapping(self, node, deep=False):
        import yaml
        if not isinstance(node, yaml.MappingNode):
            raise AtlasError('Ожидался объект YAML')
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == 'tag:yaml.org,2002:merge':
                raise AtlasError('YAML merge keys не поддерживаются')
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise AtlasError('Ключи Clash YAML должны быть строками')
            if key in seen:
                raise AtlasError('В Clash YAML повторяется ключ %s' % text(key, 80))
            seen.add(key)
        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


def _clash_tls(raw, required=False):
    if raw.get('skip-cert-verify') is True:
        raise AtlasError('Отключённая проверка TLS сертификата запрещена')
    if type(raw.get('skip-cert-verify', False)) is not bool:
        raise AtlasError('skip-cert-verify должен быть логическим значением')
    enabled = raw.get('tls', required)
    if type(enabled) is not bool:
        raise AtlasError('Параметр tls должен быть логическим значением')
    tls_opts = raw.get('tls-opts', {}) or {}
    reality_opts = raw.get('reality-opts', {}) or {}
    if not isinstance(tls_opts, dict) or not isinstance(reality_opts, dict):
        raise AtlasError('Параметры Clash TLS должны быть объектами')
    if set(tls_opts) - {'server-name', 'alpn', 'fingerprint'}:
        raise AtlasError('Обнаружены неподдерживаемые tls-opts Clash')
    if set(reality_opts) - {'public-key', 'short-id', 'public_key', 'short_id'}:
        raise AtlasError('Обнаружены неподдерживаемые reality-opts Clash')
    reality = bool(reality_opts)
    if required and not enabled and not reality:
        raise AtlasError('Для этого протокола нужно включить TLS')
    if not (enabled or required or reality or tls_opts):
        return None
    result = {'enabled': True}
    sni = raw.get('servername') or raw.get('sni') or tls_opts.get('server-name')
    if sni:
        result['server_name'] = host(sni)
    alpn = raw.get('alpn', tls_opts.get('alpn'))
    if alpn:
        if isinstance(alpn, str):
            alpn = [x.strip() for x in alpn.split(',') if x.strip()]
        if not isinstance(alpn, list) or any(not isinstance(x, str) for x in alpn):
            raise AtlasError('ALPN должен быть строкой или списком строк')
        result['alpn'] = [text(x, 40) for x in alpn]
    fingerprint = raw.get('client-fingerprint') or tls_opts.get('fingerprint')
    if fingerprint:
        result['utls'] = {'enabled': True, 'fingerprint': text(fingerprint, 32)}
    if reality:
        public_key = reality_opts.get('public-key', reality_opts.get('public_key', ''))
        short_id = reality_opts.get('short-id', reality_opts.get('short_id', ''))
        if not isinstance(public_key, str) or not isinstance(short_id, str):
            raise AtlasError('Некорректные параметры Reality')
        result['reality'] = {'enabled': True, 'public_key': public_key, 'short_id': short_id}
        result.setdefault('utls', {'enabled': True, 'fingerprint': 'chrome'})
    return result


def _clash_node(raw):
    if not isinstance(raw, dict):
        raise AtlasError('Узел Clash должен быть объектом')
    name = raw.get('name')
    kind = raw.get('type')
    if not isinstance(name, str) or not isinstance(kind, str):
        raise AtlasError('В узле Clash нужны строковые name и type')
    name = text(name, 160)
    kind = kind.lower()
    aliases = {'ss': 'shadowsocks', 'hy2': 'hysteria2', 'socks5': 'socks', 'socks4': 'socks', 'socks4a': 'socks'}
    kind = aliases.get(kind, kind)
    if kind not in SUPPORTED:
        raise AtlasError('Тип Clash %s не поддерживается' % text(kind, 40))
    common = {'name', 'type', 'server', 'port', 'udp', 'ip-version', 'interface-name', 'tfo', 'mptcp',
              'tls', 'skip-cert-verify', 'servername', 'sni', 'alpn', 'client-fingerprint', 'tls-opts',
              'reality-opts', 'network', 'ws-opts', 'grpc-opts', 'h2-opts', 'http-opts', 'dialer-proxy'}
    by_type = {
        'vless': {'uuid', 'flow', 'encryption', 'packet-encoding'},
        'vmess': {'uuid', 'alterId', 'alter_id', 'cipher', 'security', 'packet-encoding'},
        'trojan': {'password'},
        'shadowsocks': {'password', 'cipher', 'method', 'plugin', 'plugin-opts'},
        'hysteria2': {'password', 'auth', 'obfs', 'obfs-password', 'up', 'down', 'ports'},
        'tuic': {'uuid', 'password', 'congestion-control', 'udp-relay-mode', 'disable-sni'},
        'anytls': {'password'},
        'socks': {'username', 'password'},
        'http': {'username', 'password'}
    }
    unknown = set(raw) - common - by_type[kind]
    if unknown:
        raise AtlasError('Поля Clash не поддерживаются: %s' % ', '.join(sorted(text(x, 64) for x in unknown)[:4]))
    if raw.get('dialer-proxy'):
        raise AtlasError('Цепочки dialer-proxy Clash не поддерживаются')
    if 'plugin' in raw or 'plugin-opts' in raw:
        raise AtlasError('Shadowsocks plugins Clash не поддерживаются')
    if kind == 'hysteria2' and raw.get('ports'):
        raise AtlasError('Hysteria2 port hopping не поддерживается')
    if not isinstance(raw.get('server'), str) or isinstance(raw.get('port'), bool) or not isinstance(raw.get('port'), (int, str)):
        raise AtlasError('Адрес Clash должен быть строкой, а port — числом')
    server = host(raw['server'])
    server_port = port(raw['port'])
    out = {'type': kind, 'server': server, 'server_port': server_port}
    if kind in ('vless', 'vmess', 'tuic'):
        if not isinstance(raw.get('uuid'), str):
            raise AtlasError('UUID узла Clash должен быть строкой')
        out['uuid'] = str(uuid.UUID(raw.get('uuid', '')))
    if kind == 'vless':
        if raw.get('encryption', 'none') != 'none':
            raise AtlasError('VLESS encryption не поддерживается')
        if raw.get('flow'):
            if raw['flow'] != 'xtls-rprx-vision':
                raise AtlasError('Неподдерживаемый VLESS flow')
            out['flow'] = raw['flow']
        if raw.get('packet-encoding'):
            out['packet_encoding'] = text(raw['packet-encoding'], 32)
    elif kind == 'vmess':
        try:
            out['alter_id'] = int(raw.get('alterId', raw.get('alter_id', 0)))
        except (TypeError, ValueError) as exc:
            raise AtlasError('Некорректный VMess alterId') from exc
        out['security'] = text(raw.get('cipher', raw.get('security', 'auto')), 32)
        if raw.get('packet-encoding'):
            out['packet_encoding'] = text(raw['packet-encoding'], 32)
    elif kind in ('trojan', 'hysteria2', 'shadowsocks', 'anytls'):
        password = raw.get('password', raw.get('auth', ''))
        if not isinstance(password, str) or not password:
            raise AtlasError('Пароль Clash должен быть непустой строкой')
        out['password'] = text(password, 1024)
        if kind == 'shadowsocks':
            method = raw.get('cipher', raw.get('method', ''))
            if not isinstance(method, str) or not method:
                raise AtlasError('Для Shadowsocks Clash нужно указать cipher')
            out['method'] = text(method, 80)
        if kind == 'hysteria2' and raw.get('obfs'):
            if raw['obfs'] != 'salamander' or not raw.get('obfs-password'):
                raise AtlasError('Поддерживается только Hysteria2 salamander obfs')
            out['obfs'] = {'type': 'salamander', 'password': text(raw['obfs-password'], 1024)}
    elif kind == 'tuic':
        out['password'] = text(raw.get('password', ''), 1024)
        out['congestion_control'] = text(raw.get('congestion-control', 'cubic'), 32)
        out['udp_relay_mode'] = text(raw.get('udp-relay-mode', 'native'), 32)
    elif kind in ('socks', 'http'):
        if raw.get('username'):
            out['username'] = text(raw['username'], 256)
        if raw.get('password'):
            if not out.get('username'):
                raise AtlasError('Пароль Clash proxy требует username')
            out['password'] = text(raw['password'], 1024)
        if kind == 'socks':
            version = raw['type'].lower().replace('socks', '')
            out['version'] = version if version in ('4', '4a') else '5'
    tls_required = kind in ('trojan', 'hysteria2', 'tuic', 'anytls') or bool(raw.get('tls')) or bool(raw.get('reality-opts'))
    tls = _clash_tls(raw, tls_required)
    if tls:
        out['tls'] = tls
    network = raw.get('network', 'tcp')
    if network not in ('tcp', 'ws', 'grpc', 'http', 'h2'):
        raise AtlasError('Транспорт Clash %s не поддерживается' % text(network, 32))
    if network in ('ws', 'grpc', 'http', 'h2'):
        options = raw.get({'ws':'ws-opts', 'grpc':'grpc-opts', 'http':'http-opts', 'h2':'h2-opts'}[network], {}) or {}
        if not isinstance(options, dict):
            raise AtlasError('Параметры транспорта Clash должны быть объектом')
        if network == 'ws':
            if set(options) - {'path', 'headers', 'max-early-data', 'early-data-header-name'}:
                raise AtlasError('Поля WebSocket Clash не поддерживаются')
            headers = options.get('headers', {}) or {}
            if not isinstance(headers, dict):
                raise AtlasError('Заголовки WebSocket должны быть объектом')
            headers = {text(k, 64): text(v, 512) for k, v in headers.items()}
            out['transport'] = {'type':'ws', 'path':text(options.get('path', '/'), 2048)}
            if headers:
                out['transport']['headers'] = headers
            if options.get('max-early-data'):
                out['transport']['max_early_data'] = port(options['max-early-data'])
            if options.get('early-data-header-name'):
                out['transport']['early_data_header_name'] = text(options['early-data-header-name'], 64)
        elif network == 'grpc':
            if set(options) - {'grpc-service-name', 'service-name', 'authority'}:
                raise AtlasError('Поля gRPC Clash не поддерживаются')
            out['transport'] = {'type':'grpc', 'service_name':text(options.get('grpc-service-name', options.get('service-name', '')), 256)}
        else:
            if set(options) - {'path', 'host'}:
                raise AtlasError('Поля HTTP/2 Clash не поддерживаются')
            path = options.get('path', '/')
            if isinstance(path, list):
                path = path[0] if path else '/'
            hosts = options.get('host', [])
            if isinstance(hosts, str):
                hosts = [hosts]
            if not isinstance(hosts, list) or any(not isinstance(x, str) for x in hosts):
                raise AtlasError('host HTTP/2 должен быть строкой или списком')
            out['transport'] = {'type':'http', 'host':[host(x) for x in hosts], 'path':text(path, 2048)}
    return normalize(out, name)


def _parse_clash_yaml(value):
    import yaml
    try:
        obj = yaml.load(value, Loader=_AtlasYAMLLoader)
    except AtlasError:
        raise
    except (yaml.YAMLError, RecursionError, MemoryError) as exc:
        raise AtlasError('Некорректный или слишком сложный Clash YAML') from exc
    if not isinstance(obj, dict) or not isinstance(obj.get('proxies'), list):
        raise AtlasError('Clash YAML должен содержать массив proxies')
    if len(obj['proxies']) > MAX_NODES:
        raise AtlasError('Больше 512 профилей в одной подписке')
    nodes, warnings, seen = [], [], set()
    for index, item in enumerate(obj['proxies']):
        try:
            node = _clash_node(item)
            if node['id'] not in seen:
                nodes.append(node)
                seen.add(node['id'])
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
            warnings.append('Узел %d: неподдерживаемый или некорректный формат' % (index + 1))
    if not nodes:
        raise AtlasError('В Clash YAML нет поддерживаемых узлов')
    return {'nodes':nodes, 'warnings':warnings, 'format':'Clash/Mihomo YAML'}


def _looks_like_clash(value):
    return bool(re.search(r'(?m)^\s*(?:proxies|proxy-groups|proxy-providers)\s*:', value))


def parse_subscription(body, trusted_json=False):
    if not body or len(body) > MAX_BYTES:
        raise AtlasError('Пустая подписка или размер больше 4 МиБ')
    try:
        value = body.decode('utf-8-sig').strip()
    except UnicodeError as exc:
        raise AtlasError('Подписка не UTF-8') from exc
    fmt = 'URI'
    if _looks_like_clash(value) or value.startswith(('---\nproxies:', 'mixed-port:', 'port:', 'socks-port:')):
        return _parse_clash_yaml(value)
    if not value.startswith(('{', '[')) and '://' not in value:
        value = b64(value).strip()
        fmt = 'Base64 URI'
    if _looks_like_clash(value) or value.startswith(('---\nproxies:', 'mixed-port:', 'port:', 'socks-port:')):
        return _parse_clash_yaml(value)
    if value.startswith(('{', '[')):
        try:
            obj = json.loads(value)
        except ValueError as exc:
            raise AtlasError('Некорректный JSON') from exc
        items = obj.get('outbounds', []) if isinstance(obj, dict) else obj
        if not isinstance(items, list):
            raise AtlasError('Нужен список outbounds')
        # Local selector/direct groups are recreated by Atlas.
        items = [x for x in items if not isinstance(x, dict) or x.get('type') not in ('direct','block','dns','selector','urltest')]
        if isinstance(obj, dict) and isinstance(obj.get('proxies'), list):
            return _parse_clash_yaml(value)
        parse, fmt = normalize_editor_node if trusted_json else normalize_custom, 'sing-box JSON'
    else:
        items = [x.strip() for x in value.splitlines() if x.strip() and not x.startswith('#')]
        parse = uri_node
    if len(items) > MAX_NODES:
        raise AtlasError('Больше 512 профилей в одной подписке')
    nodes, errors, seen = [], [], set()
    for i, item in enumerate(items):
        try:
            n = parse(item)
            if n['id'] not in seen:
                nodes.append(n)
                seen.add(n['id'])
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            errors.append('Узел %d: неподдерживаемый или некорректный формат' % (i + 1))
    if not nodes:
        raise AtlasError('Нет поддерживаемых узлов. Поддерживаются URI VLESS/VMess/Trojan/SS/Hysteria2/TUIC/AnyTLS/SOCKS/HTTP, Clash/Mihomo YAML и sing-box JSON.')
    return {'nodes': nodes, 'warnings': errors, 'format': fmt}

def defaults():
    return {'version': 1, 'subscriptions': [], 'settings': {'mode': 'rules', 'selected': 'auto',
        'domains': [], 'cidrs': [], 'bypass_domains': [], 'bypass_cidrs': [], 'interval_hours': 12,
        'countries': [], 'excluded_countries': [], 'preferred_countries': [], 'require_verified_countries': False, 'protocols': [], 'include_names': [], 'exclude_names': [],
        'auto_interval_seconds': 60, 'auto_tolerance_ms': 80, 'interrupt_connections': False,
        'auto_strategy': 'fastest', 'min_ping_ms': 0, 'max_ping_ms': 0,
        'urltest_url': 'https://www.gstatic.com/generate_204',
        'urltest_fallbacks': [], 'urltest_download_check': 'default', 'urltest_download_url': '',
        'bootstrap_dns_type': 'https', 'bootstrap_dns_server': '1.1.1.1',
        'bootstrap_dns_sni': 'cloudflare-dns.com', 'bootstrap_dns_path': '/dns-query',
        'udp_over_tcp': False, 'udp_over_tcp_version': 2,
        'interface_monitoring': False, 'monitored_interfaces': [], 'interface_reload_delay_ms': 2000, 'default_interface': '', 'log_level': 'warn',
        'dns_filter': 'cloudflare', 'fakeip': False, 'fakeip_ttl_seconds': 60, 'resolve_real_ip': False, 'browser_diagnostics': False, 'yacd_enabled': False, 'yacd_wan': False, 'yacd_listen': '127.0.0.1', 'blocked_domains': [], 'max_active_nodes': 512,
        'routing_excluded_ips': [], 'routed_source_ips': [], 'sections': [], 'disable_quic': False, 'exclude_ntp': False,
        'kill_switch': False,
        'custom_dns_type': 'https', 'custom_dns_server': '', 'custom_dns_sni': '', 'custom_dns_path': '/dns-query',
        'mixed_proxy_enabled': False, 'mixed_proxy_listen': '', 'mixed_proxy_port': 2080,
        'mixed_proxy_username': '', 'mixed_proxy_password': '', 'block_known_doh': False,
        'fetch_lists_via_proxy': False, 'fetch_lists_subscription': '', 'fetch_lists_section': '', 'section_choices': {}, 'remote_lists': [], 'list_max_bytes': MAX_BYTES,
        'dhcp_dns_enabled': False, 'config_storage': 'flash', 'config_custom_dir': '', 'cache_storage': 'flash',
        'cache_custom_path': ''}}

def validate_settings(data):
    if not isinstance(data, dict):
        raise AtlasError('Нужен объект настроек')
    result = defaults()['settings']
    if set(data) - set(result):
        raise AtlasError('Неизвестная настройка')
    result.update(data)
    if type(result['interface_reload_delay_ms']) is not int or not 0 <= result['interface_reload_delay_ms'] <= 60000:
        raise AtlasError('Задержка восстановления WAN: 0–60000 мс')
    if type(result['list_max_bytes']) is not int or not 0 <= result['list_max_bytes'] <= 256 * 1024 * 1024:
        raise AtlasError('Размер списка: 0 (без лимита) или до 256 МиБ')
    if type(result['require_verified_countries']) is not bool:
        raise AtlasError('Некорректный флаг проверки страны выхода')
    if type(result['dhcp_dns_enabled']) is not bool:
        raise AtlasError('Некорректный режим DNS для dnsmasq')
    if result['config_storage'] not in ('flash', 'ram', 'external'):
        raise AtlasError('Место конфигурации должно быть flash или ram')
    config_dir = result['config_custom_dir']
    if result['config_storage'] == 'external':
        if not isinstance(config_dir,str) or not config_dir.startswith('/') or posixpath.normpath(config_dir) != config_dir or not re.fullmatch(r'/[A-Za-z0-9_./-]+',config_dir):
            raise AtlasError('Каталог конфигурации задайте в примонтированном /mnt или /media')
    elif config_dir:
        raise AtlasError('Каталог задаётся только для внешней конфигурации')
    if result['cache_storage'] not in ('flash', 'ram', 'external'):
        raise AtlasError('Место кеша должно быть flash, ram или external')
    if not isinstance(result['cache_custom_path'], str):
        raise AtlasError('Некорректный путь внешнего кеша')
    if result['cache_storage'] == 'external':
        cache_path = text(result['cache_custom_path'].strip(), 240)
        if (not cache_path.startswith('/') or
                posixpath.normpath(cache_path) != cache_path or
                any(part in ('', '.', '..') for part in cache_path.split('/')[1:]) or
                not re.fullmatch(r'/[A-Za-z0-9_./-]+\.db', cache_path)):
            raise AtlasError('Внешний кеш задайте файлом .db в примонтированном /mnt или /media')
        result['cache_custom_path'] = cache_path
    elif result['cache_custom_path']:
        raise AtlasError('Путь можно задавать только для внешнего кеша')
    if result['mode'] not in ('rules', 'global'):
        raise AtlasError('Неизвестный режим')
    if not isinstance(result['selected'], str) or not re.fullmatch(r'auto|[a-f0-9]{32}', result['selected']):
        raise AtlasError('Некорректный выбор узла')
    if type(result['interval_hours']) is not int or not 1 <= result['interval_hours'] <= 168:
        raise AtlasError('Интервал: 1–168 часов')
    if type(result['max_active_nodes']) is not int or result['max_active_nodes'] not in (0, 128, 256, 512, 1024):
        raise AtlasError('Пул активных профилей: 0 без лимита либо 128, 256, 512, 1024')
    for key, minimum, maximum in [('auto_interval_seconds', 30, 1800), ('auto_tolerance_ms', 1, 2000)]:
        if type(result[key]) is not int or not minimum <= result[key] <= maximum:
            raise AtlasError('%s: допустимо %d–%d' % (key, minimum, maximum))
    if type(result['interrupt_connections']) is not bool:
        raise AtlasError('Некорректный флаг разрыва соединений')
    if result['dns_filter'] not in ('cloudflare', 'adguard', 'custom'):
        raise AtlasError('Неизвестный DNS-фильтр')
    if type(result['yacd_enabled']) is not bool or type(result['yacd_wan']) is not bool:
        raise AtlasError('Некорректный флаг внешней панели')
    try:
        api_ip = ipaddress.ip_address(result['yacd_listen'])
    except (ValueError, TypeError) as exc:
        raise AtlasError('Для панели укажите IP адрес роутера') from exc
    if api_ip.version != 4 or api_ip.is_multicast or api_ip.is_link_local or (api_ip.is_unspecified and not result['yacd_wan']) or (not api_ip.is_private and not result['yacd_wan']):
        raise AtlasError('Внешний адрес панели требует включения WAN-доступа')
    if type(result['fakeip']) is not bool:
        raise AtlasError('Некорректный флаг FakeIP')
    if type(result['browser_diagnostics']) is not bool:
        raise AtlasError('Некорректный флаг диагностики браузера')
    if result['browser_diagnostics'] and not result['fakeip']:
        raise AtlasError('Для диагностики браузера включите FakeIP')
    if type(result['resolve_real_ip']) is not bool:
        raise AtlasError('Некорректный флаг разрешения реальных IP')
    if type(result['fakeip_ttl_seconds']) is not int or not 1 <= result['fakeip_ttl_seconds'] <= 86400:
        raise AtlasError('TTL FakeIP: укажите число от 1 до 86400 секунд')
    if result['bootstrap_dns_type'] not in ('https','tls','udp'):
        raise AtlasError('Bootstrap DNS: HTTPS, TLS или UDP')
    try:
        bootstrap_ip = ipaddress.ip_address(result['bootstrap_dns_server'])
    except (ValueError, TypeError) as exc:
        raise AtlasError('Bootstrap DNS должен задаваться IP адресом, чтобы не требовать DNS для самого себя') from exc
    if bootstrap_ip.is_loopback or bootstrap_ip.is_link_local or bootstrap_ip.is_multicast or bootstrap_ip.is_unspecified:
        raise AtlasError('Недопустимый IP адрес bootstrap DNS')
    result['bootstrap_dns_server'] = str(bootstrap_ip)
    result['bootstrap_dns_sni'] = host(result['bootstrap_dns_sni'])
    result['bootstrap_dns_path'] = text(result['bootstrap_dns_path'], 512)
    if not result['bootstrap_dns_path'].startswith('/') or any(x in result['bootstrap_dns_path'] for x in ('?', '#','\\')):
        raise AtlasError('Путь bootstrap DoH должен начинаться с / и не содержать query/fragment')
    if type(result['udp_over_tcp']) is not bool or type(result['udp_over_tcp_version']) is not int or result['udp_over_tcp_version'] not in (1,2):
        raise AtlasError('UDP-over-TCP: укажите версию 1 или 2')
    if type(result['interface_monitoring']) is not bool:
        raise AtlasError('Некорректный флаг мониторинга интерфейсов')
    if not isinstance(result['default_interface'], str):
        raise AtlasError('Некорректный выходной интерфейс')
    result['default_interface'] = text(result['default_interface'].strip(), 15)
    if result['default_interface'] and (not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', result['default_interface']) or result['default_interface'] in ('lo','atlas0')):
        raise AtlasError('Некорректный выходной интерфейс')
    if result['log_level'] not in ('debug','info','warn','error'):
        raise AtlasError('Уровень журнала должен быть debug, info, warn или error')
    if not isinstance(result['monitored_interfaces'], list):
        raise AtlasError('Контролируемые интерфейсы должны быть массивом')
    monitored = []
    for item in result['monitored_interfaces']:
        item = text(item.strip(), 15) if isinstance(item, str) else ''
        if not re.fullmatch('[A-Za-z0-9_.-]{1,15}', item):
            raise AtlasError('Имя контролируемого интерфейса должно быть логическим именем OpenWrt, например wan')
        if item not in monitored:
            monitored.append(item)
    result['monitored_interfaces'] = monitored
    if result['interface_monitoring'] and not monitored:
        raise AtlasError('Выберите логический интерфейс для мониторинга, например wan')
    if type(result['block_known_doh']) is not bool:
        raise AtlasError('Некорректный флаг block_known_doh')
    if type(result['fetch_lists_via_proxy']) is not bool:
        raise AtlasError('Некорректный флаг прокси для загрузки списков')
    if not isinstance(result['fetch_lists_subscription'], str) or (result['fetch_lists_subscription'] and not re.fullmatch('[a-f0-9]{16}', result['fetch_lists_subscription'])):
        raise AtlasError('Некорректная подписка для загрузки списков')
    for key in ('disable_quic', 'exclude_ntp', 'kill_switch'):
        if type(result[key]) is not bool:
            raise AtlasError('Некорректный флаг %s' % key)
    if result['custom_dns_type'] not in ('https','tls','udp'):
        raise AtlasError('Тип пользовательского DNS должен быть HTTPS, TLS или UDP')
    if result['dns_filter'] == 'custom':
        result['custom_dns_server'] = host(result['custom_dns_server'])
        if result['custom_dns_type'] in ('https','tls'):
            result['custom_dns_sni'] = host(result['custom_dns_sni'] or result['custom_dns_server'])
        result['custom_dns_path'] = text(result['custom_dns_path'], 512)
        if not result['custom_dns_path'].startswith('/') or any(x in result['custom_dns_path'] for x in ('?', '#','\\')):
            raise AtlasError('Путь DoH должен начинаться с / и не содержать query/fragment')
    if type(result['mixed_proxy_enabled']) is not bool:
        raise AtlasError('Некорректный флаг LAN proxy')
    if type(result['mixed_proxy_port']) is not int or not 1024 <= result['mixed_proxy_port'] <= 65535:
        raise AtlasError('Порт LAN proxy должен быть 1024–65535')
    if result['mixed_proxy_enabled']:
        try:
            bind_ip = ipaddress.ip_address(result['mixed_proxy_listen'])
        except (ValueError, TypeError) as exc:
            raise AtlasError('Укажите IP роутера в LAN для HTTP/SOCKS listener') from exc
        if not bind_ip.is_private or bind_ip.is_loopback or bind_ip.is_link_local:
            raise AtlasError('LAN proxy разрешён только на частном LAN адресе роутера')
        result['mixed_proxy_listen'] = str(bind_ip)
        username = text(result['mixed_proxy_username'], 64)
        password = text(result['mixed_proxy_password'], 128)
        if not re.fullmatch('[A-Za-z0-9_.-]{3,64}', username) or len(password) < 12:
            raise AtlasError('Для LAN proxy нужны имя пользователя и пароль минимум 12 символов')
    if not isinstance(result['remote_lists'], list) or len(result['remote_lists']) > MAX_RULE_LISTS:
        raise AtlasError('Источники списков должны быть массивом')
    lists, list_ids, total_entries = [], set(), 0
    for source in result['remote_lists']:
        required = {'name','url','policy','format','enabled'}
        allowed = required | {'id','domains','cidrs','updated','error','count','srs_cached','interface','section','file_version','allow_private','allow_symlinks','source_cached','source_rules'}
        if not isinstance(source, dict) or required - set(source) or set(source) - allowed:
            raise AtlasError('Некорректная запись списка правил')
        name = text(source['name'].strip(), 64)
        for flag in ('allow_private','allow_symlinks'):
            if type(source.get(flag, False)) is not bool:
                raise AtlasError('Разрешения источника должны быть логическими значениями')
        url = rule_list_url(source['url'], allow_private=source.get('allow_private',False))
        if not name:
            raise AtlasError('Введите название списка правил')
        if source['policy'] not in ('proxy','direct','exclude','interface','block','dnsblock'):
            raise AtlasError('Политика списка: proxy, direct, exclude, interface, block или dnsblock')
        if source['format'] not in ('auto','domains','hosts','cidrs','adguard','json','srs'):
            raise AtlasError('Формат списка: auto, domains, hosts, cidrs, adguard, JSON или SRS')
        if type(source['enabled']) is not bool:
            raise AtlasError('Некорректный флаг списка')
        list_id = source.get('id') or hashlib.sha256(url.encode()).hexdigest()[:16]
        if not isinstance(list_id, str) or not re.fullmatch('[a-f0-9]{16}', list_id) or list_id in list_ids:
            raise AtlasError('ID списков должен быть уникальным')
        list_ids.add(list_id)
        iface = source.get('interface', '')
        if not isinstance(iface, str):
            raise AtlasError('Интерфейс удалённого списка должен быть строкой')
        iface = text(iface.strip(), 15)
        if iface and (not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', iface) or iface in ('lo','atlas0')):
            raise AtlasError('Недопустимый интерфейс удалённого списка')
        if source['policy'] == 'interface' and not iface:
            raise AtlasError('Для политики interface укажите VPN-интерфейс списка')
        if source['policy'] != 'interface' and iface:
            raise AtlasError('Интерфейс можно задать только для политики interface')
        normalized = {'id':list_id,'name':name,'url':url,'policy':source['policy'],'format':source['format'],'enabled':source['enabled'],'interface':iface,'section':source.get('section','')}
        normalized['file_version'] = source.get('file_version', '') if isinstance(source.get('file_version',''), str) else ''
        normalized.update({flag:source.get(flag,False) for flag in ('allow_private','allow_symlinks')})
        for key in ('domains','cidrs'):
            values = source.get(key, [])
            if not isinstance(values, list) or len(values) > MAX_RULE_LIST_ENTRIES:
                raise AtlasError('Записи списка должны быть массивом')
            out, seen_values = [], set()
            for value in values:
                if not isinstance(value, str):
                    raise AtlasError('Правило списка должно быть строкой')
                if key == 'domains':
                    value = host(value)
                    if ':' in value or re.fullmatch(r'[0-9.]+', value):
                        raise AtlasError('Список доменов содержит IP вместо домена')
                else:
                    try:
                        value = str(ipaddress.ip_network(value, strict=False))
                    except ValueError as exc:
                        raise AtlasError('Список содержит некорректную IP сеть') from exc
                if value not in seen_values:
                    seen_values.add(value)
                    out.append(value)
            normalized[key] = out
        if normalized['policy'] == 'dnsblock' and normalized['cidrs']:
            raise AtlasError('DNS block list может содержать только домены')
        total_entries += len(normalized['domains']) + len(normalized['cidrs'])
        normalized['updated'] = source.get('updated', 0)
        if type(normalized['updated']) is not int or normalized['updated'] < 0:
            raise AtlasError('Некорректная дата обновления списка')
        normalized['error'] = text(source.get('error',''), 160)
        normalized['source_cached'] = source.get('source_cached', False)
        source_rules=source.get('source_rules')
        if source_rules is not None and (not isinstance(source_rules,dict) or not isinstance(source_rules.get('rules'),list)):
            raise AtlasError('Некорректный сохранённый JSON ruleset')
        if source_rules is not None:normalized['source_rules']=copy.deepcopy(source_rules)
        if type(normalized['source_cached']) is not bool:
            raise AtlasError('Некорректный статус JSON кеша')
        normalized['srs_cached'] = source.get('srs_cached', False)
        if type(normalized['srs_cached']) is not bool:
            raise AtlasError('Некорректный статус кеша SRS')
        if 'count' in source and (type(source['count']) is not int or not 0 <= source['count'] <= MAX_RULE_LIST_ENTRIES):
            raise AtlasError('Некорректное число правил списка')
        lists.append(normalized)
    if total_entries > MAX_TOTAL_RULE_LIST_ENTRIES:
        raise AtlasError('Общий кеш списков ограничен 50000 правилами')
    result['remote_lists'] = lists
    if result['auto_strategy'] not in ('fastest', 'slowest', 'stable'):
        raise AtlasError('Критерий автовыбора должен быть fastest, slowest или stable')
    for key in ('min_ping_ms', 'max_ping_ms'):
        if type(result[key]) is not int or not 0 <= result[key] <= 60000:
            raise AtlasError('Порог пинга должен быть от 0 до 60000 мс; 0 отключает порог')
    if result['min_ping_ms'] and result['max_ping_ms'] and result['min_ping_ms'] > result['max_ping_ms']:
        raise AtlasError('Минимальный пинг не может быть выше максимального')
    url = text(result['urltest_url'], 2048)
    parsed_test_url = urlsplit(url)
    if parsed_test_url.scheme != 'https' or not parsed_test_url.hostname or parsed_test_url.username or parsed_test_url.password or parsed_test_url.fragment:
        raise AtlasError('URL проверки профилей должен быть HTTPS адресом без логина и фрагмента')
    host(parsed_test_url.hostname)
    result['urltest_url'] = url
    try: result=engine_features.validate_options(result,subscription_url)
    except ValueError as exc:raise AtlasError(str(exc)) from exc
    for key in ('countries', 'excluded_countries', 'preferred_countries', 'protocols', 'include_names', 'exclude_names'):
        if not isinstance(result[key], list) or len(result[key]) > 50:
            raise AtlasError('Фильтр ограничен 50 значениями')
        values = []
        for value in result[key]:
            if not isinstance(value, str):
                raise AtlasError('Фильтр должен содержать строки')
            value = text(value.strip(), 100)
            if not value:
                raise AtlasError('Пустое значение фильтра')
            if key in ('countries', 'excluded_countries', 'preferred_countries'):
                value = value.upper()
                if not re.fullmatch('[A-Z]{2}', value):
                    raise AtlasError('Укажите двухбуквенный код страны, например EE')
            elif key == 'protocols':
                value = value.lower()
                if value not in SUPPORTED:
                    raise AtlasError('Неизвестный протокол в фильтре')
            else:
                value = value.casefold()
            if value not in values:
                values.append(value)
        result[key] = values
    for key in ('domains', 'bypass_domains', 'blocked_domains', 'cidrs', 'bypass_cidrs', 'routing_excluded_ips', 'routed_source_ips'):
        if not isinstance(result[key], list):
            raise AtlasError('Правила должны быть массивом')
        values = []
        for item in result[key]:
            if not isinstance(item, str):
                raise AtlasError('Правило должно быть строкой')
            if 'domains' in key:
                item = host(item.strip().removeprefix('*.'))
                if ':' in item or re.fullmatch(r'[0-9.]+', item):
                    raise AtlasError('IP адрес добавьте в список сетей')
            else:
                try:
                    item = str(ipaddress.ip_network(item.strip(), strict=False))
                except ValueError as exc:
                    raise AtlasError('Некорректная IP сеть') from exc
            if item not in values:
                values.append(item)
        result[key] = values
    if not isinstance(result['sections'], list):
        raise AtlasError('Секции маршрутизации должны быть списком')
    sections, names = [], set()
    for section in result['sections']:
        required = {'name', 'policy', 'domains', 'cidrs', 'source_ips'}
        allowed = required | {'pool', 'interface', 'resolver', 'source_interfaces', 'ports', 'networks', 'id', 'enabled', 'mixed_proxy', 'outbound_config', 'exclude_domains', 'exclude_cidrs', 'exclude_source_ips', 'resolve_real_ip', 'auto_interval_seconds', 'auto_tolerance_ms', 'urltest_url', 'udp_over_tcp', 'udp_over_tcp_version', 'urltest_fallbacks', 'urltest_download_check', 'urltest_download_url'}
        if not isinstance(section, dict) or required - set(section) or set(section) - allowed:
            raise AtlasError('Некорректная секция маршрутизации')
        section = dict(section)
        try: section=engine_features.validate_options(section,subscription_url)
        except ValueError as exc:raise AtlasError(str(exc)) from exc
        if (section['urltest_fallbacks'] or section['urltest_download_check']!='default') and (section['policy']!='proxy' or section.get('outbound_config')):
            raise AtlasError('Расширенный URLTest задавайте для обычного прокси-пула; для экспертного выхода используйте JSON')
        section.setdefault('resolve_real_ip', None)
        section.setdefault('udp_over_tcp',None)
        section.setdefault('udp_over_tcp_version',None)
        if section['udp_over_tcp'] is not None and type(section['udp_over_tcp']) is not bool:
            raise AtlasError('UDP-over-TCP секции: наследовать, включить или выключить')
        if section['udp_over_tcp_version'] is not None and (type(section['udp_over_tcp_version']) is not int or section['udp_over_tcp_version'] not in (1,2)):
            raise AtlasError('Версия UDP-over-TCP секции: 1 или 2')
        if section['resolve_real_ip'] is not None and type(section['resolve_real_ip']) is not bool:
            raise AtlasError('Разрешение IP секции: наследовать, включить или выключить')
        for key,minimum,maximum in [('auto_interval_seconds',30,1800),('auto_tolerance_ms',1,2000)]:
            section.setdefault(key,None)
            if section[key] is not None and (type(section[key]) is not int or not minimum <= section[key] <= maximum):
                raise AtlasError('Параметр автопроверки секции вне допустимого диапазона')
        section.setdefault('urltest_url','')
        if not isinstance(section['urltest_url'],str):
            raise AtlasError('URL автопроверки секции должен быть строкой')
        if section['urltest_url']:
            section['urltest_url'] = subscription_url(section['urltest_url'])
        section.setdefault('pool', '')
        section.setdefault('interface', '')
        section.setdefault('resolver', '')
        section.setdefault('source_interfaces', [])
        section.setdefault('ports', [])
        section.setdefault('networks', [])
        section.setdefault('enabled', True)
        section.setdefault('id', hashlib.sha256(section['name'].encode()).hexdigest()[:16])
        section.setdefault('mixed_proxy', {})
        section.setdefault('outbound_config', [])
        for key in ('exclude_domains','exclude_cidrs','exclude_source_ips'):section.setdefault(key,[])
        name = text(section['name'].strip(), 48)
        if not name or name.casefold() in names:
            raise AtlasError('Названия секций должны быть непустыми и уникальными')
        names.add(name.casefold())
        if section['policy'] not in ('proxy', 'direct', 'exclude', 'block', 'interface'):
            raise AtlasError('Секция может использовать proxy, direct, exclude, block или VPN-интерфейс')
        pool = section['pool']
        if not isinstance(pool, str) or (pool and not re.fullmatch('[a-f0-9]{16}', pool)):
            raise AtlasError('Некорректный ID пула подписки секции')
        interface = section['interface']
        if not isinstance(interface, str):
            raise AtlasError('Имя сетевого интерфейса должно быть строкой')
        interface = text(interface.strip(), 15)
        if interface and (not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', interface) or interface in ('lo','atlas0')):
            raise AtlasError('Недопустимое имя сетевого интерфейса')
        if section['policy'] == 'interface' and not interface:
            raise AtlasError('Укажите VPN-сетевой интерфейс, например wg0')
        if section['policy'] != 'interface' and interface:
            raise AtlasError('VPN-интерфейс указывается только для политики interface')
        resolver = section_dns_resolver(section['resolver']) if isinstance(section['resolver'], str) else ''
        if section['resolver'] and not resolver:
            raise AtlasError('Некорректный DNS resolver секции')
        if resolver and (section['policy'] in ('block',) or not section['domains']):
            raise AtlasError('DNS-сервер секции требует домен и политику маршрутизации')
        if pool and section['policy'] != 'proxy':
            raise AtlasError('Пул подписки можно задать только для политики proxy')
        normalized = {'name': name, 'policy': section['policy'], 'pool': pool, 'interface': interface, 'resolver': resolver}
        normalized.update({key:section[key] for key in ('resolve_real_ip','auto_interval_seconds','auto_tolerance_ms','urltest_url','udp_over_tcp','udp_over_tcp_version','urltest_fallbacks','urltest_download_check','urltest_download_url')})
        if type(section['enabled']) is not bool or not isinstance(section['id'], str) or not re.fullmatch('[a-f0-9]{16}', section['id']):
            raise AtlasError('Некорректный ID или флаг секции')
        if any(x['id'] == section['id'] for x in sections):
            raise AtlasError('ID секций должны быть уникальными')
        normalized.update(id=section['id'], enabled=section['enabled'])
        try:
            normalized['outbound_config'] = outbound_graph(section['outbound_config'],allow_external=True)
        except ValueError as exc:
            raise AtlasError(str(exc)) from exc
        if any(section[k] is not None if k!='urltest_url' else bool(section[k]) for k in ('auto_interval_seconds','auto_tolerance_ms','urltest_url')) and (section['policy']!='proxy' or normalized['outbound_config']):
            raise AtlasError('Автопроверку задавайте для обычного прокси-пула; для экспертного выхода используйте JSON')
        if normalized['outbound_config'] and (section['policy'] != 'proxy' or pool):
            raise AtlasError('JSON outbound требует proxy без подписочного пула')
        if any(section[k] is not None for k in ('udp_over_tcp','udp_over_tcp_version')) and (section['policy']!='proxy' or normalized['outbound_config']):
            raise AtlasError('UDP-over-TCP формы относится к подписочному прокси-пулу; экспертный выход настраивается в JSON')
        listener = section['mixed_proxy']
        if not isinstance(listener, dict) or set(listener) - {'enabled', 'listen', 'port', 'username', 'password'}:
            raise AtlasError('Некорректные параметры прокси секции')
        listener = dict(enabled=False, listen='', port=2081, username='', password='') | listener
        if type(listener['enabled']) is not bool:
            raise AtlasError('Некорректный флаг прокси секции')
        if listener['enabled']:
            if section['policy'] == 'block':
                raise AtlasError('Прокси нельзя включить для блокирующей секции')
            try:
                address = ipaddress.ip_address(listener['listen'])
            except (TypeError, ValueError):
                raise AtlasError('Укажите LAN или loopback IP прокси секции') from None
            if not address.is_private or address.is_unspecified or address.is_multicast or address.is_link_local:
                raise AtlasError('Прокси секции разрешён на частном LAN или loopback IP')
            if type(listener['port']) is not int or not 1024 <= listener['port'] <= 65535:
                raise AtlasError('Порт прокси секции должен быть 1024–65535')
            if not isinstance(listener['username'], str) or not re.fullmatch('[A-Za-z0-9_.-]{3,64}', listener['username']):
                raise AtlasError('Для прокси секции нужно имя пользователя от 3 символов')
            if not isinstance(listener['password'], str) or not 12 <= len(listener['password']) <= 128:
                raise AtlasError('Для прокси секции нужен пароль от 12 до 128 символов')
            listener['listen'] = str(address)
            if section['enabled']:
                occupied = {19090}
                if result['mixed_proxy_enabled']:
                    occupied.add(result['mixed_proxy_port'])
                occupied.update(x['mixed_proxy']['port'] for x in sections if x['enabled'] and x['mixed_proxy']['enabled'])
                if listener['port'] in occupied:
                    raise AtlasError('Порт прокси секции уже используется Atlas')
        normalized['mixed_proxy'] = listener
        source_interfaces = section['source_interfaces']
        if not isinstance(source_interfaces, list):
            raise AtlasError('Входные интерфейсы секции должны быть массивом')
        normalized_interfaces = []
        for source_interface in source_interfaces:
            source_interface = text(source_interface.strip(), 15) if isinstance(source_interface, str) else ''
            if not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', source_interface) or source_interface in ('lo', 'atlas0'):
                raise AtlasError('Недопустимое имя входного интерфейса')
            if source_interface not in normalized_interfaces:
                normalized_interfaces.append(source_interface)
        normalized['source_interfaces'] = normalized_interfaces
        ports = section['ports']
        if not isinstance(ports, list) or len(ports) > 64:
            raise AtlasError('В секции можно задать до 64 портов или диапазонов')
        normalized['ports'] = []
        for value in ports:
            if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', value):
                raise AtlasError('Порты секции: 443 или диапазон 10000-20000')
            bounds = [int(part) for part in value.split('-')]
            if any(not 1 <= bound <= 65535 for bound in bounds) or bounds[0] > bounds[-1]:
                raise AtlasError('Порт должен быть 1–65535; начало диапазона не выше конца')
            value = '-'.join(str(bound) for bound in bounds)
            if value not in normalized['ports']:
                normalized['ports'].append(value)
        networks = section['networks']
        if not isinstance(networks, list) or len(networks) > 2 or any(value not in ('tcp', 'udp') for value in networks):
            raise AtlasError('Транспорт секции: tcp, udp или оба')
        normalized['networks'] = list(dict.fromkeys(networks))
        for key in ('domains', 'cidrs', 'source_ips', 'exclude_domains', 'exclude_cidrs', 'exclude_source_ips'):
            values = section[key]
            if not isinstance(values, list):
                raise AtlasError('Правила секции должны быть массивом')
            out, seen_values = [], set()
            for item in values:
                if not isinstance(item, str):
                    raise AtlasError('Правило секции должно быть строкой')
                if key in ('domains','exclude_domains'):
                    item = host(item.strip().removeprefix('*.'))
                    if ':' in item or re.fullmatch(r'[0-9.]+', item):
                        raise AtlasError('Укажите домен или поместите IP в поле CIDR')
                else:
                    try:
                        item = str(ipaddress.ip_network(item.strip(), strict=False))
                    except ValueError as exc:
                        raise AtlasError('Некорректная IP сеть в секции') from exc
                if item not in seen_values:
                    seen_values.add(item)
                    out.append(item)
            normalized[key] = out
        if normalized['enabled'] and not listener['enabled'] and not normalized['outbound_config'] and not any(x.get('section') == normalized['id'] for x in result['remote_lists']) and result['fetch_lists_section'] != normalized['id'] and not any(normalized[key] for key in ('domains', 'cidrs', 'source_ips', 'source_interfaces', 'ports', 'networks')):
            raise AtlasError('Добавьте в секцию хотя бы одно правило')
        sections.append(normalized)
    result['sections'] = sections
    section_ids = {x['id']: x for x in sections}
    for item in result['remote_lists']:
        target = item['section']
        if not isinstance(target,str) or (target and (target not in section_ids or item['policy'] != 'proxy' or section_ids[target]['policy'] not in ('proxy','interface','direct'))):
            raise AtlasError('Список требует существующую секцию и политику proxy')
        if target and item['enabled'] and not section_ids[target]['enabled']:
            raise AtlasError('Включённый список ссылается на выключенную секцию')
    target = result['fetch_lists_section']
    if not isinstance(target, str) or (target and (target not in section_ids or not section_ids[target]['enabled'] or section_ids[target]['policy'] in ('block','exclude'))):
        raise AtlasError('Выберите включённую секцию для загрузки списков')
    if target and result['fetch_lists_subscription']:
        raise AtlasError('Выберите либо секцию, либо подписку для загрузки списков')
    choices = result['section_choices']
    if not isinstance(choices, dict) or any(not isinstance(k,str) or not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', k) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', v) for k,v in choices.items()):
        raise AtlasError('Некорректный выбор серверов секций')

    return result

def country_from_name(name):
    """Provider-supplied label, never an IP geolocation claim."""
    flag = re.search('[\U0001f1e6-\U0001f1ff]{2}', name)
    if flag:
        return ''.join(chr(ord(c) - 0x1f1e6 + ord('A')) for c in flag[0])
    # A leading country code is common; never infer from arbitrary words/domain.
    prefix = re.match(r'^\s*(?:\[([A-Z]{2})\]|([A-Z]{2})(?=[\s|:_-]))', name)
    return (prefix[1] or prefix[2]) if prefix else ''

COUNTRY_VERIFICATION_TTL = 30 * 24 * 60 * 60


def verified_country_from_node(node, now=None):
    """Only locally measured, recent exit metadata is trusted by country filters."""
    country = node.get('verified_country', '')
    checked = node.get('country_verified_at')
    now = int(time.time() if now is None else now)
    if (not isinstance(country, str) or not re.fullmatch('[A-Z]{2}', country) or
            type(checked) is not int or checked > now + 300 or
            now - checked > COUNTRY_VERIFICATION_TTL):
        return ''
    return country


def country_for_node(node, require_verified=False, now=None):
    verified = verified_country_from_node(node, now)
    return verified or ('' if require_verified else country_from_name(node.get('name', '')))


def country_source_for_node(node, now=None):
    if verified_country_from_node(node, now):
        return 'exit-ip'
    return 'provider-name' if country_from_name(node.get('name', '')) else 'unknown'


def filter_nodes(nodes, settings, validated=False):
    settings = settings if validated else validate_settings(settings)
    result = []
    for n in nodes:
        name = n['name'].casefold()
        country = country_for_node(n, settings['require_verified_countries'])
        if (settings['require_verified_countries'] and not country and
                any(settings[k] for k in ('countries', 'excluded_countries', 'preferred_countries'))):
            continue
        if settings['countries'] and country not in settings['countries']:
            continue
        if country and country in settings['excluded_countries']:
            continue
        if settings['protocols'] and n['outbound']['type'] not in settings['protocols']:
            continue
        if settings['include_names'] and not any(word in name for word in settings['include_names']):
            continue
        if any(word in name for word in settings['exclude_names']):
            continue
        result.append(n)
    return result

def selection_nodes(state, validated=False):
    nodes = all_nodes(state)
    if not nodes:
        raise AtlasError('Сначала обновите хотя бы одну подписку')
    nodes = filter_nodes(nodes, state['settings'], validated=validated)
    if not nodes:
        raise AtlasError('Фильтры исключили все серверы. Ослабьте фильтр; обход через другую страну не включается.')
    limit = state['settings']['max_active_nodes']
    if limit and len(nodes) > limit:
        raise AtlasError('После фильтров осталось %d профилей, лимит активного пула — %d. Ужесточите фильтры или увеличьте лимит.' % (len(nodes), limit))
    selected = state['settings'].get('selected', 'auto')
    if selected != 'auto' and not any(n['key'] == selected for n in nodes):
        raise AtlasError('Выбранный сервер отсутствует или исключён фильтром. Выберите другой или Авто.')
    return nodes

def all_nodes(state):
    nodes = []
    for sub in state['subscriptions']:
        if sub.get('enabled', True):
            for n in sub.get('nodes', []):
                item = copy.deepcopy(n)
                item['key'] = sub['id'] + n['id']
                item['subscription'] = sub['name']
                nodes.append(item)
    return nodes

def custom_auto_policy(settings):
    return settings['auto_strategy'] != 'fastest' or bool(settings['preferred_countries']) or bool(settings['min_ping_ms'] or settings['max_ping_ms'])


def real_ip_resolution_active(config):
    return any(r.get('action') == 'resolve' and (r.get('server') == 'secure' or r.get('server','').startswith('vpn_dns_')) for r in config.get('route', {}).get('rules', []))


def interface_inbound(name):
    return 'ingress_' + hashlib.sha256(name.encode()).hexdigest()[:12]


def section_match(section, match, dns=False):
    """Exceptions only remove a match from this section; later rules still apply."""
    guards=[]
    if section.get('source_interfaces'):
        guards.append({'inbound':[interface_inbound(x) for x in section['source_interfaces']]})
    for key,field in [('exclude_domains','domain_suffix'),('exclude_cidrs','ip_cidr'),('exclude_source_ips','source_ip_cidr')]:
        if section.get(key) and not (dns and key=='exclude_cidrs'):
            guards.append({field:section[key],'invert':True})
    return {'type':'logical','mode':'and','rules':[match]+guards} if guards else match


def make_config(state, tun=True, mixed_port=2080, probe_node=None, api_secret=None):
    settings = validate_settings(state['settings'])
    settings['sections'] = [x for x in settings['sections'] if x['enabled']]
    if not probe_node and not all_nodes(state) and (any(x['outbound_config'] or x['policy'] != 'proxy' for x in settings['sections']) or any(x['enabled'] for x in settings['remote_lists'])):
        # No implicit direct fallback for the main proxy when only expert sections exist.
        nodes = [{'id': 'local-only-block', 'outbound': {'type': 'block'}}]
    else:
        nodes = [probe_node] if probe_node else selection_nodes(dict(state, settings=settings), validated=True)
    nodes = list({n.get('key', n['id']): n for n in nodes}.values())
    outs = []
    for n in nodes:
        out = copy.deepcopy(n['outbound'])
        out['tag'] = n.get('key', n['id'])
        if settings['udp_over_tcp'] and out.get('type') in ('shadowsocks','socks'):
            out['udp_over_tcp'] = {'enabled': True, 'version': settings['udp_over_tcp_version']}
        outs.append(out)
    tags = [o['tag'] for o in outs]
    selected = settings['selected'] if not probe_node else tags[0]
    if selected != 'auto' and selected not in tags:
        raise AtlasError('Выбранный сервер отсутствует. Выберите другой или Авто.')
    custom = custom_auto_policy(settings) and not probe_node
    if custom and selected == 'auto':
        selected = 'policy-block'
    outs = [{'type': 'selector', 'tag': 'proxy', 'outbounds': ['auto', 'policy-block'] + tags, 'default': selected,
             'interrupt_exist_connections': settings['interrupt_connections'] or custom},
            {'type': 'urltest', 'tag': 'auto', 'outbounds': tags, 'url': settings['urltest_url'],
             'interval': '%ds' % settings['auto_interval_seconds'], 'tolerance': settings['auto_tolerance_ms'],
             'idle_timeout': '30m', 'interrupt_exist_connections': settings['interrupt_connections']},
            {'type': 'direct', 'tag': 'direct'}, {'type': 'block', 'tag': 'policy-block'}] + outs
    pool_tags = {}
    enabled_subs = {s['id']: s for s in state.get('subscriptions', []) if s.get('enabled', True)}
    if settings['fetch_lists_via_proxy'] and settings['fetch_lists_subscription'] and settings['fetch_lists_subscription'] not in enabled_subs:
        raise AtlasError('Подписка для загрузки списков отсутствует или выключена')
    needed_pools = {x['pool'] for x in settings['sections'] if x['policy'] == 'proxy' and x['pool']}
    if settings['fetch_lists_via_proxy'] and settings['fetch_lists_subscription']:
        needed_pools.add(settings['fetch_lists_subscription'])
    for sub_id in sorted(needed_pools):
        sub = enabled_subs.get(sub_id)
        if not sub:
            raise AtlasError('Секция ссылается на отсутствующую или выключенную подписку')
        members = [n for n in nodes if n.get('key','').startswith(sub_id)]
        if not members:
            raise AtlasError('Фильтры исключили все профили пула в одной из секций')
        pool_tag, auto_tag = 'pool_' + sub_id, 'auto_' + sub_id
        member_tags = [n['key'] for n in members]
        outs.extend([{'type': 'selector', 'tag': pool_tag, 'outbounds': [auto_tag, 'policy-block'] + member_tags,
                      'default': 'policy-block' if custom else auto_tag,
                      'interrupt_exist_connections': settings['interrupt_connections'] or custom},
                     {'type': 'urltest', 'tag': auto_tag, 'outbounds': member_tags,
                      'url': settings['urltest_url'], 'interval': '%ds' % settings['auto_interval_seconds'],
                      'tolerance': settings['auto_tolerance_ms'], 'idle_timeout': '30m',
                      'interrupt_exist_connections': settings['interrupt_connections']}])
        pool_tags[sub_id] = pool_tag
    interface_tags = {}
    for section in settings['sections']:
        if section['policy'] == 'interface':
            iface = section['interface']
            tag = 'if_' + hashlib.sha256(iface.encode()).hexdigest()[:12]
            interface_tags[iface] = tag
    for rule_list in settings['remote_lists']:
        if rule_list['enabled'] and rule_list['policy'] == 'interface':
            iface = rule_list['interface']
            tag = 'if_' + hashlib.sha256(iface.encode()).hexdigest()[:12]
            interface_tags[iface] = tag
    for iface, tag in interface_tags.items():
        outs.append({'type': 'direct', 'tag': tag, 'bind_interface': iface})
    section_targets = {}
    for section in settings['sections']:
        if section['outbound_config']:
            extra, target = namespace_graph(section['outbound_config'], 'section_' + section['id'],allow_external=True)
            root = next(x for x in extra if x['tag'] == target)
            if root['type'] == 'urltest':
                control = 'section_' + section['id'] + '_control'
                used={x['tag'] for x in extra}
                suffix=1
                while control in used:
                    control='section_'+section['id']+'_control_%d'%suffix
                    suffix+=1
                extra.append({'type':'selector','tag':control,'outbounds':list(dict.fromkeys([target]+root['outbounds']+root.get('fallbacks',[]))),'default':target})
                target = control
            outs.extend(extra)
        else:
            target = (pool_tags[section['pool']] if section['pool'] else 'proxy') if section['policy'] == 'proxy' else interface_tags[section['interface']] if section['policy'] == 'interface' else 'direct'
            if section['policy']=='proxy' and (section['urltest_fallbacks'] or section['urltest_download_check']!='default' or any(section[k] is not None if k!='urltest_url' else bool(section[k]) for k in ('auto_interval_seconds','auto_tolerance_ms','urltest_url')) or any(section[k] is not None for k in ('udp_over_tcp','udp_over_tcp_version'))):
                members=[tag for tag in tags if not section['pool'] or tag.startswith(section['pool'])]
                if any(section[k] is not None for k in ('udp_over_tcp','udp_over_tcp_version')):
                    private=[]
                    for tag in members:
                        outbound=copy.deepcopy(next(x for x in outs if x['tag']==tag))
                        outbound['tag']='section_'+section['id']+'_'+tag
                        if outbound['type'] in ('socks','shadowsocks'):
                            outbound['udp_over_tcp']={'enabled':settings['udp_over_tcp'] if section['udp_over_tcp'] is None else section['udp_over_tcp'],'version':settings['udp_over_tcp_version'] if section['udp_over_tcp_version'] is None else section['udp_over_tcp_version']}
                        private.append(outbound)
                    outs.extend(private)
                    members=[x['tag'] for x in private]
                target='section_'+section['id']+'_control'
                automatic='section_'+section['id']+'_auto'
                outs.extend([
                    {'type':'selector','tag':target,'outbounds':[automatic,'policy-block']+members,'default':'policy-block' if custom else automatic,'interrupt_exist_connections':settings['interrupt_connections'] or custom},
                    {'type':'urltest','tag':automatic,'outbounds':members,'url':section['urltest_url'] or settings['urltest_url'],'interval':'%ds'%(section['auto_interval_seconds'] if section['auto_interval_seconds'] is not None else settings['auto_interval_seconds']),'tolerance':section['auto_tolerance_ms'] if section['auto_tolerance_ms'] is not None else settings['auto_tolerance_ms'],'idle_timeout':'30m','interrupt_exist_connections':settings['interrupt_connections']}])
        section_targets[section['id']] = target
    features = None
    if not probe_node:
        advanced=settings['urltest_fallbacks'] or settings['urltest_download_check']!='default' or any(s['enabled'] and (s['urltest_fallbacks'] or s['urltest_download_check']!='default') for s in settings['sections'])
        if advanced:
            features=engine_features.capabilities()
            try:
                engine_features.extend_group(next(x for x in outs if x['tag']=='auto'),settings,features,custom=custom)
                for sub_id in pool_tags:
                    options=dict(settings,urltest_fallbacks=[key for key in settings['urltest_fallbacks'] if key.startswith(sub_id)])
                    engine_features.extend_group(next(x for x in outs if x['tag']=='auto_'+sub_id),options,features,custom=custom)
                for section in settings['sections']:
                    tag='section_'+section['id']+'_auto'
                    group=next((x for x in outs if x['tag']==tag and not section['outbound_config']),None)
                    if group:
                        prefix='section_'+section['id']+'_' if section['udp_over_tcp'] is not None or section['udp_over_tcp_version'] is not None else ''
                        engine_features.extend_group(group,section,features,prefix,custom)
            except ValueError as exc:raise AtlasError(str(exc)) from exc
    if custom:
        # Harmless, unused block tags carry trusted group roles through the
        # native JSON schema. Expert groups may deliberately use the same
        # control/auto naming pattern and must not receive the managed policy.
        managed = {'proxy'} | set(pool_tags.values())
        for section in settings['sections']:
            tag = 'section_' + section['id'] + '_control'
            if not section['outbound_config'] and any(x['tag'] == tag for x in outs):
                managed.add(tag)
        outs.extend({'type':'block','tag':'atlas_guard_'+tag} for tag in sorted(managed))
        # Guarded selection sends traffic directly through a measured member.
        # Its URLTest must keep measuring even without traffic through the group.
        # Only opt in on engines advertising this JSON extension.
        if 'urltest.background' in (features if features is not None else engine_features.capabilities()):
            from launch_cache import managed_auto
            automatic = {managed_auto(tag) for tag in managed
                         if tag not in settings['section_choices'] and (tag!='proxy' or settings['selected']=='auto')}
            for outbound in outs:
                if outbound['tag'] in automatic and outbound['type']=='urltest':
                    outbound['background']=True
    try:
        validate_references(outs)
    except ValueError as exc:
        raise AtlasError(str(exc)) from exc
    for outbound in outs:
        choice = settings['section_choices'].get(outbound['tag'])
        if choice and outbound['type'] == 'selector' and choice in outbound['outbounds']:
            outbound['default'] = choice
    inbound = {'type': 'tun', 'tag': 'tun', 'interface_name': 'atlas0',
               'address': ['172.31.255.1/30', 'fdfe:dcba:9876::1/126'], 'mtu': 1400,
               'auto_route': True, 'auto_redirect': True, 'strict_route': True, 'stack': 'system'}
    if not tun:
        inbound = {'type': 'mixed', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': mixed_port}
    rules = [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'}]
    if settings['browser_diagnostics']:
        rules.extend([
            {'domain': ['fakeip.podkop.fyi'], 'action': 'route-options', 'override_port': 8443},
            {'domain': ['fakeip.podkop.fyi'], 'action': 'resolve', 'server': 'bootstrap'},
            {'domain': ['fakeip.podkop.fyi'], 'action': 'route', 'outbound': 'direct'},
            {'domain': ['ip.podkop.fyi'], 'action': 'route', 'outbound': 'proxy'}])
    if tun and settings['fetch_lists_via_proxy']:
        fetch_outbound = section_targets[settings['fetch_lists_section']] if settings['fetch_lists_section'] else ('pool_' + settings['fetch_lists_subscription']) if settings['fetch_lists_subscription'] else 'proxy'
        rules.append({'inbound': ['list-fetch'], 'action': 'route', 'outbound': fetch_outbound})
    section_inbounds = []
    section_rule_resolution = {}
    def register_section_rule(rule, section):
        if section.get('resolve_real_ip') is not None:
            section_rule_resolution[id(rule)] = section['resolve_real_ip']
        return rule
    if tun:
        for section in settings['sections']:
            listener = section['mixed_proxy']
            if listener['enabled']:
                tag = 'mixed_' + section['id']
                section_inbounds.append({'type': 'mixed', 'tag': tag, 'listen': listener['listen'], 'listen_port': listener['port'],
                                         'users': [{'username': listener['username'], 'password': listener['password']}]})
                rules.append(register_section_rule({'inbound': [tag], 'action': 'route', 'outbound': section_targets[section['id']]},section))
    dns_rules = []
    priority_dns_exclusions = []
    priority_exclusions = []
    vpn_dns_servers = []
    section_resolvers = {}
    section_route_dns = {}
    for section in settings['sections']:
        if section['resolver']:
            tag = 'vpn_dns_' + hashlib.sha256((section['name'] + section['policy'] + section['interface'] + section['pool']).encode()).hexdigest()[:12]
            if section['policy'] == 'interface':
                detour = interface_tags[section['interface']]
            elif section['policy'] == 'proxy':
                detour = section_targets[section['id']]
            else:
                detour = 'direct'
            vpn_dns_servers.append(dns_server_from_uri(section['resolver'], tag, detour))
            section_resolvers[section['id']] = tag
            section_route_dns[(section_targets[section['id']], json.dumps({'inbound': ['mixed_' + section['id']]}, sort_keys=True))] = tag
            dns_match={'domain_suffix':section['domains']}
            if section['source_ips']:
                dns_match['source_ip_cidr']=section['source_ips']
            dns_rules.append(dict(section_match(section,dns_match,dns=True),action='route',server=tag))
    rules.append({'ip_is_private': True, 'action': 'route', 'outbound': 'direct'})
    if settings['routing_excluded_ips']:
        rules.append({'source_ip_cidr': settings['routing_excluded_ips'], 'action': 'route', 'outbound': 'direct'})
    if settings['disable_quic']:
        rules.append({'network': 'udp', 'port': 443, 'action': 'reject'})
    if settings['exclude_ntp']:
        rules.append({'network': 'udp', 'port': 123, 'action': 'route', 'outbound': 'direct'})
    for key, match, outbound in [('bypass_domains', 'domain_suffix', 'direct'), ('bypass_cidrs', 'ip_cidr', 'direct')]:
        if settings[key]:
            rules.append({match: settings[key], 'action': 'route', 'outbound': outbound})
    if settings['block_known_doh']:
        rules.append({'domain_suffix': KNOWN_DOH_DOMAINS, 'action': 'reject'})
    exclusion_insert_at = len(rules)
    for section in settings['sections']:
        match = {}
        if section['domains']:
            match['domain_suffix'] = section['domains']
        if section['cidrs']:
            match['ip_cidr'] = section['cidrs']
        if section['source_ips']:
            match['source_ip_cidr'] = section['source_ips']
        if section['networks']:
            match['network'] = section['networks']
        if section['ports']:
            exact = [int(value) for value in section['ports'] if '-' not in value]
            ranges = [value.replace('-', ':') for value in section['ports'] if '-' in value]
            if exact and ranges:
                alternatives = {'type': 'logical', 'mode': 'or', 'rules': [{'port': exact}, {'port_range': ranges}]}
                match = {'type': 'logical', 'mode': 'and', 'rules': [match, alternatives]} if match else alternatives
            elif exact:
                match['port'] = exact
            else:
                match['port_range'] = ranges
        if not match and not section['source_interfaces']:
            continue
        match=section_match(section,match)
        if section['policy'] == 'block':
            rules.append(dict(match, action='reject'))
        elif section['policy'] == 'exclude':
            priority_exclusions.append(dict(match, action='route', outbound='direct'))
        else:
            target = section_targets[section['id']]
            if section['id'] in section_resolvers:
                section_route_dns[(target, json.dumps(match, sort_keys=True))] = section_resolvers[section['id']]
            rules.append(register_section_rule(dict(match, action='route', outbound=target),section))
    rule_sets = []
    for rule_list in settings['remote_lists']:
        if not rule_list['enabled']:
            continue
        assigned=next((x for x in settings['sections'] if x['id']==rule_list['section']),None)
        if rule_list['section'] in section_resolvers:
            match = {'rule_set':['rules_' + rule_list['id']]} if rule_set_format(rule_list) else {'domain_suffix':rule_list['domains']} if rule_list['domains'] else {}
            if match:
                if assigned:match=section_match(assigned,match,dns=True)
                dns_rules.append(dict(match,action='route',server=section_resolvers[rule_list['section']]))
                route_match={'rule_set':['rules_' + rule_list['id']]} if rule_set_format(rule_list) else {'domain_suffix':rule_list['domains']}
                if assigned:route_match=section_match(assigned,route_match)
                section_route_dns[(section_targets[rule_list['section']],json.dumps(route_match,sort_keys=True))] = section_resolvers[rule_list['section']]
        if rule_set_format(rule_list):
            tag = 'rules_' + rule_list['id']
            definition = {'type':'local','format':rule_set_format(rule_list),'tag':tag}
            if rule_list.get('source_rules') is not None:
                definition={'type':'inline','tag':tag,'rules':copy.deepcopy(rule_list['source_rules']['rules'])}
            elif rule_list['format'] == 'srs' or rule_list.get('source_cached'):
                definition['path'] = '/etc/atlas/rules/%s.%s' % (rule_list['id'], 'srs' if rule_list['format']=='srs' else 'json')
            else:
                # Upgrade legacy JSON caches without changing their previous route behavior.
                definition = {'type':'inline','tag':tag,'rules':[]}
                for key,matcher in (('domains','domain_suffix'),('cidrs','ip_cidr')):
                    if rule_list[key]:definition['rules'].append({matcher:rule_list[key]})
            rule_sets.append(definition)
            action = 'reject' if rule_list['policy'] in ('block','dnsblock') else 'route'
            rule = {'rule_set':[tag], 'action':action}
            if assigned:rule=dict(section_match(assigned,{'rule_set':[tag]}),action=action)
            if rule_list['policy'] in ('proxy','direct','exclude','interface'):
                rule['outbound'] = ('direct' if rule_list['policy'] == 'exclude' else
                                    interface_tags[rule_list['interface']] if rule_list['policy'] == 'interface' else
                                    section_targets[rule_list['section']] if rule_list['section'] else rule_list['policy'])
            if rule_list['policy'] == 'exclude':
                priority_exclusions.append(rule)
            else:
                if assigned:register_section_rule(rule,assigned)
                rules.append(rule)
            continue
        if rule_list['policy'] == 'dnsblock':
            if rule_list['domains']:
                dns_rules.append({'domain_suffix': rule_list['domains'], 'action': 'reject'})
            continue
        action = 'reject' if rule_list['policy'] == 'block' else 'route'
        outbound = ('direct' if rule_list['policy'] == 'exclude' else
                    interface_tags[rule_list['interface']] if rule_list['policy'] == 'interface' else
                    section_targets[rule_list['section']] if rule_list['section'] else rule_list['policy'] if rule_list['policy'] in ('proxy','direct') else '')
        for key, matcher in (('domains','domain_suffix'),('cidrs','ip_cidr')):
            if rule_list[key]:
                rule = {matcher:rule_list[key], 'action':action}
                if assigned:rule=dict(section_match(assigned,{matcher:rule_list[key]}),action=action)
                if outbound:
                    rule['outbound'] = outbound
                if rule_list['policy'] == 'exclude':
                    priority_exclusions.append(rule)
                else:
                    if assigned:register_section_rule(rule,assigned)
                    rules.append(rule)
    rules[exclusion_insert_at:exclusion_insert_at] = priority_exclusions
    if settings['routed_source_ips']:
        rules.append({'source_ip_cidr': settings['routed_source_ips'], 'action': 'route', 'outbound': 'proxy'})
    for key, match, outbound in [('domains', 'domain_suffix', 'proxy'), ('cidrs', 'ip_cidr', 'proxy')]:
        if settings[key]:
            rules.append({match: settings[key], 'action': 'route', 'outbound': outbound})
    if not probe_node and (settings['resolve_real_ip'] or any(x['resolve_real_ip'] is True for x in settings['sections'])):
        resolved_rules = []
        proxy_targets = {'proxy'} | set(pool_tags.values()) | {section_targets[x['id']] for x in settings['sections'] if x['policy'] in ('proxy','interface')}
        for rule in rules:
            if rule.get('action') == 'route' and rule.get('outbound') in proxy_targets and section_rule_resolution.get(id(rule),settings['resolve_real_ip']):
                match = {k: copy.deepcopy(v) for k, v in rule.items() if k not in ('action', 'outbound')}
                resolved_rules.append(dict(match, action='resolve', server=section_route_dns.get((rule['outbound'], json.dumps(match, sort_keys=True)), 'secure'), strategy='prefer_ipv4'))
            resolved_rules.append(rule)
        if settings['mode'] == 'global' and settings['resolve_real_ip']:
            resolved_rules.append({'action': 'resolve', 'server': 'secure', 'strategy': 'prefer_ipv4'})
        rules = resolved_rules
    bootstrap = {'type': settings['bootstrap_dns_type'], 'tag': 'bootstrap', 'server': settings['bootstrap_dns_server'],
                 'tls': {'enabled': True, 'server_name': settings['bootstrap_dns_sni']}}
    if settings['bootstrap_dns_type'] == 'udp':
        bootstrap.pop('tls')
    if settings['bootstrap_dns_type'] == 'https':
        bootstrap['path'] = settings['bootstrap_dns_path']
    dns_servers = [bootstrap] + vpn_dns_servers
    default_dns_outbound = (next((section_targets[x['id']] for x in settings['sections'] if x['outbound_config'] or x['policy'] == 'interface'),'proxy')
                            if nodes and nodes[0]['id'] == 'local-only-block' else 'proxy')
    if nodes and nodes[0]['id']=='local-only-block' and settings['mode']=='rules' and not any(settings[k] for k in ('domains','cidrs','routed_source_ips','fetch_lists_via_proxy')) and not any(x['policy']=='proxy' for x in settings['sections']) and not any(x['enabled'] and x['policy']=='proxy' for x in settings['remote_lists']):
        # Explicitly direct/block-only operation still needs a usable DNS resolver.
        # A missing proxy remains blocked; a proxy-requesting configuration never gets this path.
        default_dns_outbound='direct'
    if settings['dns_filter'] == 'adguard':
        secure_dns = {'type': 'https', 'tag': 'secure', 'server': '94.140.14.14',
                      'path': '/dns-query', 'tls': {'enabled': True, 'server_name': 'dns.adguard-dns.com'},
                      'detour': default_dns_outbound}
    elif settings['dns_filter'] == 'custom':
        secure_dns = {'type': settings['custom_dns_type'], 'tag': 'secure', 'server': settings['custom_dns_server'], 'detour': default_dns_outbound}
        if settings['custom_dns_type'] == 'https':
            secure_dns['path'] = settings['custom_dns_path']
        if settings['custom_dns_type'] in ('https','tls'):
            secure_dns['tls'] = {'enabled': True, 'server_name': settings['custom_dns_sni']}
    else:
        secure_dns = {'type': 'https', 'tag': 'secure', 'server': '1.1.1.1',
                      'path': '/dns-query', 'tls': {'enabled': True, 'server_name': 'cloudflare-dns.com'},
                      'detour': default_dns_outbound}
    dns_servers.append(secure_dns)
    empty_direct = {x['tag'] for x in outs if x.get('type') == 'direct' and set(x) <= {'type','tag'}}
    for server in dns_servers:
        if server.get('detour') in empty_direct:
            server.pop('detour')
    if settings['blocked_domains']:
        dns_rules.append({'domain_suffix': settings['blocked_domains'], 'action': 'reject'})
    if settings['fakeip']:
        dns_servers.append({'type': 'fakeip', 'tag': 'fakeip',
                            'inet4_range': '198.18.0.0/15', 'inet6_range': 'fc00::/18'})
        def domain_dns_rule(match, proxy):
            return dict(match, action='route', server='fakeip' if proxy else 'secure',
                        **({'rewrite_ttl': settings['fakeip_ttl_seconds']} if proxy else {}))
        if settings['bypass_domains']:
            priority_dns_exclusions.append(domain_dns_rule({'domain_suffix': settings['bypass_domains']}, False))
        ordered_sections = sorted(settings['sections'], key=lambda x: x['policy'] != 'exclude')
        ordered_lists = sorted(settings['remote_lists'], key=lambda x: x['policy'] != 'exclude')
        for section in ordered_sections:
            if section['domains'] and not section['resolver'] and not section['cidrs'] and not section['ports'] and not section['networks']:
                match = {'domain_suffix': section['domains']}
                if section['source_ips']:
                    match['source_ip_cidr'] = section['source_ips']
                match=section_match(section,match,dns=True)
                target = priority_dns_exclusions if section['policy'] == 'exclude' else dns_rules
                target.append(dict(match, action='reject') if section['policy'] == 'block' else
                              domain_dns_rule(match, section['policy'] == 'proxy'))
        for item in ordered_lists:
            if not item['enabled']:
                continue
            match = {'rule_set': ['rules_' + item['id']]} if rule_set_format(item) else ({'domain_suffix': item['domains']} if item['domains'] else {})
            if not match:
                continue
            assigned=next((x for x in settings['sections'] if x['id']==item['section']),None)
            if assigned:match=section_match(assigned,match,dns=True)
            target = priority_dns_exclusions if item['policy'] == 'exclude' else dns_rules
            target.append(dict(match, action='reject') if item['policy'] in ('block', 'dnsblock') else
                          domain_dns_rule(match, item['policy'] == 'proxy'))
        if settings['mode'] == 'global':
            dns_rules.append(domain_dns_rule({}, True))
        elif settings['domains']:
            dns_rules.append(domain_dns_rule({'domain_suffix': settings['domains']}, True))
    # A deny rule must win over a custom DNS resolver or FakeIP rewrite.
    dns_rules = [rule for rule in dns_rules if rule.get('action') == 'reject'] + priority_dns_exclusions + [rule for rule in dns_rules if rule.get('action') != 'reject']
    if settings['browser_diagnostics']:
        dns_rules[0:0] = [
            {'domain': ['fakeip.podkop.fyi', 'ip.podkop.fyi'], 'query_type': ['HTTPS'], 'action': 'reject'},
            {'domain': ['fakeip.podkop.fyi', 'ip.podkop.fyi'], 'action': 'route', 'server': 'fakeip', 'rewrite_ttl': settings['fakeip_ttl_seconds']}]
    inbounds = [inbound] + section_inbounds
    if tun:
        interfaces = sorted({i for s in settings['sections'] for i in s['source_interfaces']})
        if interfaces:
            inbound['exclude_interface'] = interfaces
        for index, interface in enumerate(interfaces, 1):
            scoped = copy.deepcopy(inbound)
            scoped.pop('exclude_interface', None)
            scoped.update(tag=interface_inbound(interface), interface_name='atli%d' % index,
                          include_interface=[interface], auto_redirect=False,
                          address=['10.254.%d.%d/30' % ((index // 64) % 256, (index % 64) * 4 + 1),
                                   'fdfe:dcba:9877:%x::1/126' % index],
                          iproute2_table_index=2100+index, iproute2_rule_index=10000+index*20,
                          auto_redirect_input_mark=0x3000+index*4,
                          auto_redirect_output_mark=0x3001+index*4)
            inbounds.append(scoped)
    if tun and settings['dhcp_dns_enabled']:
        inbounds.append({'type': 'direct', 'tag': 'dhcp-dns', 'listen': '127.0.0.42', 'listen_port': 53})
        rules.insert(0, {'inbound': ['dhcp-dns'], 'action': 'hijack-dns'})
    if tun and settings['fetch_lists_via_proxy']:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            fetch_port = listener.getsockname()[1]
        inbounds.append({'type':'mixed','tag':'list-fetch','listen':'127.0.0.1','listen_port':fetch_port,
                         'users':[{'username':'atlas-fetch','password':secrets.token_urlsafe(24)}]})
    if tun and settings['mixed_proxy_enabled']:
        inbounds.append({'type':'mixed','tag':'lan-mixed','listen':settings['mixed_proxy_listen'],
                         'listen_port':settings['mixed_proxy_port'],
                         'users':[{'username':settings['mixed_proxy_username'],'password':settings['mixed_proxy_password']}]})
    config = {'log': {'level': settings['log_level'], 'timestamp': True},
            'dns': {'servers': dns_servers, 'rules': dns_rules,
                    'final': 'secure', 'strategy': 'prefer_ipv4', 'reverse_mapping': True},
            'inbounds': inbounds, 'outbounds': outs,
            'route': {'auto_detect_interface': not bool(settings['default_interface']), 'default_domain_resolver': 'bootstrap',
                      'rule_set': rule_sets,
                      'rules': rules if not probe_node else [],
                      'final': 'proxy' if probe_node or settings['mode'] == 'global' else 'direct'}}
    if settings['default_interface']:
        config['route']['default_interface'] = settings['default_interface']
    cache_path = {'flash': '/etc/atlas/cache.db', 'ram': '/tmp/atlas/cache.db'}.get(settings['cache_storage'], settings['cache_custom_path'])
    config['experimental'] = {'cache_file': {'enabled': True, 'path': cache_path, 'store_fakeip': True,
                                            'cache_id': 'atlas-policy' if custom else 'atlas-native'}}
    if probe_node:
        # A diagnostic engine must never lock or modify the service's cache.
        config['experimental']['cache_file']['enabled'] = False
    if api_secret is not None:
        if not isinstance(api_secret, str) or not re.fullmatch('[a-f0-9]{64}', api_secret):
            raise AtlasError('Некорректный ключ локального API')
        address = settings['yacd_listen'] if settings['yacd_enabled'] else '127.0.0.1'
        config['experimental']['clash_api'] = {'external_controller': address + ':19090', 'secret': api_secret}
        if settings['yacd_enabled']:
            config['experimental']['clash_api']['external_ui'] = '/www/luci-static/resources/atlas/yacd'
            config['experimental']['clash_api']['external_ui_download_url'] = 'https://github.com/haishanh/yacd/archive/gh-pages.zip'
            config['experimental']['clash_api']['external_ui_download_detour'] = 'proxy'

    return config

def privacy_checks(settings, config, running=False):
    """Report observable Atlas safeguards; this is not a third-party leak test."""
    settings = validate_settings(settings)
    dns = config.get('dns', {}) if isinstance(config, dict) else {}
    servers = dns.get('servers', [])
    rules = dns.get('rules', [])
    inbound = next((item for item in config.get('inbounds', []) if item.get('type') == 'tun'), {})
    route = config.get('route', {})
    route_rules = route.get('rules', [])
    secure = next((item for item in servers if item.get('tag') == 'secure'), {})
    resolve_requested=settings['resolve_real_ip'] or any(x['enabled'] and x.get('resolve_real_ip') is True for x in settings['sections'])
    checks = [
        {'id': 'running', 'ok': bool(running), 'label': 'Маршрутизатор Atlas запущен' if running else 'Atlas сейчас остановлен'},
        {'id': 'dns_hijack', 'ok': any(item.get('action') == 'hijack-dns' for item in route_rules), 'label': 'DNS-порт 53 перехватывается sing-box'},
        {'id': 'dnsmasq_ingress', 'ok': not settings['dhcp_dns_enabled'] or
         (any(item.get('type') == 'direct' and item.get('tag') == 'dhcp-dns' and item.get('listen') == '127.0.0.42' for item in config.get('inbounds', [])) and
          any(item.get('action') == 'hijack-dns' and 'dhcp-dns' in item.get('inbound', []) for item in route_rules)),
         'label': 'Конфигурация принимает DNS dnsmasq через Atlas' if settings['dhcp_dns_enabled'] else 'Перенаправление DNS dnsmasq не включено'},
        {'id': 'encrypted_dns', 'ok': secure.get('type') in ('https','tls') and secure.get('detour') == 'proxy' and bool(secure.get('tls', {}).get('enabled')), 'label': 'Основной DNS шифруется HTTPS/TLS через прокси'},
        {'id': 'bootstrap_dns', 'ok': any(item.get('tag') == 'bootstrap' and item.get('type') in ('https','tls') and item.get('tls', {}).get('enabled') for item in servers), 'label': 'Bootstrap запросы для адресов прокси тоже используют TLS'},
        {'id': 'no_ecs', 'ok': 'client_subnet' not in dns and all('client_subnet' not in item for item in rules), 'label': 'IP-подсеть клиента не добавляется в DNS-запросы'},
        {'id': 'strict_route', 'ok': bool(inbound.get('strict_route') and inbound.get('auto_redirect')), 'label': 'Включены строгая маршрутизация и перехват TUN'},
        {'id': 'adblock', 'ok': settings['dns_filter'] == 'adguard' or bool(settings['blocked_domains']), 'label': 'DNS-блокировка рекламы и трекеров включена' if settings['dns_filter'] == 'adguard' or settings['blocked_domains'] else 'DNS-блокировка рекламы выключена'},
        {'id': 'encrypted_dns_bypass', 'ok': settings['block_known_doh'], 'label': 'Известные публичные DoH хосты блокируются для снижения обхода DNS-фильтров' if settings['block_known_doh'] else 'Клиентские приложения могут использовать собственный DoH'},
        {'id': 'fakeip', 'ok': any(item.get('type') == 'fakeip' for item in servers) and any(item.get('server') == 'fakeip' and item.get('action') == 'route' for item in rules), 'label': 'FakeIP настроен для маршрута через прокси' if any(item.get('type') == 'fakeip' for item in servers) and any(item.get('server') == 'fakeip' and item.get('action') == 'route' for item in rules) else 'FakeIP выключен или нет доменов через прокси'},
        {'id': 'fakeip_persistence', 'ok': bool(config.get('experimental', {}).get('cache_file', {}).get('enabled') and config.get('experimental', {}).get('cache_file', {}).get('store_fakeip')), 'label': 'Кеш FakeIP сохраняется между перезапусками sing-box'},
        {'id': 'fakeip_ttl', 'ok': not settings['fakeip'] or any(x.get('server') == 'fakeip' and x.get('rewrite_ttl') == settings['fakeip_ttl_seconds'] for x in rules), 'label': 'TTL FakeIP ограничивает время хранения поддельных адресов клиентами'},
        {'id': 'real_ip_resolution', 'ok': not resolve_requested or real_ip_resolution_active(config), 'label': 'Маршрутизируемые домены разрешаются через выбранный защищённый DNS' if resolve_requested else 'Повторное разрешение реальных IP выключено'},
        {'id': 'coverage', 'ok': settings['mode'] == 'global', 'label': 'Весь внешний трафик настроен через прокси' if settings['mode'] == 'global' else 'Часть трафика идёт напрямую по режиму «По правилам»'},
    ]
    return {'checks': checks, 'notice': 'Аудит конфигурации — не проверка с устройства в интернете. Bootstrap DoH идёт напрямую к Cloudflare и раскрывает этому DNS-провайдеру запросы для адресов серверов; клиентский DoH, ECH, VPN-приложение или остановка роутера могут обходить правила.'}
