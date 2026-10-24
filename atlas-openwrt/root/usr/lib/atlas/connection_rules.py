"""Explicit monitor rules: separate ownership, bounded input, no DNS guessing."""
from functools import lru_cache
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets


def fail(message):
    from core import AtlasError
    raise AtlasError(message)


def domain(value):
    from core import host
    if not isinstance(value, str):
        fail('Домен должен быть строкой')
    value = host(value.strip().removeprefix('*.').rstrip('.')).lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if '.' not in value or ':' in value:
            fail('Укажите полное доменное имя')
        exact, wildcard, exceptions = suffixes()
        if value in exact or ('.'.join(value.split('.')[1:]) in wildcard and value not in exceptions):
            fail('Нельзя направить в секцию целую доменную зону или общий хостинг')
        return value
    fail('IP нужно добавить в поле адресов')


def public_ip(value):
    if not isinstance(value, str):
        fail('Укажите IP-адрес')
    try:
        address = ipaddress.ip_interface(value.strip())
        if address.network.prefixlen != address.max_prefixlen or not address.ip.is_global or address.ip.is_multicast:
            raise ValueError()
    except ValueError:
        fail('Из монитора можно добавить только отдельный публичный IP; локальные и FakeIP-адреса не подходят')
    return str(address)


@lru_cache(maxsize=1)
def suffixes():
    exact, wildcard, exceptions = set(), set(), set()
    try:
        body = Path(__file__).with_name('public_suffix_list.dat').read_text(encoding='utf-8')
    except OSError:
        return exact, wildcard, exceptions
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        target = exceptions if line.startswith('!') else wildcard if line.startswith('*.') else exact
        raw = line[1:] if line.startswith('!') else line[2:] if line.startswith('*.') else line
        try:
            target.add(raw.encode('idna').decode('ascii').lower())
        except UnicodeError:
            continue
    return exact, wildcard, exceptions


def site_domain(value):
    """Registrable domain, including PRIVATE suffixes (tenant isolation)."""
    value = domain(value)
    labels = value.split('.')
    exact, wildcard, exceptions = suffixes()
    length = 0
    for index in range(len(labels)):
        suffix = '.'.join(labels[index:])
        if suffix in exceptions:
            length = len(labels) - index - 1
            break
        if suffix in exact:
            length = max(length, len(labels) - index)
        if index and suffix in wildcard:
            length = max(length, len(labels) - index + 1)
    # An unavailable/unknown suffix is never broadened by guessing the last two labels.
    return '.'.join(labels[-length-1:]) if length and len(labels) > length else value


def preview(target):
    if not isinstance(target, dict) or set(target) - {'host', 'destination', 'related'}:
        fail('Некорректное соединение')
    result = {'domain': '', 'site': '', 'cidr': '', 'related': []}
    try:
        result['domain'] = domain(target.get('host', ''))
        result['site'] = site_domain(result['domain'])
    except (ValueError, TypeError):
        pass
    if not result['domain']:
        result['site'] = ''
    try:
        result['cidr'] = public_ip(target.get('destination') or target.get('host', ''))
    except Exception:
        pass
    related = target.get('related', [])
    if not isinstance(related, list) or len(related) > 50:
        fail('Слишком много связанных адресов')
    seen = {result['site']}
    for value in related:
        try:
            item = site_domain(value)
        except Exception:
            continue
        if item not in seen:
            seen.add(item)
            result['related'].append(item)
    if not result['domain'] and not result['cidr']:
        fail('В соединении нет домена или публичного IP для правила')
    return result


def revision(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:16]


def normalize(rows):
    from core import text
    if not isinstance(rows, list) or len(rows) > 64:
        fail('Не больше 64 правил из соединений в одной секции')
    result, ids = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - {'id', 'name', 'domains', 'cidrs'}:
            fail('Некорректное правило из соединения')
        identity = row.get('id', '')
        if not isinstance(identity, str) or not re.fullmatch('[a-f0-9]{16}', identity) or identity in ids:
            fail('Некорректный или повторяющийся ID правила соединения')
        ids.add(identity)
        values = {}
        for key, clean in (('domains', domain), ('cidrs', public_ip)):
            source = row.get(key, [])
            if not isinstance(source, list) or len(source) > 32:
                fail('В одном правиле не больше 32 доменов и 32 IP')
            values[key] = list(dict.fromkeys(clean(x) for x in source))
        if not any(values.values()):
            fail('Добавьте хотя бы один домен или IP')
        result.append(dict(id=identity, name=text(row.get('name', ''), 80) or (values['domains'] + values['cidrs'])[0], **values))
    return result


def change(settings, operation, section_id, identity, target):
    """Change only this owned record; manual section matchers stay untouched."""
    if operation not in ('save', 'delete'):
        fail('Неизвестная операция правила соединения')
    original = next(((s, r) for s in settings['sections'] for r in s.get('connection_rules', []) if r['id'] == identity), None) if identity else None
    if identity and not original:
        fail('Правило уже удалено; обновите список')
    if operation == 'delete':
        if not original:
            fail('Правило не найдено')
        owner, row = original
        owner['connection_rules'].remove(row)
        # A section containing only monitor rules becomes an inert empty section.
        has_base = any(owner.get(k) for k in ('domains', 'cidrs', 'source_ips', 'routed_source_ips', 'source_interfaces', 'ports', 'networks', 'outbound_config')) or owner.get('mixed_proxy', {}).get('enabled') or any(x.get('section') == owner['id'] for x in settings['remote_lists']) or settings.get('fetch_lists_section') == owner['id']
        if not owner['connection_rules'] and not has_base:
            owner['enabled'] = False
        return {'id': identity, 'section_disabled': not owner['enabled']}
    owner = next((s for s in settings['sections'] if s['id'] == section_id and s['enabled'] and s['policy'] == 'proxy'), None)
    if owner is None:
        fail('Выберите включённую прокси-секцию')
    if not isinstance(target, dict) or set(target) - {'name', 'domains', 'cidrs'}:
        fail('Некорректные адреса правила')
    clean = normalize([dict(target, id=identity or secrets.token_hex(8))])[0]
    for s in settings['sections']:
        for row in s.get('connection_rules', []):
            if row['id'] == identity:
                continue
            if set(row['domains']) & set(clean['domains']) or set(row['cidrs']) & set(clean['cidrs']):
                if s['id'] == owner['id'] and row['domains'] == clean['domains'] and row['cidrs'] == clean['cidrs']:
                    return {'id': row['id'], 'unchanged': True}
                fail('Адрес уже есть в правиле «%s» секции «%s». Измените это правило.' % (row['name'], s['name']))
    if original:
        original[0]['connection_rules'].remove(original[1])
        if original[0] is not owner:
            old = original[0]
            has_base = any(old.get(k) for k in ('domains', 'cidrs', 'source_ips', 'routed_source_ips', 'source_interfaces', 'ports', 'networks', 'outbound_config')) or old.get('mixed_proxy', {}).get('enabled') or any(x.get('section') == old['id'] for x in settings['remote_lists']) or settings.get('fetch_lists_section') == old['id']
            if not old['connection_rules'] and not has_base:
                old['enabled'] = False
    owner.setdefault('connection_rules', []).append(clean)
    return {'id': clean['id']}
