"""Versioned backups. Rebuild imported data before it reaches runtime state."""
import copy
import json
import re
from core import (AtlasError, MAX_SUBSCRIPTIONS, MAX_NODES, MAX_TOTAL_NODES,
                  defaults, normalize_custom, normalize_editor_node, subscription_url,
                  subscription_headers, text, validate_settings)

MAX_BACKUP_BYTES = 16 * 1024 * 1024


def make_backup(state):
    return {'format': 'atlas-backup', 'schema': 1, 'state': copy.deepcopy(state)}


def restore_state(content):
    if not isinstance(content, str) or len(content.encode('utf-8')) > MAX_BACKUP_BYTES:
        raise AtlasError('Резервная копия ограничена 16 МиБ')
    try:
        backup = json.loads(content)
    except (ValueError, RecursionError):
        raise AtlasError('Некорректный JSON резервной копии') from None
    if not isinstance(backup, dict) or backup.get('format') != 'atlas-backup' or type(backup.get('schema')) is not int or backup['schema'] != 1:
        raise AtlasError('Нужна резервная копия Atlas schema=1')
    raw = backup.get('state')
    if not isinstance(raw, dict) or not isinstance(raw.get('settings'), dict):
        raise AtlasError('В копии отсутствуют настройки')
    state = defaults()
    state['settings'] = validate_settings(raw['settings'])
    subscriptions = raw.get('subscriptions')
    if not isinstance(subscriptions, list) or len(subscriptions) > MAX_SUBSCRIPTIONS:
        raise AtlasError('Некорректный список источников резервной копии')
    ids, count = set(), 0
    for source in subscriptions:
        if not isinstance(source, dict) or not isinstance(source.get('id'), str) or not re.fullmatch('[a-f0-9]{16}', source['id']) or source['id'] in ids:
            raise AtlasError('Некорректный или повторяющийся ID источника')
        ids.add(source['id'])
        if type(source.get('enabled', True)) is not bool or source.get('source', 'remote') not in ('remote', 'local'):
            raise AtlasError('Некорректный тип источника или флаг')
        name = text(source.get('name', ''), 80)
        if not name:
            raise AtlasError('Пустое имя источника')
        local = source.get('source') == 'local'
        url = '' if local else subscription_url(source.get('url', ''))
        headers = source.get('headers', {})
        if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
            raise AtlasError('Некорректные HTTP-заголовки')
        headers = subscription_headers('\n'.join('%s: %s' % (k, v) for k, v in headers.items())) if headers else {}
        nodes = source.get('nodes', [])
        if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
            raise AtlasError('Источник содержит слишком много профилей')
        rebuilt, node_ids = [], set()
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get('id'), str) or not re.fullmatch('[a-f0-9]{16}', node['id']) or node['id'] in node_ids:
                raise AtlasError('Некорректный ID профиля')
            try:
                clean = (normalize_editor_node if local else normalize_custom)(node.get('outbound'), node.get('name'))
            except (ValueError, TypeError, KeyError, AttributeError):
                raise AtlasError('Некорректный профиль в резервной копии') from None
            # Preserve selection keys. Geolocation evidence must be measured anew.
            clean['id'] = node['id']
            node_ids.add(clean['id'])
            rebuilt.append(clean)
        count += len(rebuilt)
        if count > MAX_TOTAL_NODES:
            raise AtlasError('Резервная копия содержит более 4096 профилей')
        state['subscriptions'].append({'id': source['id'], 'name': name, 'url': url,
            'source': 'local' if local else 'remote', 'enabled': source.get('enabled', True),
            'nodes': rebuilt, 'headers': {} if local else headers, 'updated': 0,
            'metadata': {}, 'error': '', 'warnings': [], 'format': source.get('format', 'backup')})
    return state
