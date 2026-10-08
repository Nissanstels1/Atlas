"""Section controls derived from validated configuration, never client tags."""
from urllib.parse import quote, urlencode
from core import AtlasError


def groups_for_section(section, config):
    prefix = 'section_' + section['id'] + '_'
    targets = {x['tag']: x for x in config['outbounds']}
    if section.get('outbound_config') or prefix+'control' in targets:
        return [x for x in config['outbounds'] if x['tag'].startswith(prefix) and x['type'] in ('selector', 'urltest')]
    root = 'pool_' + section['pool'] if section.get('pool') else 'proxy'
    if section['policy'] != 'proxy':
        return []
    group = targets.get(root)
    result = [group] if group else []
    result += [targets[tag] for tag in (group or {}).get('outbounds', []) if tag in targets and targets[tag]['type'] == 'urltest']
    return result


def section_dashboard(current, config, request):
    proxies = request().get('proxies', {})
    names = {s['id'] + n['id']: n['name'] for s in current['subscriptions'] for n in s.get('nodes', [])}
    rows = []
    for section in current['settings']['sections']:
        if not section['enabled']:
            continue
        groups = []
        for group in groups_for_section(section, config):
            live = proxies.get(group['tag'], {})
            groups.append({'tag':group['tag'], 'type':group['type'], 'selected':live.get('now', group.get('default','')),
                'shared':not group['tag'].startswith('section_'+section['id']+'_'),
                'members':[{'tag':tag, 'name':names.get(tag,names.get(tag.removeprefix('section_' + section['id'] + '_'),tag.removeprefix('section_' + section['id'] + '_'))),
                    'delay':next((h.get('delay') for h in reversed(proxies.get(tag, {}).get('history', []))), None)} for tag in group.get('outbounds', [])]})
        rows.append({'id':section['id'], 'name':section['name'], 'policy':section['policy'], 'groups':groups})
    return rows


def choose_section(current, config, section_id, group_tag, member, request):
    section = next((x for x in current['settings']['sections'] if x['id'] == section_id and x['enabled']), None)
    if not section:
        raise AtlasError('Секция не найдена или выключена')
    group = next((x for x in groups_for_section(section, config) if x['tag'] == group_tag and x['type'] == 'selector'), None)
    if not group or member not in group['outbounds']:
        raise AtlasError('Сервер не принадлежит selector этой секции')
    if group_tag == 'proxy' and member not in ['auto'] + [x['tag'] for x in config['outbounds'] if len(x.get('tag','')) == 32]:
        raise AtlasError('Для основного пула выберите Авто или сервер')
    request('PUT', '/proxies/' + quote(group_tag, safe=''), {'name':member})
    if group_tag == 'proxy':
        current['settings']['selected'] = 'auto' if member == 'auto' else member
    else:
        automatic = next((x for x in config['outbounds'] if x['tag'] == member and x['type'] == 'urltest'), None)
        if automatic and (group_tag.startswith('pool_') or group_tag.startswith('section_'+section['id']+'_control')):
            current['settings']['section_choices'].pop(group_tag, None)
        else:
            current['settings']['section_choices'][group_tag] = member


def test_section(current, config, section_id, request):
    section = next((x for x in current['settings']['sections'] if x['id'] == section_id and x['enabled']), None)
    if not section:
        raise AtlasError('Секция не найдена')
    groups = groups_for_section(section, config)
    members = list(dict.fromkeys(tag for group in groups for tag in group.get('outbounds', [])))
    if not members:
        raise AtlasError('В секции нет группы серверов для проверки')
    query = urlencode({'timeout':5000, 'url':section.get('urltest_url') or current['settings']['urltest_url']})
    result = {}
    for member in members:
        try:
            result[member] = request('GET', '/proxies/' + quote(member, safe='') + '/delay?' + query, timeout=7)
        except (AtlasError, OSError, ValueError):
            result[member] = {'ok':False}
    return result
