"""Keep one cache namespace while rejecting stale managed selector choices.

sing-box restores a choice only when its value belongs to the current selector.
Rotate managed member tags, not cache namespaces. Public Atlas IDs stay stable.
"""
import copy
import re
from urllib.parse import quote, unquote

PREFIX = re.compile(r'^atlas_run_[a-f0-9]{32}_(.+)$')
MANAGED = re.compile(r'^(?:[a-f0-9]{32}|section_[a-f0-9]{16}_[a-f0-9]{32})$')


def managed_auto(group):
    if group == 'proxy': return 'auto'
    if re.fullmatch(r'pool_[a-f0-9]{16}', group): return 'auto_' + group[5:]
    if re.fullmatch(r'section_[a-f0-9]{16}_control', group): return group[:-7] + 'auto'
    return None


def managed_groups(config):
    targets = {x['tag']: x for x in config.get('outbounds', []) if isinstance(x, dict) and isinstance(x.get('tag'), str)}
    marked = any(x.get('type')=='block' and tag.startswith('atlas_guard_') for tag,x in targets.items())
    for group in targets.values():
        if marked and targets.get('atlas_guard_'+group['tag'],{}).get('type')!='block': continue
        automatic = managed_auto(group['tag'])
        tester = targets.get(automatic, {})
        if group.get('type') == 'selector' and 'policy-block' in group.get('outbounds', []) and tester.get('type') == 'urltest' and all(MANAGED.fullmatch(base_tag(tag)) for tag in tester.get('outbounds', [])):
            yield group, automatic


def base_tag(tag):
    if not isinstance(tag, str): return tag
    match = PREFIX.fullmatch(tag)
    return match[1] if match and MANAGED.fullmatch(match[1]) else tag


def rewrite(config, mapping):
    result = copy.deepcopy(config)
    def reference(value, key):
        if isinstance(value, dict) and isinstance(value.get(key), str):
            value[key] = mapping.get(value[key], value[key])
    for outbound in result.get('outbounds', []):
        for key in ('tag','detour','default'): reference(outbound,key)
        for field in ('outbounds','fallbacks'):
            if isinstance(outbound.get(field),list):
                outbound[field]=[mapping.get(tag,tag) if isinstance(tag,str) else tag for tag in outbound[field]]
    for server in result.get('dns',{}).get('servers',[]): reference(server,'detour')
    route=result.get('route',{})
    reference(route,'final')
    for ruleset in route.get('rule_set',[]): reference(ruleset,'download_detour')
    def rules(values):
        for rule in values:
            reference(rule,'outbound')
            if isinstance(rule,dict) and isinstance(rule.get('rules'),list): rules(rule['rules'])
    rules(route.get('rules',[]))
    reference(result.get('experimental',{}).get('clash_api',{}),'external_ui_download_detour')
    return result


def normalized_config(config):
    if not isinstance(config, dict): return config
    mapping = {x['tag']: base_tag(x['tag']) for x in config.get('outbounds', []) if isinstance(x, dict) and isinstance(x.get('tag'), str)}
    result = rewrite(config, mapping) if any(key != value for key, value in mapping.items()) else copy.deepcopy(config)
    if result.get('experimental', {}).get('cache_file', {}).get('cache_id') == 'atlas-policy-v2':
        for group, automatic in managed_groups(result):
            if automatic not in group['outbounds']: group['outbounds'].insert(0, automatic)
    return result


def prepare(config, token):
    result = normalized_config(copy.deepcopy(config))
    cache = result.get('experimental', {}).get('cache_file', {})
    if not cache.get('cache_id', '').startswith('atlas-policy'): return result
    cache['cache_id'] = 'atlas-policy-v2'
    # Keep URLTest group IDs stable (including external dashboard expansion
    # cache keys). Advanced selection uses fresh node evidence, never URLTest's
    # unconstrained result. Atlas exposes "Auto" as a command to return to the
    # guarded policy, not as a directly selectable persisted engine member.
    for group, automatic in managed_groups(result):
        group['outbounds'] = [tag for tag in group['outbounds'] if tag != automatic]
        if group.get('default') == automatic: group['default'] = 'policy-block'
    mapping = {x['tag']: 'atlas_run_' + token + '_' + x['tag'] for x in result.get('outbounds', []) if isinstance(x, dict) and MANAGED.fullmatch(x.get('tag', ''))}
    return rewrite(result, mapping)


def normalized_proxies(proxies):
    if not isinstance(proxies, dict): return proxies
    result = {}
    for tag, value in proxies.items():
        item = dict(value) if isinstance(value, dict) else value
        if isinstance(item, dict):
            for key in ('name', 'now'):
                if key in item: item[key] = base_tag(item[key])
            if isinstance(item.get('all'), list): item['all'] = [base_tag(x) for x in item['all']]
        result[base_tag(tag)] = item
    return result


def wire_request(config, path, body):
    mapping = {base_tag(x['tag']): x['tag'] for x in config.get('outbounds', []) if isinstance(x, dict) and isinstance(x.get('tag'), str)}
    if path.startswith('/proxies/'):
        tag, separator, tail = path[len('/proxies/'):].partition('/')
        name, question, query = tag.partition('?')
        path = '/proxies/' + quote(mapping.get(unquote(name), unquote(name)), safe='') + (question + query if question else '') + (separator + tail if separator else '')
    if isinstance(body, dict) and isinstance(body.get('name'), str):
        body = dict(body, name=mapping.get(body['name'], body['name']))
        group_tag = unquote(path[len('/proxies/'):]) if path.startswith('/proxies/') and '/' not in path[len('/proxies/'):] else None
        for group, automatic in managed_groups(config):
            if group['tag'] == group_tag and body['name'] == automatic and automatic not in group['outbounds']:
                body['name'] = 'policy-block'
    return path, body
