#!/usr/bin/python3
"""Root-only backend. rpcd provides authentication; ACL grants individual methods."""
import contextlib
import calendar
import base64
import copy
import fcntl
import http.client
import ipaddress
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from probes import probe_batch, probe_workers
from maintenance import prune_artifacts
from launch_cache import base_tag, normalized_config, normalized_proxies, wire_request, prepare as prepare_launch_cache
from sections import section_dashboard, choose_section, test_section
from planner import safe_config, explain_route, conflicts
from firewall_diag import inspect as inspect_firewall
from version import VERSION
from backups import MAX_BACKUP_BYTES, make_backup, restore_state
from urllib.parse import urlsplit, quote, urlencode
from download_policy import DownloadPolicy
from core import AtlasError, MAX_BYTES, MAX_RULE_LIST_ENTRIES, MAX_SUBSCRIPTIONS, MAX_TOTAL_NODES, all_nodes, custom_auto_policy, real_ip_resolution_active, country_for_node, country_source_for_node, defaults, filter_nodes, host, make_config, parse_subscription, privacy_checks, rule_set_format, rule_list_url, selection_nodes, subscription_headers, subscription_url, text, validate_settings

DATA = Path('/etc/atlas')
RUN = Path('/var/run/atlas')
STATE = DATA / 'state.json'
CONFIG = RUN / 'config.json'
SCRIPT = '/usr/lib/atlas/atlas.py'
BINARY = __import__('engine_features').binary_path()
MAX_INLINE_PROFILE_BYTES = 256 * 1024
METHODS = {'status': {}, 'save_subscription': {'id': '', 'name': '', 'url': '', 'enabled': True, 'headers': '', 'clear_headers': False},
           'import_subscriptions': {'items': []},
           'import_profiles': {'name': '', 'content': '', 'id': ''},
           'get_profiles': {'id': ''}, 'section_details': {'id': ''},
           'config_preview': {'validate':False}, 'route_explain': {'query':{}}, 'section_clone': {'id':'','name':''}, 'set_autostart': {'enabled':False},
           'service_logs': {}, 'nft_diagnostics': {},
           'export_backup': {}, 'restore_backup': {'content': ''}, 'diagnostic_report': {},
           'delete_subscription': {'id': ''}, 'save_settings': {'settings': {}},
           'import_rules': {'content': '', 'target': ''},
           'action': {'operation': '', 'id': ''}, 'monitor': {}, 'dashboard_access': {}, 'section_dashboard': {}, 'section_select': {'id':'','group':'','member':''}}


def stored_config_dir(settings):
    if settings.get('config_storage') == 'external':
        path = Path(settings['config_custom_dir'])
        if path.is_symlink() or any(x.is_symlink() for x in path.parents):
            raise AtlasError('Каталог конфигурации не должен быть символьной ссылкой')
        created = not path.exists()
        path.mkdir(mode=0o700,parents=True,exist_ok=True)
        if created:path.chmod(0o700)
        return path
    return RUN if settings.get('config_storage') == 'ram' else DATA


def prepare_runtime_paths(config, settings):
    cache = config.get('experimental', {}).get('cache_file', {}).get('path', '')
    if not isinstance(cache, str) or not cache.startswith('/'):
        raise AtlasError('Недопустимый путь файла кеша')
    path = Path(cache)
    if path.is_symlink() or any(part.is_symlink() for part in path.parents if str(part) != '/'):
        raise AtlasError('Путь кеша не должен проходить через символическую ссылку')
    created = not path.parent.exists()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created:path.parent.chmod(0o700)



def setup():
    os.umask(0o077)
    for p in (DATA, RUN):
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        p.chmod(0o700)


def read_json(path, fallback):
    try:
        value = json.loads(path.read_text())
        return normalized_config(value) if path == CONFIG else value
    except FileNotFoundError:
        return copy.deepcopy(fallback)


def atomic(path, data):
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_bytes(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def named_lock(name, block=False):
    with open(RUN / name, 'a') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if block else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise AtlasError('Другая операция ещё выполняется') from exc
        yield


def locked(block=False):
    return named_lock('lock', block)


def maintain_artifacts(current):
    """Best-effort cleanup under the operation lock, after a successful commit."""
    try:
        result = prune_artifacts(current, DATA, RUN, CONFIG)
        checks = result.pop('checks', None)
        if checks is not None:
            atomic(RUN / 'checks.json', checks)
        return result
    except OSError:
        return {'skipped': 'filesystem-error'}


def state():
    value = read_json(STATE, defaults())
    value['settings'] = validate_settings(value['settings'])
    return value


def runtime_config(current, persist=True):
    credentials = read_json(DATA / 'controller.json', {})
    if not credentials.get('secret'):
        credentials = {'secret': secrets.token_hex(32)}
        if persist:atomic(DATA / 'controller.json', credentials)
    prepared = copy.deepcopy(current)
    config = make_config(prepared, api_secret=credentials['secret'])
    if persist:prepare_runtime_paths(config, current['settings'])
    return config


def decode_runtime(proxies, nodes):
    """Read actual selector chain. Never guess the selected server from RTT."""
    if not isinstance(proxies, dict):
        raise AtlasError('Некорректный ответ локального API')
    current, seen = 'proxy', set()
    while current in ('proxy', 'auto'):
        if current in seen:
            raise AtlasError('Цикл в ответе локального API')
        seen.add(current)
        group = proxies.get(current, {})
        current = group.get('now')
        if not isinstance(current, str) or not current:
            return {'available': True, 'selected': None, 'message': 'Движок ещё не выбрал узел'}
    if current == 'local-only-block':
        return {'available': True, 'selected': None, 'automatic': False, 'blocked': True, 'reason': 'no-main-pool',
                'message': 'Основной пул не подключён; используются независимые секции'}
    if current == 'policy-block':
        return {'available': True, 'selected': None, 'automatic': True, 'blocked': True,
                'message': 'Группа заблокирована: нет свежего узла, соответствующего критериям'}
    import re
    if not re.fullmatch('[a-f0-9]{32}', current):
        raise AtlasError('Неизвестный маршрут в ответе локального API')
    n = next((n for n in nodes if n['key'] == current), None)
    group = proxies.get('auto', {})
    candidates = group.get('all', [])
    result = {'available': True, 'selected': current, 'automatic': 'auto' in seen,
              'name': n['name'] if n else 'Узел из ранее применённой конфигурации',
              'country': country_for_node(n) if n else '',
              'candidate_count': len(candidates) if isinstance(candidates, list) else 0}
    history = proxies.get(current, {}).get('history', [])
    if isinstance(history, list) and history and isinstance(history[-1], dict):
        last = history[-1]
        if type(last.get('delay')) is int and 0 < last['delay'] <= 60000:
            result['last_delay_ms'] = last['delay']
            result['last_check'] = str(last.get('time', ''))[:64]
    return result


def runtime_status(nodes, running):
    if not running:
        return {'available': False, 'message': 'Движок остановлен'}
    # Read the active config, not a potentially unapplied new credential.
    config = read_json(CONFIG, {})
    api = config.get('experimental', {}).get('clash_api', {})
    controller = api.get('external_controller', '')
    address, _, port = controller.rpartition(':')
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        return {'available':False,'message':'Примените настройки для включения API'}
    if port != '19090' or not api.get('secret'):
        return {'available': False, 'message': 'Примените настройки для включения статуса выбора'}
    connection = http.client.HTTPConnection('127.0.0.1' if address == '0.0.0.0' else address, 19090, timeout=1)
    try:
        connection.request('GET', '/proxies', headers={'Authorization': 'Bearer ' + api['secret']})
        response = connection.getresponse()
        if response.status != 200:
            raise AtlasError('Локальный API недоступен')
        raw = response.read(4 * MAX_BYTES + 1)
        if len(raw) > 4 * MAX_BYTES:
            raise AtlasError('Ответ локального API слишком большой')
        proxies = normalized_proxies(json.loads(raw).get('proxies'))
        result = decode_runtime(proxies, nodes)
        groups = []
        for tag in sorted(proxies):
            if re.fullmatch(r'pool_[a-f0-9]{16}', tag):
                current = proxies[tag].get('now')
                if current == 'auto_' + tag[5:]:
                    current = proxies.get(current, {}).get('now')
                member = next((n for n in nodes if n['key'] == current), None)
                groups.append({'group': tag, 'blocked': current == 'policy-block',
                               'selected': member['key'] if member else None,
                               'name': member['name'] if member else 'Заблокирован' if current == 'policy-block' else 'Выбор пока неизвестен'})
        result['groups'] = groups
        return result
    except (AtlasError, OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
        return {'available': False, 'message': 'Нет ответа от движка; выбранный узел неизвестен'}
    finally:
        connection.close()


def runtime_monitor():
    """Return a bounded, sanitized Clash API snapshot to LuCI administrators only."""
    if not service_running():
        return {'ok': True, 'available': False, 'message': 'Движок остановлен', 'connections': [], 'rules': []}
    try:
        payload = clash_request('GET', '/connections')
        raw_connections = payload.get('connections', []) if isinstance(payload, dict) else []
        if not isinstance(raw_connections, list):
            raw_connections = []
        connections = []
        for item in raw_connections[:50]:
            if not isinstance(item, dict):
                continue
            metadata = item.get('metadata', {}) if isinstance(item.get('metadata'), dict) else {}
            identity = item.get('id', '')
            if not isinstance(identity, str) or not re.fullmatch('[A-Za-z0-9._:-]{1,128}', identity):
                continue
            def short(value, limit=160):
                try:
                    return text(value, limit)
                except (AtlasError, TypeError):
                    return ''
            chains = item.get('chains', [])
            if not isinstance(chains, list):
                chains = []
            connections.append({
                'id': identity,
                'network': short(metadata.get('network', ''), 12),
                'host': short(metadata.get('host', ''), 253),
                'destination': short(metadata.get('destinationIP', '') or item.get('destination', ''), 253),
                'source': short(item.get('source', ''), 128),
                'chains': [short(base_tag(value), 64) for value in chains[:4] if isinstance(value, str)],
                'rule': short(item.get('rule', ''), 100),
                'rule_payload': short(item.get('rulePayload', ''), 180),
                'upload': item.get('upload', 0) if type(item.get('upload', 0)) is int else 0,
                'download': item.get('download', 0) if type(item.get('download', 0)) is int else 0,
                'start': short(item.get('start', ''), 40)
            })
        rules_payload = clash_request('GET', '/rules')
        raw_rules = rules_payload.get('rules', []) if isinstance(rules_payload, dict) else []
        rules = []
        if isinstance(raw_rules, list):
            for item in raw_rules[:60]:
                if not isinstance(item, dict):
                    continue
                rules.append({'type': text(item.get('type', ''), 64),
                              'payload': text(item.get('payload', ''), 128),
                              'outbound': text(base_tag(item.get('proxy', '')), 96)})
        return {'ok': True, 'available': True, 'connections': connections, 'rules': rules,
                'memory': process_memory(),
                'upload_total': payload.get('uploadTotal', 0) if type(payload.get('uploadTotal', 0)) is int else 0,
                'download_total': payload.get('downloadTotal', 0) if type(payload.get('downloadTotal', 0)) is int else 0,
                'truncated': len(raw_connections) > 50 or len(raw_rules) > 60}
    except (AtlasError, OSError, ValueError, TypeError, http.client.HTTPException):
        return {'ok': True, 'available': False, 'message': 'Локальный Clash API не отвечает',
                'connections': [], 'rules': []}


def process_memory():
    """Read sing-box RSS from procfs; the compatible Clash /memory endpoint can hang."""
    try:
        result = run(['/bin/ubus', 'call', 'service', 'list', json.dumps({'name': 'atlas'})], 3)
        services = json.loads(result.stdout) if result.returncode == 0 else {}
        instances = services.get('atlas', {}).get('instances', {})
        for instance in instances.values():
            pid = instance.get('pid') if isinstance(instance, dict) else None
            if type(pid) is not int or pid <= 0:
                continue
            status = Path('/proc/%d/status' % pid).read_text()
            match = re.search(r'^VmRSS:\s+(\d+)\s+kB$', status, re.M)
            if match:
                return {'inuse': int(match.group(1)) * 1024}
    except (AtlasError, OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        pass
    return {}


def clash_request(method='GET', path='/proxies', body=None, timeout=2):
    """Talk only to Atlas' loopback Clash API; never expose the token over RPC."""
    active = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    path, body = wire_request(active, path, body)
    api = active.get('experimental', {}).get('clash_api', {})
    controller = api.get('external_controller', '')
    address, _, port = controller.rpartition(':')
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        raise AtlasError('Некорректный адрес API Atlas')
    if port != '19090' or not api.get('secret'):
        raise AtlasError('Локальный API Atlas не настроен')
    connection = http.client.HTTPConnection('127.0.0.1' if address == '0.0.0.0' else address, 19090, timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {'Authorization': 'Bearer ' + api['secret'], 'Connection': 'close'}
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        data = response.read(4 * MAX_BYTES + 1)
        if len(data) > 4 * MAX_BYTES:
            raise AtlasError('Слишком большой ответ локального API')
        if response.status not in (200, 204):
            raise AtlasError('Локальный API вернул HTTP %d' % response.status)
        value = json.loads(data) if data else {}
        if isinstance(value, dict) and 'proxies' in value:
            value['proxies'] = normalized_proxies(value['proxies'])
        return value
    finally:
        connection.close()


def auto_choice(nodes, settings, proxies, now=None):
    """Return best measured filtered node, or None when evidence is stale/absent."""
    now = int(now or time.time())
    preferred = settings['preferred_countries']
    reserve_order = {key:index+1 for index,key in enumerate(settings.get('urltest_fallbacks', []))}
    candidates = []
    for node in nodes:
        proxy = proxies.get(node['key'], {}) if isinstance(proxies, dict) else {}
        history = proxy.get('history', []) if isinstance(proxy, dict) else []
        if not isinstance(history, list) or not history or not isinstance(history[-1], dict) or type(history[-1].get('delay')) is not int or not 0 < history[-1]['delay'] <= 60000:
            continue
        delays = []
        for sample in history[-5:] if isinstance(history, list) else []:
            if not isinstance(sample, dict) or type(sample.get('delay')) is not int:
                continue
            if not 0 < sample['delay'] <= 60000:
                continue
            # Clash API emits RFC3339 timestamps. Reject stale measurements when parseable.
            stamp = sample.get('time')
            if not isinstance(stamp, str) or not stamp:
                continue
            if stamp:
                try:
                    parsed = time.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S')
                    age = now - int(calendar.timegm(parsed))
                    if age < -60 or age > max(180, settings['auto_interval_seconds'] * 3):
                        continue
                except (TypeError, ValueError, OverflowError):
                    continue
            delays.append(sample['delay'])
        if not delays:
            continue
        recent = delays[-1]
        if settings['min_ping_ms'] and recent < settings['min_ping_ms']:
            continue
        if settings['max_ping_ms'] and recent > settings['max_ping_ms']:
            continue
        country = country_for_node(node, settings.get('require_verified_countries', False))
        country_rank = preferred.index(country) if country in preferred else len(preferred)
        mean = sum(delays) / len(delays)
        jitter = max(delays) - min(delays) if len(delays) > 1 else 0
        if settings['auto_strategy'] == 'slowest':
            score = -recent
        elif settings['auto_strategy'] == 'stable':
            score = jitter * 2 + mean
        else:
            score = recent
        # All URLTest members are measured, including reserves. A reserve is
        # eligible only after every primary failed these same fresh criteria.
        reserve_rank = reserve_order.get(node['key'], 0)
        candidates.append((reserve_rank, country_rank, score, recent, node['key']))
    return min(candidates)[4] if candidates else None


def automatic_select(current):
    """Select each active pool independently; fail closed without qualifying evidence."""
    settings = current['settings']
    if not service_running():
        return {'changed': False, 'reason': 'service-stopped'}
    nodes = filter_nodes(all_nodes(current), settings)
    custom = custom_auto_policy(settings)
    try:
        proxies = clash_request().get('proxies', {})
        groups = {}
        if settings['selected'] == 'auto':
            groups['proxy'] = (nodes, 'auto', settings)
        for sub in current.get('subscriptions', []):
            tag = 'pool_' + sub['id']
            if sub.get('enabled', True) and tag in proxies and tag not in settings.get('section_choices', {}):
                groups[tag] = ([n for n in nodes if n['key'].startswith(sub['id'])], 'auto_' + sub['id'], settings)
        for section in settings['sections']:
            tag='section_'+section['id']+'_control'
            if section['enabled'] and not section['outbound_config'] and tag in proxies and tag not in settings.get('section_choices',{}):
                members=[n for n in nodes if not section['pool'] or n['key'].startswith(section['pool'])]
                if section['udp_over_tcp'] is not None or section['udp_over_tcp_version'] is not None:
                    members=[dict(n,key='section_'+section['id']+'_'+n['key']) for n in members]
                policy=dict(settings)
                for field in ('urltest_fallbacks','urltest_download_check','urltest_download_url'):
                    policy[field]=section.get(field, [] if field=='urltest_fallbacks' else 'default' if field=='urltest_download_check' else '')
                if section['udp_over_tcp'] is not None or section['udp_over_tcp_version'] is not None:
                    policy['urltest_fallbacks']=['section_'+section['id']+'_'+key for key in policy['urltest_fallbacks']]
                if section['auto_interval_seconds'] is not None:
                    policy['auto_interval_seconds']=section['auto_interval_seconds']
                groups[tag]=(members, 'section_'+section['id']+'_auto', policy)
        transfers=None
        ordered=list(groups.items())
        if custom and any(policy.get('urltest_download_check')=='custom' for _,(_,_,policy) in ordered):
            proof_path=RUN/'download-proofs.json'
            try:saved=read_json(proof_path,{}) if proof_path.stat().st_size<=1048576 else {}
            except (OSError,ValueError):saved={}
            generation=hashlib.sha256(CONFIG.read_bytes()).hexdigest()
            def transfer(key,url):
                path='/proxies/'+quote(key,safe='')+'/download?'+urlencode({'url':url,'timeout':5000})
                return clash_request('GET',path,timeout=5.5)
            transfers=DownloadPolicy(saved,generation,transfer)
            offset=transfers.cursor%max(1,len(ordered))
            ordered=ordered[offset:]+ordered[:offset]
        results = []
        for tag, (members, native, policy) in ordered:
            previous = proxies.get(tag, {}).get('now')
            download=None
            if transfers is not None and policy.get('urltest_download_check')=='custom':
                key,download=transfers.choose(members,policy,proxies,previous,auto_choice)
            else:key = (auto_choice(members, policy, proxies) or 'policy-block') if custom else native
            try:
                if previous != key:
                    clash_request('PUT', '/proxies/' + tag, {'name': key})
            except (AtlasError, OSError, ValueError, TypeError, http.client.HTTPException):
                results.append({'group':tag,'selected':previous,'requested':key,'blocked':previous=='policy-block','changed':False,'ok':False,'reason':'switch-failed'})
                continue
            results.append({'group': tag, 'selected': key, 'blocked': key == 'policy-block', 'changed': previous != key, 'ok':True})
            if download:results[-1]['download']=download
        if transfers is not None:atomic(RUN/'download-proofs.json',transfers.export(len(ordered)))
        result = {'changed': any(x['changed'] for x in results), 'groups': results,
                  'selected': next((x['selected'] for x in results if x['group'] == 'proxy'), None),
                  'at': int(time.time()), 'reason': 'partial-failure' if any(not x['ok'] for x in results) else 'criteria-applied' if custom else 'native-fastest'}
        atomic(RUN / 'auto-selection.json', result)
        return result
    except (AtlasError, OSError, ValueError, TypeError, http.client.HTTPException):
        return {'changed': False, 'reason': 'controller-unavailable'}


def wait_engine_ready(attempts=60):
    """procd can report the launcher before sing-box is accepting requests."""
    for _ in range(attempts):
        if service_running():
            try:
                if isinstance(clash_request('GET','/proxies',timeout=1).get('proxies'),dict) and service_running():
                    return True
            except (AtlasError,OSError,http.client.HTTPException,ValueError):
                pass
        time.sleep(.4)
    return False


def healthcheck():
    """Bounded watchdog: validate and restart only an enabled Atlas service."""
    enabled = Path('/etc/rc.d/S99atlas').exists()
    if not enabled:
        return {'ok': True, 'reason': 'disabled'}
    if any(service_running(name) for name in ('podkop', 'sing-box', 'passwall', 'passwall2', 'openclash')):
        return {'ok': False, 'reason': 'conflicting-service'}
    current = state()
    config_store = stored_config_dir(current['settings'])
    current_config = read_json(CONFIG, None)
    good_config = read_json(config_store / 'last-good.json', None) or read_json(config_store / 'active.json', None)
    if current_config:
        try:
            check(current_config)
        except (AtlasError, OSError, subprocess.TimeoutExpired):
            if not good_config:
                return {'ok': False, 'reason': 'invalid-config-no-backup'}
            try:
                check(good_config)
            except (AtlasError, OSError, subprocess.TimeoutExpired):
                return {'ok': False, 'reason': 'invalid-backup'}
            atomic(CONFIG, good_config)
            current_config = good_config
    elif good_config:
        try:
            check(good_config)
        except (AtlasError, OSError, subprocess.TimeoutExpired):
            return {'ok': False, 'reason': 'invalid-backup'}
        atomic(CONFIG, good_config)
    else:
        return {'ok': False, 'reason': 'no-config'}
    country_policy = enforce_verified_country_policy(current, current_config or good_config)
    if country_policy is not None:
        return country_policy
    if service_running():
        return {'ok': True, 'reason': 'healthy'}
    stamp = int(time.time())
    attempts = [x for x in read_json(RUN / 'recovery.json', {}).get('attempts', []) if type(x) is int and stamp - x < 600]
    if len(attempts) >= 3:
        return {'ok': False, 'reason': 'restart-limit'}
    attempts.append(stamp)
    atomic(RUN / 'recovery.json', {'attempts': attempts})
    try:
        proc = run(['/etc/init.d/atlas', 'restart'], 90)
        ok = proc.returncode == 0 and wait_engine_ready()
        return {'ok': ok, 'reason': 'restarted' if ok else 'restart-failed'}
    except (OSError, subprocess.TimeoutExpired):
        return {'ok': False, 'reason': 'restart-failed'}


def record_interface_event(action=None, interface=None):
    """Persist only netifd events explicitly selected by the router admin."""
    action = action if action is not None else os.environ.get('ACTION', '')
    interface = interface if interface is not None else os.environ.get('INTERFACE', '')
    try:
        current = state()
    except (OSError, ValueError, AtlasError):
        return {'ok': False, 'reason':'invalid-state'}
    settings = current['settings']
    if action not in ('ifup','ifdown') or not settings['interface_monitoring'] or interface not in settings['monitored_interfaces']:
        return {'ok': True, 'reason':'ignored'}
    event = {'id':secrets.token_hex(8), 'action':action, 'interface':interface, 'at':int(time.time()), 'monotonic':time.monotonic()}
    with named_lock('interface-event.lock', True):
        atomic(RUN / 'interface-event.json', event)
        if action=='ifup':
            with open(RUN/'interface-worker.lock','a') as gate:
                try:
                    fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    return {'ok':True,'reason':'coalesced'}
                subprocess.Popen([sys.executable,SCRIPT,'iface-recover',event['id'],str(gate.fileno())],pass_fds=(gate.fileno(),),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
    return {'ok':True,'reason':'recorded'}


def interface_event_worker(event_id, worker_fd=None):
    """One inherited lock owns the queue; new events extend its debounce."""
    if worker_fd is None:
        gate=open(RUN/'interface-worker.lock','a')
        try:
            fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            gate.close()
            return {'ok':True,'reason':'worker-active'}
    else:
        gate=os.fdopen(worker_fd,'a')
    try:
        while True:
            event=read_json(RUN/'interface-event.json',{})
            current=state()
            delay=current['settings']['interface_reload_delay_ms']/1000
            deadline=event.get('monotonic',time.monotonic())+delay
            remaining=deadline-time.monotonic()
            if remaining>0:
                time.sleep(remaining)
            with locked(block=True):
                latest=read_json(RUN/'interface-event.json',{})
                if latest.get('id')!=event.get('id'):
                    continue
                if active_job().get('status') in ('queued','running'):
                    result={'ok':True,'reason':'superseded-or-busy'}
                else:
                    result=interface_recover(state(),lock_held=True)
                    atomic(RUN/'watchdog.json',dict(result,at=int(time.time())))
            # Release the worker gate while writers are excluded, so a final
            # arriving event either stays in this loop or starts a new worker.
            with named_lock('interface-event.lock', True):
                if read_json(RUN/'interface-event.json',{}).get('id')!=event.get('id'):
                    continue
                gate.close()
                return result
    finally:
        gate.close()


def interface_recover(current, lock_held=False):
    with contextlib.nullcontext() if lock_held else locked(block=True):
        return _interface_recover(current)


def _interface_recover(current):
    """Restart Atlas after an enabled monitored network interface returns."""
    settings = current['settings']
    if not settings['interface_monitoring'] or not service_running():
        return {'ok':True,'reason':'inactive'}
    event = read_json(RUN / 'interface-event.json', {})
    if event.get('action') != 'ifup' or event.get('interface') not in settings['monitored_interfaces']:
        return {'ok':True,'reason':'no-interface-up-event'}
    last = read_json(RUN / 'interface-handled.json', {})
    if not event.get('id') or event.get('id') == last.get('id'):
        return {'ok':True,'reason':'already-handled'}
    stamp=int(time.time())
    attempts=[x for x in read_json(RUN/'recovery.json',{}).get('attempts',[]) if type(x) is int and stamp-x<600]
    if len(attempts)>=3:
        return {'ok':False,'reason':'restart-limit'}
    attempts.append(stamp);atomic(RUN/'recovery.json',{'attempts':attempts})
    try:
        result=run(['/etc/init.d/atlas','restart'],90)
        ok=result.returncode==0 and wait_engine_ready()
    except (OSError,subprocess.TimeoutExpired):
        ok=False
    if ok:
        atomic(RUN/'interface-handled.json',{'id':event['id'],'at':event['at'],'interface':event['interface']})
    return {'ok':ok,'reason':'interface-restarted' if ok else 'restart-failed'}


def run(args, timeout=15):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def service_running(name='atlas'):
    try:
        r = run(['/bin/ubus', 'call', 'service', 'list', json.dumps({'name': name})], 3)
        obj = json.loads(r.stdout)
        return any(x.get('running') for x in obj.get(name, {}).get('instances', {}).values())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def engine_version():
    try:
        r = run([BINARY, 'version'], 4)
        return r.stdout.decode().splitlines()[0][:100] if r.returncode == 0 else None
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return None


def system_interfaces():
    try:
        return {p.name for p in Path('/sys/class/net').iterdir() if re.fullmatch('[A-Za-z0-9_.:-]{1,15}', p.name)}
    except OSError:
        return set()


def source_interface_networks(interface):
    """Resolve an incoming LAN interface to its current client subnets."""
    if not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', interface) or interface in ('lo', 'atlas0'):
        raise AtlasError('Недопустимое имя входного интерфейса')
    try:
        result = run(['/sbin/ip', '-j', 'address', 'show', 'dev', interface], 4)
        if result.returncode:
            return []
        objects = json.loads(result.stdout)
        networks = []
        for obj in objects:
            for address in obj.get('addr_info', []):
                if address.get('family') not in ('inet', 'inet6'):
                    continue
                local, prefix = address.get('local'), address.get('prefixlen')
                try:
                    parsed = ipaddress.ip_interface('%s/%d' % (local, int(prefix)))
                    if parsed.ip.is_link_local or parsed.ip.is_multicast or parsed.ip.is_unspecified:
                        continue
                    network = str(parsed.network)
                except (ValueError, TypeError):
                    continue
                if network not in networks:
                    networks.append(network)
        return networks
    except (AtlasError, OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return []


def manage_kill_switch(enabled):
    """Maintain one named fw4 rule that blocks LAN-to-WAN fallback traffic."""
    uci = '/sbin/uci'
    section = 'firewall.atlas_kill_switch'
    if enabled:
        result = run([uci, 'set', section + '=rule'], 5)
        if result.returncode:
            run([uci, 'revert', 'firewall'], 5)
            raise AtlasError('Не удалось создать fail-closed правило firewall4')
        for option, value in (('name', 'Atlas fail-closed'), ('src', 'lan'),
                              ('dest', 'wan'), ('proto', 'all'), ('target', 'DROP'), ('enabled', '1')):
            result = run([uci, 'set', '%s.%s=%s' % (section, option, value)], 5)
            if result.returncode:
                run([uci, 'revert', 'firewall'], 5)
                raise AtlasError('Не удалось настроить fail-closed правило firewall4')
        result = run([uci, 'commit', 'firewall'], 5)
        if result.returncode:
            run([uci, 'revert', 'firewall'], 5)
            raise AtlasError('Не удалось сохранить fail-closed правило firewall4')
        reload_result = run(['/etc/init.d/firewall', 'reload'], 20)
        if reload_result.returncode:
            raise AtlasError('Правило сохранено, но firewall4 не подтвердил перезагрузку; проверьте firewall')
        return
    result = run([uci, '-q', 'delete', section], 5)
    if result.returncode:
        return
    if run([uci, 'commit', 'firewall'], 5).returncode:
        raise AtlasError('Не удалось удалить fail-closed правило firewall4')
    if run(['/etc/init.d/firewall', 'reload'], 20).returncode:
        raise AtlasError('Правило удалено из UCI, но firewall4 не подтвердил перезагрузку')


def kill_switch_active():
    try:
        values = {}
        for key in ('target', 'src', 'dest', 'enabled'):
            result = run(['/sbin/uci', '-q', 'get', 'firewall.atlas_kill_switch.' + key], 3)
            values[key] = result.stdout.decode().strip() if result.returncode == 0 else ''
        return values == {'target': 'DROP', 'src': 'lan', 'dest': 'wan', 'enabled': '1'}
    except (AtlasError, OSError, subprocess.TimeoutExpired):
        return False


def manage_ingress_firewall(enabled):
    """Allow forwarding only into the named Atlas scoped TUN devices."""
    existing = run(['/sbin/uci','-q','get','firewall.atlas_ingress'],5).returncode == 0
    if not enabled and not existing:return
    for section in ('atlas_ingress','atlas_ingress_capture'):
        run(['/sbin/uci','-q','delete','firewall.'+section],5)
    if enabled:
        values = [('atlas_ingress','=zone'),('atlas_ingress.name','=atlas_ingress'),
                  ('atlas_ingress.input','=ACCEPT'),('atlas_ingress.output','=ACCEPT'),
                  ('atlas_ingress.forward','=ACCEPT'),('atlas_ingress_capture','=rule'),
                  ('atlas_ingress_capture.name','=Atlas scoped TUN capture'),
                  ('atlas_ingress_capture.src','=*'),('atlas_ingress_capture.dest','=atlas_ingress'),
                  ('atlas_ingress_capture.proto','=all'),('atlas_ingress_capture.target','=ACCEPT')]
        for name,value in values:
            if run(['/sbin/uci','set','firewall.'+name+value],5).returncode:
                raise AtlasError('Не удалось настроить firewall входных интерфейсов')
        if run(['/sbin/uci','add_list','firewall.atlas_ingress.device=atli+'],5).returncode:
            raise AtlasError('Не удалось зарегистрировать scoped TUN в firewall')
    if run(['/sbin/uci','commit','firewall'],5).returncode or run(['/etc/init.d/firewall','reload'],20).returncode:
        raise AtlasError('Не удалось применить firewall входных интерфейсов')


DHCP_BACKUP = DATA / 'dhcp-dns-backup.json'
DHCP_MANAGED = {'server': ['127.0.0.42'], 'noresolv': ['1'], 'cachesize': ['0']}


def dnsmasq_config():
    result = run(['/sbin/uci', '-q', 'show', 'dhcp'], 5)
    if result.returncode:
        raise AtlasError('Не удалось прочитать конфигурацию DHCP/dnsmasq')
    raw = result.stdout.decode('utf-8', 'strict')
    selectors = []
    for line in raw.splitlines():
        match = re.match(r'^dhcp\.(@dnsmasq\[\d+\]|[A-Za-z0-9_-]+)=dnsmasq$', line)
        if match:
            selectors.append(match.group(1))
    config = {selector: {'server': [], 'noresolv': [], 'cachesize': []} for selector in selectors}
    for line in raw.splitlines():
        try:
            fields = shlex.split(line, posix=True, comments=False)
        except (ValueError,RecursionError) as exc:
            raise AtlasError('Конфигурация dnsmasq содержит некорректное значение') from exc
        if not fields:
            continue
        key, sep, value = fields[0].partition('=')
        if not sep:
            continue
        match = re.match(r'^dhcp\.(@dnsmasq\[\d+\]|[A-Za-z0-9_-]+)\.(server|noresolv|cachesize)$', key)
        if match and match.group(1) in config:
            config[match.group(1)][match.group(2)].append(value)
    return config


def set_dnsmasq_option(selector, name, values):
    key = 'dhcp.%s.%s' % (selector, name)
    result = run(['/sbin/uci', '-q', 'delete', key], 5)
    # A missing option is the expected state before the first assignment.
    if values:
        command = 'add_list' if name == 'server' else 'set'
        for value in values if name == 'server' else values[-1:]:
            result = run(['/sbin/uci', command, '%s=%s' % (key, value)], 5)
            if result.returncode:
                raise AtlasError('Не удалось обновить параметр dnsmasq %s' % name)


def commit_dnsmasq():
    result = run(['/sbin/uci', 'commit', 'dhcp'], 5)
    if result.returncode:
        raise AtlasError('Не удалось сохранить конфигурацию dnsmasq')
    result = run(['/etc/init.d/dnsmasq', 'restart'], 20)
    if result.returncode:
        raise AtlasError('dnsmasq не перезапустился; проверьте настройки DNS')


def manage_dhcp_dns(enabled):
    """Optionally point dnsmasq to sing-box, preserving/restoring its exact prior options."""
    if type(enabled) is not bool:
        raise AtlasError('Некорректный режим DNS для dnsmasq')
    backup = read_json(DHCP_BACKUP, None)
    config = dnsmasq_config()
    if not config:
        if enabled:
            raise AtlasError('В UCI не найден раздел dnsmasq для подключения DNS sing-box')
        return {'enabled': False, 'restored': False, 'changed_by_admin': []}
    if enabled:
        if backup:
            if not isinstance(backup, dict) or not isinstance(backup.get('sections'), list) or len(backup['sections']) != len(config):
                raise AtlasError('Состав dnsmasq изменился; отключите управление DNS и восстановите параметры вручную')
            for entry in backup['sections']:
                if config.get(entry.get('section')) != DHCP_MANAGED:
                    raise AtlasError('Параметры dnsmasq изменены вручную; выключите и снова включите управление DNS')
            return {'enabled': True, 'restored': False, 'changed_by_admin': []}
        sections = []
        for selector, values in config.items():
            sections.append({'section': selector, 'options': {
                name: {'present': bool(values[name]), 'values': values[name]}
                for name in ('server', 'noresolv', 'cachesize')}})
        atomic(DHCP_BACKUP, {'sections': sections})
        try:
            for selector in config:
                for name, values in DHCP_MANAGED.items():
                    set_dnsmasq_option(selector, name, values)
            commit_dnsmasq()
        except (AtlasError, OSError, subprocess.TimeoutExpired):
            for entry in sections:
                for name, original in entry['options'].items():
                    set_dnsmasq_option(entry['section'], name, original['values'] if original['present'] else [])
            run(['/sbin/uci', 'commit', 'dhcp'], 5)
            run(['/etc/init.d/dnsmasq', 'restart'], 20)
            DHCP_BACKUP.unlink(missing_ok=True)
            raise
        return {'enabled': True, 'restored': False, 'changed_by_admin': []}
    if not backup:
        return {'enabled': False, 'restored': False, 'changed_by_admin': []}
    saved = backup.get('sections', []) if isinstance(backup, dict) else []
    if len(saved) != len(config):
        raise AtlasError('Состав dnsmasq изменился; резервная копия сохранена для ручного восстановления')
    changed_by_admin, changed = [], False
    for entry in saved:
        selector = entry.get('section')
        if selector not in config:
            raise AtlasError('Раздел dnsmasq изменился; резервная копия сохранена')
        for name, managed_values in DHCP_MANAGED.items():
            if config[selector].get(name) != managed_values:
                changed_by_admin.append('%s.%s' % (selector, name))
                continue
            original = entry['options'][name]
            set_dnsmasq_option(selector, name, original.get('values', []) if original.get('present') else [])
            changed = True
    if changed:
        commit_dnsmasq()
    DHCP_BACKUP.unlink(missing_ok=True)
    return {'enabled': False, 'restored': changed, 'changed_by_admin': changed_by_admin}


def dhcp_dns_active():
    try:
        config = dnsmasq_config()
        return bool(config) and all(values == DHCP_MANAGED for values in config.values())
    except (AtlasError, OSError, subprocess.TimeoutExpired):
        return False


def check(config):
    fd, path = tempfile.mkstemp(prefix='check-', suffix='.json', dir=RUN)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)
        try:
            r = run([BINARY, 'check', '-c', path], 15)
        except FileNotFoundError as exc:
            raise AtlasError('sing-box не установлен') from exc
        if r.returncode:
            # Engine diagnostics can contain passwords/UUIDs. Never expose raw output via RPC.
            raise AtlasError('sing-box отклонил конфигурацию. Проверьте версию (нужна 1.12+) и формат узлов.')
    finally:
        os.unlink(path)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        subscription_url(newurl)
        old = urlsplit(req.full_url)
        new = urlsplit(newurl)
        old_origin = (old.hostname.lower(), old.port or 443)
        new_origin = (new.hostname.lower(), new.port or 443)
        if old_origin != new_origin:
            raise AtlasError('Подписка перенаправлена на другой сервер. Проверьте URL у провайдера.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def require_public_https(url, allow_private=False):
    """Reject private/reserved destinations for admin-configured remote lists."""
    parsed = urlsplit(rule_list_url(url, allow_private=allow_private))
    try:
        literal = ipaddress.ip_address(parsed.hostname)
        addresses = [literal]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme=='https' else 80), type=socket.SOCK_STREAM)]
        except (OSError, ValueError) as exc:
            raise AtlasError('Не удалось разрешить публичный адрес списка') from exc
    if not addresses or (not allow_private and any(not address.is_global for address in addresses)):
        raise AtlasError('Список правил должен находиться на публичном HTTPS сервере')
    return url


class PublicHTTPSRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    def __init__(self, allow_private=False):
        super().__init__()
        self.allow_private = allow_private
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(req.full_url).scheme=='https' and urlsplit(newurl).scheme!='https':
            raise AtlasError('HTTPS список не должен перенаправляться на HTTP')
        require_public_https(newurl, allow_private=self.allow_private)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_rule_list(body, fmt='auto', max_bytes=MAX_BYTES):
    """Parse plain domains, hosts, CIDRs, AdGuard lines, and sing-box JSON rules."""
    try:
        source = body.decode('utf-8-sig') if isinstance(body, bytes) else str(body)
    except UnicodeError as exc:
        raise AtlasError('Список правил должен быть в UTF-8') from exc
    if max_bytes and len(source.encode('utf-8')) > max_bytes:
        raise AtlasError('Файл списка правил слишком большой')
    domains, cidrs, seen = [], [], set()
    def add_domain(value):
        value = value.strip().lower().rstrip('.')
        if value.startswith('*.'):
            value = value[2:]
        if not value or value == 'localhost' or '/' in value:
            return
        try:
            ipaddress.ip_address(value)
            return
        except ValueError:
            pass
        try:
            import core
            value = core.host(value)
        except AtlasError:
            return
        if '.' not in value:
            return
        key = ('d', value)
        if key not in seen:
            seen.add(key); domains.append(value)
    if fmt == 'json' or (fmt == 'auto' and source.lstrip().startswith('{')):
        try:
            obj = json.loads(source)
        except (ValueError,RecursionError) as exc:
            raise AtlasError('Некорректный JSON список правил') from exc
        if not isinstance(obj, dict) or not isinstance(obj.get('rules'), list) or len(obj['rules']) > MAX_RULE_LIST_ENTRIES:
            raise AtlasError('JSON список должен содержать массив rules')
        return obj  # Preserve every engine-supported field and logical structure.
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#','!',';','[')):
            continue
        if fmt in ('auto','adguard') and line.startswith('||'):
            candidate = line[2:].split('^', 1)[0].split('|', 1)[0]
            if candidate and not any(ch in candidate for ch in '*$^/'):
                add_domain(candidate)
            continue
        if fmt in ('auto','cidrs'):
            try:
                network = str(ipaddress.ip_network(line, strict=False))
                key = ('c', network)
                if key not in seen:
                    seen.add(key); cidrs.append(network)
                continue
            except ValueError:
                if fmt == 'cidrs':
                    continue
        fields = line.split()
        if fmt in ('hosts','auto') and len(fields) >= 2:
            try:
                ipaddress.ip_address(fields[0])
                for item in fields[1:]:
                    if not item.startswith('#'):
                        add_domain(item)
                continue
            except ValueError:
                if fmt == 'hosts':
                    continue
        if fmt in ('domains','auto','adguard'):
            if len(fields) == 1:
                add_domain(fields[0])
    if len(domains) + len(cidrs) > MAX_RULE_LIST_ENTRIES:
        raise AtlasError('Список правил превышает 10000 записей')
    if not domains and not cidrs:
        raise AtlasError('В списке правил не найдено поддерживаемых записей')
    return domains, cidrs


def fetch_rule_proxy_url():
    """Return the authenticated loopback-only proxy from the active config, or fail closed."""
    if not service_running():
        raise AtlasError('Сначала запустите Atlas: загрузка списков через прокси не переключается на прямое соединение')
    config = read_json(CONFIG, {})
    inbound = next((x for x in config.get('inbounds', []) if isinstance(x, dict) and x.get('tag') == 'list-fetch'), None)
    if not inbound or inbound.get('type') != 'mixed' or inbound.get('listen') != '127.0.0.1':
        raise AtlasError('Примените Atlas с включённой загрузкой списков через прокси')
    port = inbound.get('listen_port')
    users = inbound.get('users')
    if type(port) is not int or not 1024 <= port <= 65535 or not isinstance(users, list) or len(users) != 1:
        raise AtlasError('Loopback proxy для списков некорректен; примените настройки повторно')
    username, password = users[0].get('username'), users[0].get('password')
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        raise AtlasError('Не заданы учётные данные loopback proxy')
    from urllib.parse import quote
    return 'http://%s:%s@127.0.0.1:%d' % (quote(username, safe=''), quote(password, safe=''), port)


def local_rule_bytes(url, allow_symlinks=False, max_bytes=MAX_BYTES):
    rule_list_url(url)
    path = Path(urlsplit(url).path)
    if not allow_symlinks and (path.is_symlink() or any(x.is_symlink() for x in path.parents)):
        raise AtlasError('Символьные ссылки для локального списка запрещены')
    if allow_symlinks:
        try:
            path = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise AtlasError('Не удалось разрешить символьную ссылку списка') from exc
    if not path.is_file():
        raise AtlasError('Локальный список не найден')
    try:
        with path.open('rb') as stream:
            body = stream.read(max_bytes + 1 if max_bytes else -1)
    except OSError as exc:
        raise AtlasError('Не удалось прочитать локальный список') from exc
    if max_bytes and len(body) > max_bytes:
        raise AtlasError('Локальный список больше 4 МиБ')
    return body


def local_rule_version(url):
    if not url.startswith('file:///'):
        return ''
    try:
        stat = Path(urlsplit(url).path).stat()
        return '%d:%d' % (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return 'missing'


def fetch_rule_bytes(url, proxy_url=None, allow_private=False, allow_symlinks=False, max_bytes=MAX_BYTES):
    if url.startswith('file:///'):
        return local_rule_bytes(url, allow_symlinks=allow_symlinks, max_bytes=max_bytes)
    deadline = time.monotonic() + 90
    for attempt in range(3):
        try:
            require_public_https(url, allow_private=allow_private)
            handler = urllib.request.ProxyHandler({'http':proxy_url,'https':proxy_url}) if proxy_url else urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(handler, PublicHTTPSRedirect(allow_private=allow_private))
            request = urllib.request.Request(url,headers={'User-Agent':'Atlas/OpenWrt rule-list','Accept':'*/*','Accept-Encoding':'identity'})
            with opener.open(request,timeout=max(1,min(20,deadline-time.monotonic()))) as response:
                if urlsplit(url).scheme=='https' and urlsplit(response.geturl()).scheme!='https':
                    raise AtlasError('HTTPS список перенаправлен на HTTP')
                chunks,total=[],0
                while True:
                    if time.monotonic()>deadline:raise AtlasError('Превышено время загрузки списка')
                    part=response.read(16384)
                    if not part:break
                    total+=len(part)
                    if max_bytes and total>max_bytes:raise AtlasError('Список превышает настроенный размер файла')
                    chunks.append(part)
                return b''.join(chunks)
        except urllib.error.HTTPError as exc:
            if exc.code not in (408,429) and exc.code<500:
                raise AtlasError('Сервер списка вернул HTTP %d'%exc.code) from exc
            failure=exc
        except (urllib.error.URLError,OSError) as exc:
            failure=exc
        except AtlasError as exc:
            if not isinstance(exc.__cause__,OSError):raise
            failure=exc
        if attempt==2 or time.monotonic()+2>=deadline:
            raise AtlasError('Не удалось загрузить список после повторных попыток') from failure
        time.sleep(2)


def fetch_rule_list(url, fmt, proxy_url=None, allow_private=False, allow_symlinks=False, max_bytes=MAX_BYTES):
    return parse_rule_list(fetch_rule_bytes(url,proxy_url,allow_private,allow_symlinks,max_bytes),fmt,max_bytes=max_bytes)


def fetch_rule_set(url, proxy_url=None, allow_private=False, allow_symlinks=False, max_bytes=MAX_BYTES):
    body=fetch_rule_bytes(url,proxy_url,allow_private,allow_symlinks,max_bytes)
    if len(body)<16:raise AtlasError('Файл слишком мал для SRS')
    return body


def validate_source_rules(body):
    fd,name=tempfile.mkstemp(prefix='rules-check-',suffix='.json',dir=RUN)
    path=Path(name);compiled=path.with_suffix('.srs')
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(body)
        result=run([BINARY,'rule-set','compile',str(path),'-o',str(compiled)],45)
        if result.returncode:raise AtlasError('sing-box отклонил JSON ruleset')
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AtlasError('Не удалось проверить JSON ruleset движком') from exc
    finally:
        path.unlink(missing_ok=True);compiled.unlink(missing_ok=True)


def store_rule_set(current, item, body, source=False):
    if source:validate_source_rules(body)
    target=DATA/'rules'/(item['id']+('.json' if source else '.srs'))
    previous=target.read_bytes() if target.exists() else None
    previous_item=copy.deepcopy(item)
    atomic_bytes(target,body)
    item.update(source_cached=source,srs_cached=not source,domains=[],cidrs=[])
    if source:item['source_rules']=json.loads(body)
    else:item.pop('source_rules',None)
    try:
        check(make_config(current))
    except (AtlasError,OSError,subprocess.TimeoutExpired) as exc:
        if previous is None:target.unlink(missing_ok=True)
        else:atomic_bytes(target,previous)
        item.clear();item.update(previous_item)
        if isinstance(exc,AtlasError):raise
        raise AtlasError('Не удалось проверить набор правил движком') from exc


def _validator(value):
    if not value:
        return ''
    try:
        return text(value, 512)
    except AtlasError:
        return ''


def fetch(url, headers=None, etag='', last_modified=''):
    url = subscription_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect())
    request_headers = {'User-Agent': 'sing-box/Atlas-0.12', 'Accept': 'text/plain, application/json, application/yaml, text/yaml, */*', 'Accept-Encoding': 'identity'}
    request_headers.update(headers or {})
    if etag:
        request_headers['If-None-Match'] = etag
    if last_modified:
        request_headers['If-Modified-Since'] = last_modified
    try:
        req = urllib.request.Request(url, headers=request_headers)
        with opener.open(req, timeout=20) as response:
            deadline = time.monotonic() + 45
            chunks, total = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise AtlasError('Превышено время загрузки подписки')
                part = response.read(16384)
                if not part:
                    break
                total += len(part)
                if total > MAX_BYTES:
                    raise AtlasError('Подписка больше 4 МиБ')
                chunks.append(part)
            metadata = {}
            for part in response.headers.get('subscription-userinfo', '').split(';'):
                key, sep, value = part.strip().partition('=')
                if key in ('upload', 'download', 'total', 'expire') and sep and value.isdigit():
                    metadata[key] = int(value)
            from happ import decrypt_body, HappError
            try:
                body = decrypt_body(response.geturl(), b''.join(chunks), response.headers.get('encrypt-tag'))
            except HappError as exc:
                raise AtlasError(str(exc)) from exc
            return body, metadata, _validator(response.headers.get('ETag')), _validator(response.headers.get('Last-Modified')), False
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            validators = (_validator(exc.headers.get('ETag') if exc.headers else '') or etag,
                          _validator(exc.headers.get('Last-Modified') if exc.headers else '') or last_modified)
            exc.close()
            return None, {}, validators[0], validators[1], True
        exc.close()
        raise AtlasError('Сервер подписки вернул HTTP %d' % exc.code) from exc
    except AtlasError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if isinstance(exc, AtlasError):
            raise
        reason = getattr(exc, 'reason', exc)
        if isinstance(reason, socket.gaierror):
            message = 'Не удалось разрешить DNS-имя сервера подписки'
        elif isinstance(reason, (TimeoutError, socket.timeout)):
            message = 'Истекло время ожидания ответа сервера подписки'
        elif reason.__class__.__name__ in ('SSLCertVerificationError', 'CertificateError'):
            message = 'Ошибка TLS-сертификата сервера подписки; проверьте время роутера и сертификат'
        else:
            message = 'Не удалось подключиться к серверу подписки: проверьте сеть, TLS и время роутера'
        raise AtlasError(message) from exc


def apply(current, enable=False):
    for name in ('podkop', 'sing-box', 'passwall', 'passwall2', 'openclash'):
        if service_running(name):
            raise AtlasError('Работает %s. Сначала отключите конфликтующий сервис.' % name)
    candidate = runtime_config(current)
    required_interfaces = {section['interface'] for section in current['settings'].get('sections', []) if section.get('policy') == 'interface' and section.get('enabled', True)}
    required_interfaces.update(interface for section in current['settings'].get('sections', [])
                               for interface in section.get('source_interfaces', []) if section.get('enabled', True))
    if current['settings'].get('default_interface'):
        required_interfaces.add(current['settings']['default_interface'])
    missing = sorted(required_interfaces - system_interfaces())
    if missing:
        raise AtlasError('VPN-интерфейс не найден: %s' % ', '.join(missing))
    check(candidate)
    old = CONFIG.read_bytes() if CONFIG.exists() else None
    was_running = service_running()
    atomic(CONFIG, candidate)
    try:
        r = run(['/etc/init.d/atlas', 'restart'], 90)
        if r.returncode:
            raise AtlasError('Не удалось запустить сервис')
        for _ in range(60):
            time.sleep(.4)
            if service_running():
                # procd can report the Python launcher before exec and engine startup.
                try:
                    ready = isinstance(clash_request('GET', '/proxies', timeout=1).get('proxies'), dict)
                except (OSError, AtlasError, http.client.HTTPException):
                    ready = False
                if ready and service_running():
                    if enable:
                        run(['/etc/init.d/atlas', 'enable'])
                    config_store = stored_config_dir(current['settings'])
                    atomic(config_store / 'active.json', candidate)
                    atomic(config_store / 'last-good.json', candidate)
                    atomic(RUN / 'applied.json', {'at': int(time.time())})
                    maintain_artifacts(current)
                    return
        raise AtlasError('sing-box не запустился; восстановлена предыдущая конфигурация')
    except Exception as exc:
        if old is not None:
            atomic(CONFIG, json.loads(old))
        else:
            CONFIG.unlink(missing_ok=True)
        run(['/etc/init.d/atlas', 'stop'], 60)
        if was_running and old is not None:
            run(['/etc/init.d/atlas', 'start'], 90)
        if isinstance(exc,subprocess.TimeoutExpired):
            raise AtlasError('Истекло время запуска службы; восстановлена предыдущая конфигурация') from exc
        raise


def refresh(current, sub_id=''):
    found = False
    successes, failures, list_successes = 0, [], 0
    for sub in current['subscriptions']:
        if sub_id and sub['id'] != sub_id:
            continue
        if not sub.get('enabled', True):
            continue
        if sub.get('source') == 'local':
            continue
        found = True
        try:
            fetched = fetch(sub['url'], sub.get('headers', {}), sub.get('etag', ''), sub.get('last_modified', ''))
            if len(fetched) == 2:  # Keep existing integrations and test doubles compatible.
                body, meta = fetched
                etag, last_modified, not_modified = sub.get('etag', ''), sub.get('last_modified', ''), False
            else:
                body, meta, etag, last_modified, not_modified = fetched
            if not_modified:
                sub.update({'updated': int(time.time()), 'etag': etag, 'last_modified': last_modified, 'error': ''})
                sub['change'] = {'added': 0, 'removed': 0, 'total': len(sub.get('nodes', [])), 'unchanged': True}
                successes += 1
                continue
            parsed = parse_subscription(body)
            old_nodes = {x.get('id'): x for x in sub.get('nodes', [])}
            for node in parsed['nodes']:
                previous = old_nodes.get(node['id'], {})
                for key in ('verified_country', 'country_verified_at'):
                    if key in previous:
                        node[key] = previous[key]
            old_ids = {x.get('id') for x in sub.get('nodes', [])}
            new_ids = {x.get('id') for x in parsed['nodes']}
            proposed = copy.deepcopy(current)
            dest = next(x for x in proposed['subscriptions'] if x['id'] == sub['id'])
            dest.update(parsed)
            if sum(len(x.get('nodes', [])) for x in proposed['subscriptions']) > MAX_TOTAL_NODES:
                raise AtlasError('Общий архив превышает 4096 профилей. Удалите старые или лишние подписки.')
            # Validate each subscription independently, even if selection points to an old node.
            validation = defaults()
            validation['subscriptions'] = [dest]
            check(make_config(validation, tun=False))
            sub.update(parsed)
            sub.update({'updated': int(time.time()), 'metadata': meta, 'error': '', 'etag': etag,
                        'last_modified': last_modified,
                        'change': {'added': len(new_ids - old_ids), 'removed': len(old_ids - new_ids),
                                   'total': len(new_ids), 'unchanged': not (new_ids - old_ids or old_ids - new_ids)}})
            successes += 1
        except AtlasError as exc:
            sub['error'] = str(exc)
            failures.append(sub['name'])
    if not sub_id:
        for rule_list in current['settings']['remote_lists']:
            if not rule_list['enabled']:
                continue
            found = True
            try:
                file_version = local_rule_version(rule_list['url'])
                list_proxy = fetch_rule_proxy_url() if current['settings'].get('fetch_lists_via_proxy') else None
                permissions = {flag:rule_list.get(flag,False) for flag in ('allow_private','allow_symlinks')}
                if current['settings'].get('list_max_bytes',MAX_BYTES)!=MAX_BYTES:
                    permissions['max_bytes']=current['settings']['list_max_bytes']
                if rule_list['format']=='srs':
                    store_rule_set(current,rule_list,fetch_rule_set(rule_list['url'],proxy_url=list_proxy,**permissions))
                    rule_list.update(count=0)
                else:
                    parsed=fetch_rule_list(rule_list['url'],rule_list['format'],proxy_url=list_proxy,**permissions)
                    if isinstance(parsed,dict):
                        store_rule_set(current,rule_list,json.dumps(parsed).encode(),source=True)
                        rule_list.update(count=len(parsed['rules']))
                    else:
                        domains,cidrs=parsed
                        rule_list.update(source_cached=False,domains=domains,cidrs=cidrs)
                        rule_list.pop('source_rules',None)
                rule_list.update(file_version=file_version,updated=int(time.time()),error='')
                list_successes += 1
            except AtlasError as exc:
                # Keep last known good rules when a list server is temporarily unavailable.
                rule_list['error'] = text(str(exc), 160)
                failures.append(rule_list['name'])
    if not found:
        if any(x.get('source') == 'local' and x.get('enabled', True) and
               (not sub_id or x['id'] == sub_id) for x in current['subscriptions']):
            return 'Локальные профили не требуют сетевого обновления'
        raise AtlasError('Нет включённых подписок или списков правил для обновления')
    atomic(STATE, current)
    if (successes or list_successes) and service_running():
        apply(current)
    maintain_artifacts(current)
    if failures:
        raise AtlasError('Не обновлено источников: %d. Предыдущие узлы и правила сохранены; подробности в карточках.' % len(failures))
    return 'Обновлено подписок: %d, списков правил: %d' % (successes, list_successes)


def probe(node, binary=BINARY, directory=RUN, settings=None):
    """Real HTTPS request through a dedicated loopback mixed inbound, no TUN."""
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        listen_port = s.getsockname()[1]
    active_settings = validate_settings(settings or defaults()['settings'])
    config = make_config({'settings': active_settings, 'subscriptions': []}, tun=False,
                         mixed_port=listen_port, probe_node=node)
    test_url = urlsplit(active_settings['urltest_url'])
    test_host = test_url.hostname
    test_port = test_url.port or 443
    test_path = test_url.path or '/'
    if test_url.query:
        test_path += '?' + test_url.query
    with tempfile.TemporaryDirectory(prefix='probe-', dir=directory) as tmp:
        path = Path(tmp) / 'config.json'
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        logfile = open(Path(tmp) / 'engine.log', 'w+b')
        process = subprocess.Popen([binary, 'run', '-c', str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=logfile)
        stage = 'engine'
        try:
            for _ in range(30):
                if process.poll() is not None:
                    logfile.seek(0)
                    diagnostic = logfile.read(16384).lower()
                    if b'operation not permitted' in diagnostic or b'permission denied' in diagnostic:
                        raise AtlasError('Система запретила сетевой запуск sing-box; соединение с сервером ещё не проверялось')
                    raise AtlasError('Тестовый sing-box не запустился')
                try:
                    with socket.create_connection(('127.0.0.1', listen_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise AtlasError('Тестовый sing-box не открыл локальный порт')
            # Explicit CONNECT avoids urllib bypass rules and never changes proxy environment.
            import ssl
            start = time.monotonic()
            stage = 'https'
            connection = http.client.HTTPSConnection('127.0.0.1', listen_port, timeout=12, context=ssl.create_default_context())
            connection.set_tunnel(test_host, test_port)
            try:
                connection.request('GET', test_path, headers={'Host': test_host, 'Connection': 'close'})
                response = connection.getresponse()
                if not 200 <= response.status < 300:
                    raise AtlasError('Проверочный URL вернул HTTP %d' % response.status)
                return {'ok': True, 'stage': 'https', 'latency_ms': round((time.monotonic() - start) * 1000), 'checked': int(time.time()), 'http': response.status}
            finally:
                connection.close()
        except AtlasError as exc:
            return {'ok': False, 'stage': stage, 'checked': int(time.time()), 'error': str(exc)}
        except (OSError, http.client.HTTPException):
            return {'ok': False, 'stage': stage, 'checked': int(time.time()), 'error': 'HTTPS через узел не прошёл (сеть, TLS или параметры узла)'}
        finally:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            logfile.close()


def direct_public_ip():
    # Bind an isolated direct outbound to OpenWrt's WAN, so the baseline cannot
    # accidentally use the active Atlas TUN or an environment proxy.
    reply = run(['ubus', 'call', 'network.interface.wan', 'status'], 8)
    if reply.returncode:
        raise AtlasError('Не удалось определить WAN для сравнения выходного IP')
    try:
        status = json.loads(reply.stdout)
        interface = status.get('l3_device', '')
    except (ValueError, AttributeError):
        raise AtlasError('Некорректный ответ состояния WAN')
    if not status.get('up') or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', interface) or interface == 'atlas0':
        raise AtlasError('Для сравнения IP нужен активный WAN интерфейс')
    baseline = {'id': 'f' * 16, 'key': 'f' * 32,
                'outbound': {'type': 'direct', 'bind_interface': interface}}
    body = proxied_https_get(baseline, 'api.ipify.org', '/', 128)
    return str(ipaddress.ip_address(body.decode('ascii').strip()))


def proxied_https_get(node, hostname, request_path, body_limit=256, binary=BINARY, directory=RUN):
    """A bounded TLS request through one isolated outbound; no direct fallback."""
    if (not isinstance(hostname, str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', hostname) or
            hostname.startswith('.') or hostname.endswith('.') or '..' in hostname):
        raise AtlasError('Некорректный адрес сервиса проверки')
    if (not isinstance(request_path, str) or not request_path.startswith('/') or request_path.startswith('//') or
            len(request_path) > 2048 or any(c in request_path for c in ('\\', '\x00', '\r', '\n', '?', '#'))):
        raise AtlasError('Некорректный путь сервиса проверки')
    if type(body_limit) is not int or not 1 <= body_limit <= 4096:
        raise AtlasError('Некорректный предел ответа')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        listen_port = sock.getsockname()[1]
    config = make_config(defaults(), tun=False, mixed_port=listen_port, probe_node=node)
    with tempfile.TemporaryDirectory(prefix='privacy-', dir=directory) as tmp:
        config_path = Path(tmp) / 'config.json'
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        with open(Path(tmp) / 'engine.log', 'w+b') as logfile:
            process = subprocess.Popen([binary, 'run', '-c', str(config_path)], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=logfile)
            try:
                for _ in range(30):
                    if process.poll() is not None:
                        raise AtlasError('Временный тестовый прокси не запустился')
                    try:
                        with socket.create_connection(('127.0.0.1', listen_port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AtlasError('Тестовый прокси не открыл локальный порт')
                import ssl
                connection = http.client.HTTPSConnection('127.0.0.1', listen_port, timeout=15,
                                                          context=ssl.create_default_context())
                connection.set_tunnel(hostname, 443)
                try:
                    connection.request('GET', request_path, headers={'Host': hostname, 'Connection': 'close',
                                                                   'User-Agent': 'Atlas-check/0.12'})
                    response = connection.getresponse()
                    if response.status != 200:
                        raise AtlasError('Проверочный сервис вернул HTTP %d через прокси' % response.status)
                    body = response.read(body_limit + 1)
                    if len(body) > body_limit:
                        raise AtlasError('Ответ сервиса проверки слишком большой')
                    return body
                finally:
                    connection.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def proxied_public_ip(node, binary=BINARY, directory=RUN):
    body = proxied_https_get(node, 'api.ipify.org', '/', 128, binary, directory)
    return str(ipaddress.ip_address(body.decode('ascii').strip()))


def proxied_exit_country(node):
    country = proxied_https_get(node, 'ipapi.co', '/country/', 16).decode('ascii').strip().upper()
    if not re.fullmatch('[A-Z]{2}', country):
        raise AtlasError('Сервис геолокации не вернул код страны')
    return country


def stop_for_country_policy(current):
    """Keep LAN fail-closed and prevent recovery of a disallowed old configuration."""
    manage_kill_switch(True)
    current['settings']['kill_switch'] = True
    atomic(STATE, current)
    run(['/etc/init.d/atlas', 'disable'])
    run(['/etc/init.d/atlas', 'stop'], 20)
    for _ in range(20):
        if not service_running():
            return
        time.sleep(.25)
    raise AtlasError('Fail-closed включён, но остановка старого туннеля не подтверждена')


def enforce_verified_country_policy(current, config):
    settings = current['settings']
    if not settings.get('require_verified_countries') or not any(settings[k] for k in ('countries', 'excluded_countries', 'preferred_countries')):
        return None
    eligible = filter_nodes(all_nodes(current), settings)
    keys = {n['key'] for n in eligible}
    loaded = {out.get('tag') for out in (config or {}).get('outbounds', []) if re.fullmatch('[a-f0-9]{32}', out.get('tag', ''))}
    if loaded <= keys:
        return None
    try:
        selection_nodes(current)
        apply(current)
        return {'ok': True, 'reason': 'country-pool-updated'}
    except (AtlasError, OSError, subprocess.TimeoutExpired):
        stop_for_country_policy(current)
        return {'ok': False, 'reason': 'country-pool-blocked'}


def save_exit_country(current, key, country):
    """Store only ISO code/time and enforce changed country restrictions immediately."""
    if not isinstance(country, str) or not re.fullmatch('[A-Z]{2}', country):
        raise AtlasError('Некорректный результат проверки страны')
    profile = next((n for s in current['subscriptions'] for n in s.get('nodes', []) if s['id'] + n['id'] == key), None)
    if profile is None:
        raise AtlasError('Сервер больше не существует')
    profile.update(verified_country=country, country_verified_at=int(time.time()))
    settings = current['settings']
    has_filter = any(settings[k] for k in ('countries', 'excluded_countries', 'preferred_countries'))
    atomic(STATE, current)
    message = 'Страна выхода: %s; сохранены только код и время проверки' % country
    if has_filter and service_running():
        eligible = filter_nodes(all_nodes(current), settings)
        if settings['selected'] != 'auto' and not any(x['key'] == settings['selected'] for x in eligible):
            settings['selected'] = 'auto'
        try:
            selection_nodes(current)
        except AtlasError:
            # Never keep a now-forbidden exit active or let watchdog restore it.
            stop_for_country_policy(current)
            return message + '. Пул пуст: туннель остановлен, fail-closed включён. Выберите допустимый сервер и запустите Atlas.'
        atomic(STATE, current)
        try:
            apply(current)
        except (AtlasError, OSError, subprocess.TimeoutExpired):
            stop_for_country_policy(current)
            raise AtlasError('Страна проверена, но применить новый пул не удалось. Туннель остановлен с fail-closed.')
        message += '; фильтры применены'
    return message


def _dns_skip_name(packet, offset):
    for _ in range(128):
        if offset >= len(packet):
            break
        size = packet[offset]
        if size == 0:
            return offset + 1
        if size & 0xc0 == 0xc0:
            if offset + 1 < len(packet) and ((size & 0x3f) << 8 | packet[offset + 1]) < len(packet):
                return offset + 2
            break
        if size & 0xc0 or size > 63 or offset + size + 1 > len(packet):
            break
        offset += size + 1
    raise AtlasError('Некорректное DNS имя в ответе')


def query_local_dns_a(name, port=53):
    """Query the actual dnsmasq listener, bypassing libc and negative caches."""
    name = host(name).rstrip('.')
    labels = name.split('.')
    if any(not part or len(part) > 63 for part in labels) or len(name) > 253:
        raise AtlasError('Некорректное тестовое DNS имя')
    txid = secrets.randbits(16)
    qname = b''.join(bytes((len(part),)) + part.encode('ascii') for part in labels) + b'\0'
    query = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect(('127.0.0.1', port))
            sock.send(query)
            packet = sock.recv(4096)
    except OSError:
        raise AtlasError('Локальный dnsmasq не ответил на DNS запрос')
    if len(packet) < 12:
        raise AtlasError('Короткий DNS ответ')
    reply_id, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', packet[:12])
    if (reply_id != txid or not flags & 0x8000 or flags & 0x020f or questions != 1 or answers > 128):
        raise AtlasError('DNS ответ не соответствует запросу или содержит ошибку')
    question_end = _dns_skip_name(packet, 12) + 4
    if question_end > len(packet) or packet[12:question_end] != query[12:]:
        raise AtlasError('DNS ответ содержит другой вопрос')
    offset, result = question_end, []
    for _ in range(answers):
        offset = _dns_skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise AtlasError('Короткая DNS запись')
        record_type, record_class, _, length = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        if offset + length > len(packet):
            raise AtlasError('Короткое DNS значение')
        if record_type == 1 and record_class == 1 and length == 4:
            result.append(str(ipaddress.IPv4Address(packet[offset:offset + length])))
        offset += length
    return result


def privacy_egress_test(node, direct_check=direct_public_ip, proxy_check=proxied_public_ip):
    """Compare direct and selected-node public exits; never retain the IP values."""
    checked = int(time.time())
    try:
        direct = direct_check()
        proxied = proxy_check(node)
        return {'status': 'done', 'ok': direct != proxied, 'same_exit': direct == proxied,
                'checked': checked, 'error': ''}
    except (AtlasError, OSError, ValueError, UnicodeError, urllib.error.URLError,
            http.client.HTTPException, subprocess.TimeoutExpired):
        return {'status': 'error', 'ok': False, 'same_exit': None, 'checked': checked,
                'error': 'Не удалось выполнить внешний тест IP. Адреса ответов не сохраняются.'}


def active_job():
    job = read_json(RUN / 'job.json', {})
    if job.get('status') in ('queued', 'running'):
        try:
            os.kill(job.get('pid', -1), 0)
        except (OSError, TypeError):
            job.update(status='error', message='Операция прервана. Можно повторить.')
    return job


def public_status():
    current = state()
    running = service_running()
    raw_nodes = all_nodes(current)
    eligible = {n['key'] for n in filter_nodes(raw_nodes, current['settings'], validated=True)}
    subscriptions = []
    for sub in current['subscriptions']:
        metadata = sub.get('metadata', {})
        subscriptions.append({k: sub[k] for k in ('id','name','enabled','updated','error','warnings','format') if k in sub})
        local = sub.get('source') == 'local'
        subscriptions[-1].update({'host': 'Локальный импорт' if local else urlsplit(sub.get('url', '')).hostname,
                                  'source': 'local' if local else 'remote', 'count': len(sub.get('nodes', [])),
                                  'metadata': metadata, 'headers_set': bool(sub.get('headers')),
                                  'change': {k: sub.get('change', {}).get(k) for k in ('added','removed','total','unchanged')
                                             if k in sub.get('change', {})}})
    nodes = [{'key': n['key'], 'name': n['name'], 'type': n['outbound']['type'],
              'country': country_for_node(n), 'country_source': country_source_for_node(n),
              'country_verified_at': n.get('country_verified_at', 0), 'eligible': n['key'] in eligible,
              'subscription': n['subscription'], 'server': n['outbound'].get('server',''), 'port': n['outbound'].get('server_port',0)}
             for n in raw_nodes]
    active_config = read_json(stored_config_dir(current['settings']) / 'active.json', {})
    if not active_config:
        fallback = {'id': 'privacy-check', 'key': '0' * 32,
                    'outbound': {'type': 'direct', 'tag': 'privacy-check'}}
        try:
            active_config = make_config(current) if raw_nodes or any(x.get('outbound_config') and x.get('enabled', True) for x in current['settings']['sections']) else make_config(current, tun=False, probe_node=fallback)
        except AtlasError:
            active_config = make_config(current, tun=False, probe_node=fallback)
    privacy = privacy_checks(current['settings'], active_config, running)
    dhcp_enabled = current['settings'].get('dhcp_dns_enabled', False)
    dhcp_active = dhcp_dns_active() if dhcp_enabled else False
    privacy['checks'].append({'id': 'dhcp_dnsmasq', 'ok': not dhcp_enabled or dhcp_active,
                              'label': 'dnsmasq направляет DNS в Atlas' if dhcp_enabled and dhcp_active else
                                       'DNS dnsmasq не перенаправлен в Atlas' if dhcp_enabled else
                                       'Интеграция DNS с dnsmasq выключена'})
    public_settings = copy.deepcopy(current['settings'])
    public_settings.pop('mixed_proxy_password', None)
    for section in public_settings.get('sections', []):
        section['mixed_proxy'].pop('password', None)
        section['outbound_config_set'] = bool(section.pop('outbound_config', []))
    for source in public_settings.get('remote_lists', []):
        parsed = urlsplit(source['url'])
        source['url'] = source['url'] if parsed.scheme == 'file' else '%s://%s/[saved]' % (parsed.scheme, parsed.hostname)
        source['count'] = source.get('count', 0) if rule_set_format(source) else len(source.get('domains', [])) + len(source.get('cidrs', []))
        source.pop('domains', None)
        source.pop('cidrs', None)
        source.pop('source_rules', None)
    return {'ok': True, 'running': running, 'engine': engine_version(), 'engine_features': __import__('engine_features').capabilities(BINARY),
            'subscriptions': subscriptions, 'nodes': nodes, 'interfaces': sorted(system_interfaces()), 'settings': public_settings,
            'runtime': runtime_status(raw_nodes, running), 'eligible_count': len(eligible),
            'checks': read_json(RUN / 'checks.json', {}), 'job': active_job(),
            'applied': read_json(RUN / 'applied.json', {}), 'privacy': privacy,
            'privacy_egress': read_json(RUN / 'privacy-egress.json', {}),
            'selftest': read_json(RUN / 'selftest.json', {}),
            'auto_selection': read_json(RUN / 'auto-selection.json', {}),
            'watchdog': read_json(RUN / 'watchdog.json', {}), 'version': VERSION, 'autostart': os.name=='posix' and os.access('/etc/rc.d/S99atlas',os.X_OK)}


def selftest(current):
    """Separate local functional/privacy checks from the optional public-IP test."""
    cfg = read_json(CONFIG, {})
    running = service_running()
    checks = []
    try:
        check(cfg)
        checks.append({'id':'config','ok':True,'label':'Активная конфигурация проходит sing-box check'})
    except (AtlasError, OSError, subprocess.TimeoutExpired):
        checks.append({'id':'config','ok':False,'label':'sing-box отклоняет активную конфигурацию'})
    checks.append({'id':'service','ok':running,'label':'Процесс Atlas работает' if running else 'Процесс Atlas остановлен'})
    guard_enabled = bool(current['settings'].get('kill_switch'))
    guard_ok = kill_switch_active() if guard_enabled else True
    checks.append({'id':'kill_switch','ok':guard_ok,
                   'label':'Firewall4 блокирует обход LAN → WAN при сбое Atlas' if guard_enabled and guard_ok else
                           'Fail-closed выключен' if not guard_enabled else 'Fail-closed включён в настройках, но firewall4 не подтвердил правило'})
    api_ok = False
    if running:
        try:
            api_ok = isinstance(clash_request().get('proxies'), dict)
        except (AtlasError, OSError, ValueError, http.client.HTTPException):
            pass
    checks.append({'id':'controller','ok':api_ok,'label':'API Atlas отвечает с обязательным ключом' if api_ok else 'Локальный API не отвечает'})
    has_tun = any(x.get('type') == 'tun' for x in cfg.get('inbounds', []))
    tun_ok = not has_tun or 'atlas0' in system_interfaces()
    checks.append({'id':'tun','ok':running and tun_ok,'label':'TUN интерфейс создан' if running and tun_ok else 'TUN интерфейс отсутствует'})
    route_rules = cfg.get('route', {}).get('rules', [])
    checks.append({'id':'dns_hijack','ok':any(x.get('action') == 'hijack-dns' for x in route_rules),
                   'label':'DNS перехват настроен в активной конфигурации'})
    dns_ok = False
    dns_message = 'Запрос через системный DNS роутера не прошёл'
    try:
        # Ask a fresh name to exercise the router resolver instead of a browser cache.
        socket.getaddrinfo('atlas-check-%s.example.com' % secrets.token_hex(6), 443, type=socket.SOCK_STREAM)
        dns_ok, dns_message = True, 'Новый DNS-запрос через роутер получил ответ'
    except socket.gaierror as exc:
        # A negative answer still proves the DNS path is live; only resolver failures fail this check.
        if getattr(exc, 'errno', None) == getattr(socket, 'EAI_NONAME', -2):
            dns_ok, dns_message = True, 'DNS-резолвер ответил (тестовое имя отсутствует, как и ожидается)'
    except OSError:
        pass
    checks.append({'id':'router_dns','ok':dns_ok,'label':dns_message})
    dns = cfg.get('dns', {})
    secure = next((x for x in dns.get('servers', []) if x.get('tag') == 'secure'), {})
    checks.append({'id':'dns_tls','ok':secure.get('type') in ('https','tls') and bool(secure.get('tls',{}).get('enabled')),
                   'label':'DNS настроен с TLS'})
    resolve_requested=current['settings'].get('resolve_real_ip') or any(x.get('enabled',True) and x.get('resolve_real_ip') is True for x in current['settings']['sections'])
    checks.append({'id':'real_ip_resolution','ok':not resolve_requested or real_ip_resolution_active(cfg),
                   'label':'Повторное разрешение маршрутизируемых доменов использует выбранный DNS' if resolve_requested else 'Повторное разрешение реальных IP выключено'})
    dhcp_enabled = current['settings'].get('dhcp_dns_enabled', False)
    dhcp_active = dhcp_dns_active() if dhcp_enabled else False
    checks.append({'id':'dhcp_dnsmasq','ok':not dhcp_enabled or dhcp_active,
                   'label':'dnsmasq направляет DNS в Atlas' if dhcp_enabled and dhcp_active else
                           'DNS dnsmasq не перенаправлен в Atlas' if dhcp_enabled else
                           'Интеграция DNS с dnsmasq выключена'})
    fakeip_enabled = current['settings'].get('fakeip', False)
    fakeip_ok = not fakeip_enabled
    fakeip_message = 'FakeIP выключен; DNS проверка FakeIP пропущена'
    if fakeip_enabled:
        suffix = 'example.com' if current['settings'].get('mode') == 'global' else next((d for r in cfg.get('dns', {}).get('rules', []) if r.get('server') == 'fakeip' and not r.get('source_ip_cidr') for d in r.get('domain_suffix', [])), '')
        if not suffix:
            fakeip_message = 'Для проверки FakeIP добавьте домен в общий список прокси или включите глобальный режим'
        else:
            try:
                addresses = query_local_dns_a('atlas-check-%s.%s' % (secrets.token_hex(6), suffix))
                fakeip_ok = bool(addresses) and all(ipaddress.ip_address(x) in ipaddress.ip_network('198.18.0.0/15') for x in addresses)
                fakeip_message = ('dnsmasq вернул FakeIP из 198.18.0.0/15' if fakeip_ok else
                                  'dnsmasq не вернул ожидаемый FakeIP; проверьте DNS интеграцию')
            except (AtlasError, OSError, ValueError):
                fakeip_message = 'Проверка FakeIP через локальный dnsmasq не прошла'
    checks.append({'id':'fakeip_dns','ok':fakeip_ok,'label':fakeip_message})
    nodes = filter_nodes(all_nodes(current), current['settings'], validated=True)
    test = {'ok':False,'error':'Нет прошедшего фильтры узла'}
    if nodes and running:
        active = runtime_status(all_nodes(current), running).get('selected')
        selected = next((x for x in nodes if x['key'] == active), nodes[0])
        test = probe(selected, settings=current['settings'])
    checks.append({'id':'outbound_https','ok':bool(test.get('ok')),
                   'label':('HTTPS через %s: %s мс' % (selected['name'], test.get('latency_ms')) if nodes and test.get('ok') else 'HTTPS через выбранный узел не прошёл')})
    return {'checked':int(time.time()), 'checks':checks, 'ok':all(x['ok'] for x in checks),
            'notice':'Проверка выполняется на самом роутере. Она не измеряет браузерный DNS, DoH внутри устройств или обходы со стороны клиентских VPN-приложений.'}


def dispatch(method, args):
    if method == 'status':
        return public_status()
    if method == 'monitor':
        return runtime_monitor()
    with locked():
        if active_job().get('status') in ('queued', 'running'):
            raise AtlasError('Дождитесь завершения операции')
        current = state()
        if method == 'service_logs':
            output=run(['/sbin/logread','-e','atlas'],5)
            if output.returncode:raise AtlasError('Журнал OpenWrt недоступен')
            lines=output.stdout.decode('utf-8',errors='replace').splitlines()
            return {'ok':True,'content':'\n'.join(lines[-200:])[-32768:],'truncated':len(lines)>200 or len(output.stdout)>32768}
        elif method == 'set_autostart':
            if type(args.get('enabled')) is not bool:raise AtlasError('Некорректный флаг автозапуска')
            action='enable' if args['enabled'] else 'disable'
            if run(['/etc/init.d/atlas',action],10).returncode:raise AtlasError('Не удалось изменить автозапуск')
            return {'ok':True,'enabled':args['enabled']}
        elif method == 'nft_diagnostics':
            return inspect_firewall(run,read_json(CONFIG,{}))
        elif method == 'config_preview':
            if type(args.get('validate',False)) is not bool:raise AtlasError('Некорректный флаг проверки')
            cfg=runtime_config(current,persist=False)
            if args.get('validate'):check(cfg)
            return {'ok':True,'config':safe_config(cfg),'validated':bool(args.get('validate')),'conflicts':conflicts(current['settings'])}
        elif method == 'route_explain':
            return dict(explain_route(runtime_config(current,persist=False),args.get('query')),ok=True)
        elif method == 'section_clone':
            original=next((x for x in current['settings']['sections'] if x['id']==args.get('id')),None)
            if original is None:raise AtlasError('Секция не найдена')
            clone=copy.deepcopy(original);clone.update(id=secrets.token_hex(8),name=args.get('name',''),enabled=False)
            clone['mixed_proxy']=dict(enabled=False,listen='',port=2081,username='',password='')
            current['settings']['sections'].append(clone)
            current['settings']=validate_settings(current['settings'])
            import_result={'ok':True,'id':clone['id']}
        elif method == 'dashboard_access':
            active = read_json(CONFIG,{}).get('experimental',{}).get('clash_api',{})
            if not current['settings']['yacd_enabled'] or not service_running():
                raise AtlasError('Включите внешнюю панель и примените настройки')
            return {'ok':True, 'controller':active.get('external_controller'), 'secret':active.get('secret')}
        elif method == 'section_dashboard':
            if not service_running():
                return {'ok':True, 'sections':[], 'message':'Запустите Atlas для управления секциями'}
            return {'ok':True, 'sections':section_dashboard(current, read_json(CONFIG,{}), clash_request)}
        elif method == 'section_select':
            if not service_running():
                raise AtlasError('Запустите Atlas')
            choose_section(current, read_json(CONFIG,{}), args.get('id'), args.get('group'), args.get('member'), clash_request)
            active = read_json(CONFIG,{})
            for out in active.get('outbounds',[]):
                if out.get('tag') == args.get('group'):
                    out['default'] = args.get('member')
            wire = json.loads(CONFIG.read_text())
            _, selection = wire_request(wire, '/proxies/'+args.get('group'), {'name':args.get('member')})
            for out in wire.get('outbounds',[]):
                if out.get('tag') == args.get('group'): out['default'] = selection['name']
            atomic(CONFIG,wire)
            for filename in ('active.json','last-good.json'):
                atomic(stored_config_dir(current['settings']) / filename,active)
        elif method == 'export_backup':
            return {'ok': True, 'backup': make_backup(current)}
        elif method == 'diagnostic_report':
            checks = read_json(RUN / 'checks.json', {})
            report = {'format': 'atlas-diagnostics', 'schema': 1, 'version': VERSION,
                'at': int(time.time()), 'engine': engine_version(), 'running': service_running(),
                'source_count': len(current['subscriptions']), 'node_count': len(all_nodes(current)),
                'section_count': len(current['settings']['sections']),
                'list_count': len(current['settings']['remote_lists']), 'memory': process_memory(),
                'mode': current['settings']['mode'], 'fakeip': current['settings']['fakeip'],
                'kill_switch_configured': current['settings']['kill_switch'], 'kill_switch_active': kill_switch_active(),
                'dnsmasq_configured': current['settings']['dhcp_dns_enabled'], 'dnsmasq_active': dhcp_dns_active(),
                'probes': {'total': len(checks), 'passed': sum(bool(x.get('ok')) for x in checks.values() if isinstance(x, dict))}}
            # No URLs, profile names, addresses, connections, credentials, graph or logs.
            return {'ok': True, 'report': report}
        elif method == 'restore_backup':
            if service_running():
                raise AtlasError('Остановите Atlas перед восстановлением резервной копии')
            restored = restore_state(args.get('content', ''))
            for item in restored['settings']['remote_lists']:
                if item.get('source_rules') is not None:
                    validate_source_rules(json.dumps(item['source_rules']).encode())
            # Check every archived profile, including disabled sources, without
            # claiming that restored country evidence is fresh or widening saved filters.
            for source in restored['subscriptions']:
                if source['nodes']:
                    validation = defaults()
                    validation['subscriptions'] = [dict(source, enabled=True)]
                    check(make_config(validation, tun=False))
            if all_nodes(restored) or any(x['outbound_config'] and x['enabled'] for x in restored['settings']['sections']):
                validation = copy.deepcopy(restored)
                validation['settings'].update(selected='auto', require_verified_countries=False, max_active_nodes=1024)
                for key in ('countries','excluded_countries','preferred_countries','protocols','include_names','exclude_names'):
                    validation['settings'][key] = []
                for source in validation['subscriptions']:
                    source['nodes'] = source['nodes'][:16]
                check(make_config(validation, tun=False))
            atomic(DATA / 'backup-before-restore.json', current)
            old_guard = current['settings']['kill_switch']
            previous_rule_files={}
            try:
                manage_kill_switch(restored['settings']['kill_switch'])
                for item in restored['settings']['remote_lists']:
                    if item.get('source_rules') is not None:
                        path=DATA/'rules'/(item['id']+'.json')
                        previous_rule_files[path]=path.read_bytes() if path.exists() else None
                        atomic_bytes(path,json.dumps(item['source_rules']).encode())
                atomic(STATE, restored)
            except (AtlasError, OSError, subprocess.TimeoutExpired):
                for path,body in previous_rule_files.items():
                    if body is None:path.unlink(missing_ok=True)
                    else:atomic_bytes(path,body)
                manage_kill_switch(old_guard)
                raise
            maintain_artifacts(restored)
            return {'ok': True, 'sources': len(restored['subscriptions']), 'message': 'Настройки восстановлены. Запустите Atlas после проверки правил.'}
        elif method == 'section_details':
            section = next((x for x in current['settings']['sections'] if x['id'] == args.get('id')), None)
            if section is None:
                raise AtlasError('Секция не найдена')
            return {'ok': True, 'outbound_config': section['outbound_config']}
        elif method == 'get_profiles':
            source = next((x for x in current['subscriptions'] if x['id'] == args.get('id') and x.get('source') == 'local'), None)
            if source is None:
                raise AtlasError('Локальный источник не найден')
            return {'ok': True, 'content': json.dumps({'outbounds': [dict(x['outbound'], tag=x['name']) for x in source['nodes']]}, ensure_ascii=False, indent=2)}
        elif method == 'import_rules':
            encoded = args.get('content', '')
            target = args.get('target', '')
            if not isinstance(encoded, str) or len(encoded) > 4*((4*1024*1024+2)//3):
                raise AtlasError('Файл списка должен быть меньше 4 МиБ')
            if target not in ('proxy', 'direct', 'block'):
                raise AtlasError('Выберите действие для импортируемого списка')
            try:
                raw = base64.b64decode(encoded, validate=True)
                if len(raw) > 4*1024*1024:
                    raise ValueError('oversized')
                raw.decode('utf-8-sig')
            except (ValueError, UnicodeError):
                raise AtlasError('Нужен текстовый файл UTF-8 размером до 4 МиБ')
            parsed = parse_rule_list(raw)
            if isinstance(parsed,dict):
                list_id=secrets.token_hex(8)
                item=dict(id=list_id,name='Импортированный JSON',url=(DATA/'rules'/(list_id+'.json')).resolve().as_uri(),policy=target,format='json',enabled=True)
                candidate=copy.deepcopy(current)
                candidate['settings']['remote_lists'].append(item)
                candidate['settings']=validate_settings(candidate['settings'])
                item=candidate['settings']['remote_lists'][-1]
                store_rule_set(candidate,item,json.dumps(parsed).encode(),source=True)
                item.update(count=len(parsed['rules']),updated=int(time.time()))
                atomic(STATE,candidate)
                return {'ok':True,'domains':0,'cidrs':0,'rules':len(parsed['rules'])}
            domains,cidrs = parsed
            settings = current['settings']
            if target == 'block':
                names = {x['name'].casefold() for x in settings['sections']}
                base_name, name, suffix = 'Импортированный список', 'Импортированный список', 2
                while name.casefold() in names:
                    name, suffix = '%s %d' % (base_name, suffix), suffix + 1
                settings['sections'].append({'name': name, 'policy': 'block', 'domains': domains,
                                             'cidrs': cidrs, 'source_ips': [], 'source_interfaces': [],
                                             'pool': '', 'interface': '', 'resolver': ''})
                added_domains, added_cidrs = len(domains), len(cidrs)
            else:
                dkey, ckey = (('domains', 'cidrs') if target == 'proxy' else ('bypass_domains', 'bypass_cidrs'))
                before_d, before_c = len(settings[dkey]), len(settings[ckey])
                settings[dkey] = list(dict.fromkeys(settings[dkey] + domains))
                settings[ckey] = list(dict.fromkeys(settings[ckey] + cidrs))
                added_domains, added_cidrs = len(settings[dkey]) - before_d, len(settings[ckey]) - before_c
            current['settings'] = validate_settings(settings)
            import_result = {'ok': True, 'domains': added_domains, 'cidrs': added_cidrs}
        elif method == 'import_profiles':
            raw_name = args.get('name', '')
            content = args.get('content', '')
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise AtlasError('Введите название локального источника')
            name = text(raw_name.strip(), 80)
            if not isinstance(content, str):
                raise AtlasError('Профили должны быть текстом')
            try:
                raw = content.encode('utf-8')
            except UnicodeError:
                raise AtlasError('Нужен корректный текст UTF-8')
            if len(raw) > MAX_INLINE_PROFILE_BYTES:
                raise AtlasError('Локальный импорт ограничен 256 КиБ')
            source_id = args.get('id', '')
            prior = next((x for x in current['subscriptions'] if x['id'] == source_id and x.get('source') == 'local'), None) if source_id else None
            if source_id and prior is None:
                raise AtlasError('Локальный источник не найден')
            if not prior and len(current['subscriptions']) >= MAX_SUBSCRIPTIONS:
                raise AtlasError('Максимум %d источников' % MAX_SUBSCRIPTIONS)
            parsed = parse_subscription(raw, trusted_json=True)
            if prior and parsed['warnings']:
                raise AtlasError('Не все профили корректны. Изменение отменено; прежний источник сохранён.')
            if len(parsed['nodes']) + sum(len(x.get('nodes', [])) for x in current['subscriptions'] if x is not prior) > MAX_TOTAL_NODES:
                raise AtlasError('Общий архив превышает 4096 профилей')
            source = dict(parsed, id=prior['id'] if prior else secrets.token_hex(8), name=name, source='local', url='', enabled=True,
                          updated=int(time.time()), metadata={}, error='', headers={},
                          change={'added': len(parsed['nodes']), 'removed': 0, 'total': len(parsed['nodes']), 'unchanged': False})
            validation = defaults()
            validation['subscriptions'] = [source]
            check(make_config(validation, tun=False))
            if prior:
                current['subscriptions'][current['subscriptions'].index(prior)] = source
            else:
                current['subscriptions'].append(source)
            import_result = {'ok': True, 'id': source['id'], 'count': len(parsed['nodes']),
                             'format': parsed['format'], 'warnings': parsed['warnings']}
        elif method == 'save_subscription':
            sub_id = args.get('id', '')
            name = text(args.get('name', '').strip(), 80)
            if not name:
                raise AtlasError('Введите название')
            if type(args.get('enabled', True)) is not bool:
                raise AtlasError('Некорректный флаг')
            if type(args.get('clear_headers', False)) is not bool:
                raise AtlasError('Некорректный флаг очистки заголовков')
            if sub_id:
                sub = next((x for x in current['subscriptions'] if x['id'] == sub_id), None)
                if not sub:
                    raise AtlasError('Подписка не найдена')
                if sub.get('source') == 'local':
                    if args.get('url') or args.get('headers'):
                        raise AtlasError('Локальный источник не использует URL или HTTP заголовки')
                    sub.update(name=name, enabled=args.get('enabled', True))
                    atomic(STATE, current)
                    return {'ok': True}
            else:
                if len(current['subscriptions']) >= MAX_SUBSCRIPTIONS:
                    raise AtlasError('Максимум %d подписок' % MAX_SUBSCRIPTIONS)
                sub = {'id': secrets.token_hex(8), 'nodes': []}
                current['subscriptions'].append(sub)
            if args.get('url'):
                new_url = subscription_url(args['url'])
                if sub.get('url') != new_url:
                    old = urlsplit(sub.get('url', 'https://invalid.example'))
                    new = urlsplit(new_url)
                    if (old.hostname, old.port or 443) != (new.hostname, new.port or 443):
                        sub['headers'] = {}
                    sub.update(nodes=[], updated=0, metadata={}, error='', warnings=[], etag='', last_modified='', change={})
                sub['url'] = new_url
            if not sub.get('url'):
                raise AtlasError('Введите URL подписки')
            header_text = args.get('headers', '')
            if not isinstance(header_text, str):
                raise AtlasError('Заголовки подписки должны быть текстом')
            if header_text.strip():
                sub['headers'] = subscription_headers(header_text)
            elif args.get('clear_headers'):
                sub['headers'] = {}
            else:
                sub.setdefault('headers', {})
            sub.update(name=name, enabled=args.get('enabled', True))
        elif method == 'import_subscriptions':
            items = args.get('items')
            if not isinstance(items, list) or len(items) > MAX_SUBSCRIPTIONS:
                raise AtlasError('Пакетный импорт принимает до 64 строк')
            known = {x.get('url') for x in current['subscriptions']}
            results = []
            for index, item in enumerate(items):
                label = 'Строка %d' % (index + 1)
                try:
                    if not isinstance(item, dict) or set(item) - {'name','url'} or not isinstance(item.get('url'), str):
                        raise AtlasError('Ожидались поля name и url')
                    url = subscription_url(item['url'])
                    raw_name = item.get('name', '')
                    if not isinstance(raw_name, str):
                        raise AtlasError('Название должно быть текстом')
                    name = text(raw_name.strip(), 80) or (urlsplit(url).hostname or 'Подписка')
                    if not name:
                        raise AtlasError('Введите название')
                    if url in known:
                        results.append({'line': index + 1, 'name': name, 'status': 'duplicate', 'message': 'Этот URL уже добавлен'})
                        continue
                    if len(current['subscriptions']) >= MAX_SUBSCRIPTIONS:
                        results.append({'line': index + 1, 'name': name, 'status': 'error', 'message': 'Достигнут предел 64 подписки'})
                        continue
                    sub = {'id': secrets.token_hex(8), 'name': name, 'url': url, 'enabled': True, 'nodes': [],
                           'updated': 0, 'metadata': {}, 'error': '', 'warnings': [], 'headers': {}}
                    current['subscriptions'].append(sub)
                    known.add(url)
                    results.append({'line': index + 1, 'name': name, 'status': 'added', 'id': sub['id']})
                except (AtlasError, TypeError, ValueError, AttributeError) as exc:
                    results.append({'line': index + 1, 'name': label, 'status': 'error', 'message': text(str(exc), 180)})
            import_result = {'ok': True, 'items': results,
                             'added': sum(1 for x in results if x['status'] == 'added'),
                             'duplicates': sum(1 for x in results if x['status'] == 'duplicate'),
                             'errors': sum(1 for x in results if x['status'] == 'error')}
        elif method == 'delete_subscription':
            if not any(x['id'] == args.get('id') for x in current['subscriptions']):
                raise AtlasError('Подписка не найдена')
            current['subscriptions'] = [x for x in current['subscriptions'] if x['id'] != args['id']]
        elif method == 'save_settings':
            previous = copy.deepcopy(current)
            submitted = copy.deepcopy(args.get('settings', {}))
            if not submitted.get('mixed_proxy_password'):
                submitted['mixed_proxy_password'] = current['settings'].get('mixed_proxy_password', '')
            old_sections = {item['id']: item for item in current['settings']['sections']}
            for section in submitted.get('sections', []):
                if not isinstance(section, dict):
                    continue
                section.pop('outbound_config_set', None)
                old_section = old_sections.get(section.get('id')) or next(
                    (x for x in old_sections.values() if x['name'] == section.get('name')), None)
                if old_section:
                    section.setdefault('id', old_section['id'])
                    section.setdefault('outbound_config', old_section['outbound_config'])
                    for field in ('resolve_real_ip','auto_interval_seconds','auto_tolerance_ms','urltest_url','udp_over_tcp','udp_over_tcp_version','urltest_fallbacks','urltest_download_check','urltest_download_url'):
                        section.setdefault(field,old_section[field])
                    section.setdefault('mixed_proxy', old_section['mixed_proxy'])
                    listener = section.get('mixed_proxy', {})
                    if isinstance(listener, dict) and not listener.get('password'):
                        listener['password'] = old_section['mixed_proxy'].get('password', '')
                        section['mixed_proxy'] = listener
            old_lists = {item['id']: item for item in current['settings'].get('remote_lists', [])}
            for item in submitted.get('remote_lists', []):
                if isinstance(item, dict):
                    prior = old_lists.get(item.get('id'))
                    if prior:
                        for flag in ('allow_private','allow_symlinks'):
                            item.setdefault(flag,prior.get(flag,False))
                    if prior and isinstance(item.get('url'), str) and item['url'].endswith('/[saved]'):
                        item['url'] = prior['url']
                    if prior and item.get('url') == prior.get('url'):
                        for cache_key in ('domains','cidrs','updated','error','count','srs_cached','source_cached','source_rules'):
                            if cache_key=='source_rules' and cache_key not in prior:continue
                            item.setdefault(cache_key, prior.get(cache_key, [] if cache_key in ('domains','cidrs') else 0 if cache_key == 'updated' else ''))
            current['settings'] = validate_settings(submitted)
            if all_nodes(current):
                selection_nodes(current)
            if any(x['outbound_config'] or x['mixed_proxy']['enabled'] for x in current['settings']['sections']):
                # Validate expert graphs with the real engine before changing saved state.
                check(make_config(current, tun=False))
            atomic(STATE, current)
            new_guard = current['settings']['kill_switch']
            old_guard = previous['settings'].get('kill_switch', False)
            if new_guard or new_guard != old_guard:
                try:
                    manage_kill_switch(new_guard)
                except (AtlasError, OSError, subprocess.TimeoutExpired):
                    atomic(STATE, previous)
                    try:
                        manage_kill_switch(old_guard)
                    except (AtlasError, OSError, subprocess.TimeoutExpired):
                        pass
                    raise
            maintain_artifacts(current)
            return {'ok': True}
        elif method == 'action':
            operation = args.get('operation')
            if operation not in ('refresh', 'apply', 'start', 'stop', 'probe', 'privacy', 'selftest', 'geo_check', 'section_test'):
                raise AtlasError('Неизвестная операция')
            sub_id = args.get('id', '')
            if operation == 'section_test':
                if not service_running() or not any(x['id'] == sub_id and x['enabled'] for x in current['settings']['sections']):
                    raise AtlasError('Для проверки выберите включённую секцию работающего Atlas')
            elif operation == 'geo_check':
                if not isinstance(sub_id, str) or not re.fullmatch('[a-f0-9]{32}', sub_id) or not any(x['key'] == sub_id for x in all_nodes(current)):
                    raise AtlasError('Сервер для проверки страны не найден')
            elif sub_id and not any(x['id'] == sub_id for x in current['subscriptions']):
                raise AtlasError('Подписка не найдена')
            job = {'id': secrets.token_hex(8), 'operation': operation, 'subscription': sub_id,
                   'status': 'queued', 'message': 'В очереди', 'at': int(time.time())}
            # Worker blocks on the same lock until PID and job are persisted.
            child = subprocess.Popen([sys.executable, SCRIPT, 'worker', job['id']],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True, close_fds=True)
            job['pid'] = child.pid
            atomic(RUN / 'job.json', job)
            return {'ok': True, 'job': job['id']}
        else:
            raise AtlasError('Неизвестный метод')
        atomic(STATE, current)
        maintain_artifacts(current)
        return locals().get('import_result', {'ok': True})


def worker(job_id):
    with locked(block=True):
        job = read_json(RUN / 'job.json', {})
        if job.get('id') != job_id:
            return
        job.update(status='running', message='Выполняется')
        atomic(RUN / 'job.json', job)
        try:
            op, current = job['operation'], state()
            message = 'Готово'
            if op == 'section_test':
                results = test_section(current, read_json(CONFIG,{}), job['subscription'], clash_request)
                atomic(RUN / ('section-check-' + job['subscription'] + '.json'), results)
                message = 'Замеры секции: доступны %d из %d' % (sum(isinstance(x,dict) and x.get('delay',0)>0 for x in results.values()),len(results))
            elif op == 'refresh':
                message = refresh(current, job['subscription'])
            elif op in ('apply', 'start'):
                apply(current, enable=op == 'start')
                message = 'Конфигурация проверена, сервис запущен'
            elif op == 'stop':
                run(['/etc/init.d/atlas', 'disable'])
                run(['/etc/init.d/atlas', 'stop'], 60)
                # procd stop is asynchronous; wait before reporting failure.
                for _ in range(20):
                    if not service_running():
                        break
                    time.sleep(.25)
                else:
                    raise AtlasError('Не удалось остановить сервис')
                message = 'Сервис остановлен, автозапуск отключён'
            elif op == 'probe':
                nodes = filter_nodes(all_nodes(current), current['settings'], validated=True)
                if not nodes:
                    raise AtlasError('Нет узлов для проверки')
                checks = read_json(RUN / 'checks.json', {})
                concurrency = probe_workers()
                failures = 0
                for index, (n, result) in enumerate(probe_batch(
                        nodes, lambda node: probe(node, settings=current['settings']), concurrency)):
                    checks[n['key']] = result
                    failures += not result.get('ok', False)
                    atomic(RUN / 'checks.json', checks)
                    job['completed'] = index + 1
                    job['total'] = len(nodes)
                    job['parallelism'] = concurrency
                    job['message'] = 'Проверено %d из %d' % (index + 1, len(nodes))
                    atomic(RUN / 'job.json', job)
                message = 'HTTPS проверка завершена: %d узлов, ошибок: %d' % (len(nodes), failures)
            elif op == 'geo_check':
                node = next((x for x in all_nodes(current) if x['key'] == job['subscription']), None)
                if not node:
                    raise AtlasError('Сервер для проверки страны больше не существует')
                country = proxied_exit_country(node)
                message = save_exit_country(current, node['key'], country)
            elif op == 'privacy':
                nodes = filter_nodes(all_nodes(current), current['settings'], validated=True)
                if not nodes:
                    raise AtlasError('Нет серверов для проверки')
                runtime = runtime_status(all_nodes(current), service_running())
                active = next((n for n in nodes if n['key'] == runtime.get('selected')), None)
                if not active and current['settings']['selected'] != 'auto':
                    active = next((n for n in nodes if n['key'] == current['settings']['selected']), None)
                selected = active or nodes[0]
                result = privacy_egress_test(selected)
                atomic(RUN / 'privacy-egress.json', result)
                if result['status'] != 'done':
                    raise AtlasError(result['error'])
                message = 'Внешние IP различаются' if result['ok'] else 'Напрямую и через прокси виден одинаковый IP'
            elif op == 'selftest':
                result = selftest(current)
                atomic(RUN / 'selftest.json', result)
                failed = sum(1 for item in result['checks'] if not item['ok'])
                message = 'Самопроверка завершена: %d проверок, ошибок: %d' % (len(result['checks']), failed)
            job.update(status='done', message=message)
        except AtlasError as exc:
            job.update(status='error', message=str(exc))
        except Exception:
            job.update(status='error', message='Ошибка операции. Проверьте зависимости и свободное место.')
        job['finished'] = int(time.time())
        atomic(RUN / 'job.json', job)


def prepare_engine_start(config):
    """Preserve FakeIP without accumulating per-launch cache namespaces."""
    if not isinstance(config, dict):
        raise AtlasError('Конфигурация службы отсутствует')
    return prepare_launch_cache(config, secrets.token_hex(16))


def rpc_request_limit(method):
    if method=='import_rules':
        return 6*1024*1024
    if method == 'import_profiles':
        return MAX_INLINE_PROFILE_BYTES * 6 + 4096
    if method == 'save_settings':
        return 16 * 1024 * 1024
    if method == 'restore_backup':
        return 2 * MAX_BACKUP_BYTES + 4096
    return 131072


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'list':
        print(json.dumps(METHODS))
        return
    setup()
    if len(sys.argv) > 1 and sys.argv[1] == 'engine-run':
        config = prepare_engine_start(read_json(CONFIG, None))
        if not isinstance(config, dict):
            raise AtlasError('Конфигурация службы отсутствует')
        check(config)
        atomic(CONFIG, config)
        os.execv(BINARY, [BINARY, 'run', '-c', str(CONFIG)])
        return
    if len(sys.argv) > 2 and sys.argv[1] == 'worker':
        worker(sys.argv[2])
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'boot-config':
        current = state()
        config = runtime_config(current) if current['settings'].get('require_verified_countries') else (read_json(stored_config_dir(current['settings']) / 'active.json', None) or runtime_config(current))
        check(config)
        atomic(CONFIG, config)
        return
    if len(sys.argv) > 1 and sys.argv[1] in ('dhcp-sync', 'dhcp-restore'):
        try:
            manage_dhcp_dns(state()['settings']['dhcp_dns_enabled'] if sys.argv[1] == 'dhcp-sync' else False)
        except (AtlasError, OSError, subprocess.TimeoutExpired) as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        return
    if len(sys.argv) > 1 and sys.argv[1] in ('ingress-sync','ingress-restore'):
        config=read_json(CONFIG,{})
        enabled=sys.argv[1]=='ingress-sync' and any(x.get('include_interface') for x in config.get('inbounds',[]))
        manage_ingress_firewall(enabled)
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'iface-event':
        record_interface_event()
        return
    if len(sys.argv)>2 and sys.argv[1]=='iface-recover':
        interface_event_worker(sys.argv[2],int(sys.argv[3]) if len(sys.argv)>3 else None)
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'scheduled':
        current = state()
        try:
            with locked():
                current=state()
                if active_job().get('status') not in ('queued', 'running'):
                    maintain_artifacts(current)
                    check_result = healthcheck()
                    if check_result.get('reason') not in ('healthy','disabled'):
                        atomic(RUN / 'watchdog.json', dict(check_result, at=int(time.time())))
                    if check_result.get('reason') != 'restarted':
                        interface_result = interface_recover(current,lock_held=True)
                        if interface_result.get('reason') == 'interface-restarted' or not interface_result.get('ok'):
                            atomic(RUN / 'watchdog.json', dict(interface_result, at=int(time.time())))
                    automatic_select(current)
        except AtlasError:
            pass
        interval = current['settings']['interval_hours'] * 3600
        due = any(s.get('source') != 'local' and s.get('enabled', True) and time.time() - s.get('updated', 0) >= interval for s in current['subscriptions']) or any(x.get('enabled') and (time.time() - x.get('updated', 0) >= interval or (x['url'].startswith('file:///') and local_rule_version(x['url']) != x.get('file_version',''))) for x in current['settings']['remote_lists'])
        if due:
            try:
                dispatch('action', {'operation': 'refresh'})
            except AtlasError:
                pass
        return
    try:
        if len(sys.argv) != 3 or sys.argv[1] != 'call':
            raise AtlasError('Нужен rpcd вызов')
        limit = rpc_request_limit(sys.argv[2])
        raw = sys.stdin.buffer.read(limit + 1)
        if len(raw) > limit:
            raise AtlasError('Запрос слишком большой')
        args = json.loads(raw or b'{}')
        if not isinstance(args, dict) or sys.argv[2] not in METHODS:
            raise AtlasError('Некорректный запрос')
        result = dispatch(sys.argv[2], args)
    except AtlasError as exc:
        result = {'ok': False, 'error': str(exc)}
    except Exception:
        result = {'ok': False, 'error': 'Ошибка backend. Проверьте зависимости и свободное место.'}
    print(json.dumps(result, ensure_ascii=False))

if __name__ == '__main__':
    main()
