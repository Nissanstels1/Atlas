"""Remove only Atlas-owned artifacts absent from saved and deployed state.

Call while holding the backend lock. Never edit sing-box's live Bolt database.
"""
import json
import re
from pathlib import Path


def prune_artifacts(current, data, run, config):
    data, run, config = Path(data), Path(run), Path(config)
    settings = current['settings']
    if any(not isinstance(x, dict) or not re.fullmatch(r'[a-f0-9]{16}', x.get('id', '')) for x in settings.get('remote_lists', []) + settings.get('sections', [])):
        return {'skipped': 'unvalidated-state'}
    keep = {x['id'] + suffix for x in settings.get('remote_lists', []) for suffix in ('.json', '.srs')}
    store = (Path(settings['config_custom_dir']) if settings.get('config_storage') == 'external'
             else run if settings.get('config_storage') == 'ram' else data)
    # A saved edit may precede Apply. Keep files needed by the running service,
    # next boot and rollback, even when they are no longer in edited settings.
    for path in (config, store / 'active.json', store / 'last-good.json'):
        try:
            value = json.loads(path.read_text())
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return {'skipped': 'unreadable-deployed-config'}
        if not isinstance(value, dict):
            return {'skipped': 'invalid-deployed-config'}
        route = value.get('route', {})
        if not isinstance(route, dict) or not isinstance(route.get('rule_set', []), list):
            return {'skipped': 'invalid-deployed-config'}
        for item in route.get('rule_set', []):
            if not isinstance(item, dict) or not isinstance(item.get('path', ''), str):
                return {'skipped': 'invalid-deployed-config'}
            target = Path(item.get('path', ''))
            if target.parent == data / 'rules':
                keep.add(target.name)
    removed = 0
    rules = data / 'rules'
    if rules.exists() and not rules.is_symlink():
        for path in rules.iterdir():
            if re.fullmatch(r'[a-f0-9]{16}\.(json|srs)', path.name) and path.name not in keep and path.is_file() and not path.is_symlink():
                path.unlink()
                removed += 1
    sections = {x['id'] for x in settings.get('sections', [])}
    for path in run.glob('section-check-*.json'):
        match = re.fullmatch(r'section-check-([a-f0-9]{16})\.json', path.name)
        if match and match[1] not in sections and path.is_file() and not path.is_symlink():
            path.unlink()
            removed += 1
    checks = run / 'checks.json'
    try:
        old = json.loads(checks.read_text())
    except (OSError, ValueError):
        old = None
    keys = {sub['id'] + node['id'] for sub in current.get('subscriptions', []) for node in sub.get('nodes', [])}
    trimmed = {key: value for key, value in old.items() if key in keys} if isinstance(old, dict) else None
    return {'removed': removed, 'checks': trimmed if trimmed != old else None}
