import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
from outbounds import namespace_graph, outbound_graph
from backups import make_backup, restore_state


def sample():
    state = core.defaults()
    state['subscriptions'] = [{'id': 'b'*16, 'name': 'local', 'enabled': True, 'source': 'local',
        'nodes': [core.uri_node('trojan://private-password@example.com:443#local')]}]
    return state


def section(name='expert', **kwargs):
    value = dict(name=name, policy='proxy', domains=['example.org'], cidrs=[], source_ips=[],
                 outbound_config=[{'type': 'http', 'tag': 'entry', 'server': '127.0.0.1', 'server_port': 8443,
                                   'password': 'graph-secret', 'username': 'username'}])
    value.update(kwargs)
    return value


def listener(port=2081):
    return dict(enabled=True, listen='127.0.0.1', port=port, username='username', password='listener-secret')


class ExpertGraphs(unittest.TestCase):
    def test_admin_profile_json_preserves_extra_fields_and_friendly_names(self):
        value={'outbounds':[{'type':'trojan','tag':'EE My custom server','server':'example.com','server_port':443,
            'password':'private-password','tls':{'enabled':True,'insecure':True},'multiplex':{'enabled':True}}]}
        parsed=core.parse_subscription(json.dumps(value).encode(),trusted_json=True)
        node=parsed['nodes'][0]
        self.assertEqual(node['name'],'EE My custom server')
        self.assertTrue(node['outbound']['multiplex']['enabled'])
        self.assertTrue(node['outbound']['tls']['insecure'])
        with self.assertRaises(core.AtlasError):core.parse_subscription(json.dumps(value).encode())

    def test_selector_refs_and_detours_are_namespaced(self):
        graph = [{'type': 'selector', 'tag': 'entry', 'outbounds': ['primary','relay'], 'default': 'primary'},
                 {'type': 'http', 'tag': 'primary', 'server': 'example.org', 'server_port': 443, 'detour': 'relay'},
                 {'type': 'direct', 'tag': 'relay'}]
        rewritten, root = namespace_graph(graph, 'section_123')
        self.assertEqual(root, 'section_123_entry')
        self.assertEqual(rewritten[0]['outbounds'], ['section_123_primary', 'section_123_relay'])
        self.assertEqual(rewritten[1]['detour'], 'section_123_relay')
        self.assertEqual(graph[0]['tag'], 'entry')

    def test_cycles_missing_tags_and_duplicates_are_rejected(self):
        cases = [
            [{'type':'direct','tag':'same'},{'type':'direct','tag':'same'}],
            [{'type':'http','tag':'entry','detour':'absent'}],
            [{'type':'http','tag':'a','detour':'b'},{'type':'http','tag':'b','detour':'a'}],
            [{'type':'selector','tag':'entry','outbounds':['entry']}],
            [{'type':'direct','tag':'bad tag'}],
        ]
        for graph in cases:
            with self.subTest(graph=graph), self.assertRaises(ValueError):
                outbound_graph(graph)

    def test_protocol_fields_are_preserved(self):
        graph = outbound_graph({'type':'vless', 'server':'example.com', 'server_port':443,
                                'uuid':'11111111-1111-4111-8111-111111111111',
                                'tls':{'enabled':True,'certificate':['PEM']},'multiplex':{'enabled':True}})
        self.assertTrue(graph[0]['multiplex']['enabled'])
        self.assertEqual(graph[0]['tls']['certificate'], ['PEM'])

    def test_sections_with_identical_local_tags_do_not_collide(self):
        state = sample()
        state['settings']['sections'] = [section('first'), section('second')]
        config = core.make_config(state)
        tags = [x['tag'] for x in config['outbounds']]
        self.assertEqual(len(tags), len(set(tags)))
        routes = [r for r in config['route']['rules'] if r.get('domain_suffix') == ['example.org']]
        self.assertEqual(len(set(r['outbound'] for r in routes)), 2)

    def test_disabled_section_emits_nothing(self):
        state = sample()
        state['settings']['sections'] = [section(enabled=False, mixed_proxy=listener())]
        config = core.make_config(state)
        self.assertFalse(any(x['tag'].startswith('section_') for x in config['outbounds']))
        self.assertFalse(any(x['tag'].startswith('mixed_') for x in config['inbounds']))

    def test_split_dns_uses_custom_section_outbound(self):
        state = sample()
        state['settings']['sections'] = [section(resolver='https://1.1.1.1/dns-query')]
        config = core.make_config(state)
        resolver = next(x for x in config['dns']['servers'] if x['tag'].startswith('vpn_dns_'))
        self.assertTrue(resolver['detour'].startswith('section_'))

    def test_listener_routes_before_global_device_exclusions(self):
        state = sample()
        state['settings'].update(routing_excluded_ips=['192.168.1.0/24'],
                                  sections=[section(mixed_proxy=listener())])
        config = core.make_config(state)
        inbound = next(x for x in config['inbounds'] if x['tag'].startswith('mixed_'))
        self.assertEqual(inbound['users'][0]['password'], 'listener-secret')
        rules = config['route']['rules']
        route = next(x for x in rules if x.get('inbound') == [inbound['tag']])
        self.assertTrue(route['outbound'].startswith('section_'))
        self.assertLess(rules.index(route), next(i for i,r in enumerate(rules) if r.get('source_ip_cidr') == ['192.168.1.0/24']))

    def test_listener_only_section_does_not_capture_other_traffic(self):
        state = sample()
        state['settings']['sections'] = [section(domains=[], mixed_proxy=listener())]
        config = core.make_config(state)
        custom_routes = [r for r in config['route']['rules'] if str(r.get('outbound','')).startswith('section_')]
        self.assertEqual(len(custom_routes), 1)
        self.assertIn('inbound', custom_routes[0])

    def test_reserved_duplicate_public_and_bad_credentials_are_rejected(self):
        for change in [dict(port=19090),dict(listen='0.0.0.0'),dict(listen='8.8.8.8'),dict(password='short'),dict(username='')]:
            state = sample(); value=listener();value.update(change)
            state['settings']['sections'] = [section(mixed_proxy=value)]
            with self.subTest(change=change), self.assertRaises(core.AtlasError):
                core.make_config(state)
        state=sample();state['settings']['sections']=[section('a',mixed_proxy=listener()),section('b',mixed_proxy=listener())]
        with self.assertRaises(core.AtlasError):core.make_config(state)

    def test_expert_graph_can_run_without_subscription_with_main_blocked(self):
        state=core.defaults();state['settings']['sections']=[section()]
        config=core.make_config(state)
        self.assertEqual(next(x for x in config['outbounds'] if x['tag']=='local-only-block')['type'], 'block')
        self.assertTrue(any(x['tag'].startswith('section_') for x in config['outbounds']))

    def test_id_survives_rename(self):
        settings=core.validate_settings({'sections':[section()]})
        identity=settings['sections'][0]['id']
        settings['sections'][0]['name']='renamed'
        self.assertEqual(core.validate_settings(settings)['sections'][0]['id'],identity)

    def test_real_ip_resolution_uses_each_sections_dns_without_overriding_main(self):
        state=sample()
        state['settings'].update(resolve_real_ip=True, sections=[
            section('one',outbound_config=[],domains=['one.example'],resolver='https://1.1.1.1/dns-query'),
            section('two',outbound_config=[],domains=['two.example'],resolver='https://9.9.9.9/dns-query')])
        state['settings']['domains']=['main.example']
        config=core.make_config(state)
        resolve=[r for r in config['route']['rules'] if r.get('action')=='resolve']
        self.assertEqual(next(r for r in resolve if r.get('domain_suffix')==['main.example'])['server'],'secure')
        self.assertNotEqual(next(r for r in resolve if r.get('domain_suffix')==['one.example'])['server'],
                            next(r for r in resolve if r.get('domain_suffix')==['two.example'])['server'])

    def test_default_dns_has_working_graph_detour_without_main_subscription(self):
        state=core.defaults();state['settings']['sections']=[section()]
        config=core.make_config(state)
        self.assertTrue(next(x for x in config['dns']['servers'] if x['tag']=='secure')['detour'].startswith('section_'))


class Backups(unittest.TestCase):
    def test_local_advanced_profile_survives_backup_restore(self):
        state=sample()
        state['subscriptions'][0]['nodes'][0]['outbound']['multiplex']={'enabled':True}
        restored=restore_state(json.dumps(make_backup(state)))
        self.assertTrue(restored['subscriptions'][0]['nodes'][0]['outbound']['multiplex']['enabled'])

    def test_roundtrip_preserves_keys_secrets_and_expert_graphs(self):
        state=sample();state['settings']['sections']=[section(mixed_proxy=listener())]
        restored=restore_state(json.dumps(make_backup(state)))
        self.assertEqual(restored['subscriptions'][0]['nodes'][0]['id'], state['subscriptions'][0]['nodes'][0]['id'])
        self.assertEqual(restored['settings']['sections'][0]['mixed_proxy']['password'],'listener-secret')
        self.assertEqual(restored['settings']['sections'][0]['outbound_config'][0]['password'],'graph-secret')

    def test_imported_country_evidence_is_not_reused(self):
        state=sample();state['subscriptions'][0]['nodes'][0].update(verified_country='EE',country_verified_at=123456)
        restored=restore_state(json.dumps(make_backup(state)))
        self.assertNotIn('verified_country',restored['subscriptions'][0]['nodes'][0])

    def test_invalid_schema_duplicate_ids_and_unsafe_url_rejected(self):
        backup=make_backup(sample())
        bad_schema=copy.deepcopy(backup);bad_schema['schema']=True
        duplicate=copy.deepcopy(backup);duplicate['state']['subscriptions']*=2
        unsafe=copy.deepcopy(backup);unsafe['state']['subscriptions'][0].update(source='remote',url='http://example.org/sub')
        for value in [bad_schema,duplicate,unsafe,{}]:
            with self.subTest(value=value),self.assertRaises(core.AtlasError):restore_state(json.dumps(value))


if __name__ == '__main__': unittest.main()
