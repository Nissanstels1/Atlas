"""Monitor assignments must be scoped, editable and removable without collateral edits."""
import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
import connection_rules as rules
import planner
from test_core import state_with_node
from test_independent_sections import sec
import test_extensions_rpc as fixtures


def record(identity='c' * 16, **values):
    return dict(id=identity, name='Example', domains=['example.org'], cidrs=[]) | values


class DomainSuggestions(unittest.TestCase):
    def test_real_site_boundaries_and_private_tenants(self):
        for value, expected in [('img.example.co.uk', 'example.co.uk'), ('rr2---sn-a.googlevideo.com', 'googlevideo.com'), ('www.example.ru', 'example.ru'), ('a.tenant.github.io', 'tenant.github.io'), ('d111.cloudfront.net', 'd111.cloudfront.net'), ('x.www.ck', 'www.ck'), ('a.example.invalidsuffix', 'a.example.invalidsuffix')]:
            with self.subTest(value=value):
                self.assertEqual(rules.site_domain(value), expected)
    def test_idna_and_exact_domains(self):
        self.assertEqual(rules.site_domain('Фото.пример.рф'), 'xn--e1afmkfd.xn--p1ai')
        for value in ('co.uk', 'github.io', 'cloudfront.net'):
            with self.assertRaises(core.AtlasError):
                rules.site_domain(value)
    def test_missing_suffix_file_never_guesses_a_parent(self):
        with mock.patch.object(rules, 'suffixes', return_value=(set(), set(), set())):
            self.assertEqual(rules.site_domain('img.example.co.uk'), 'img.example.co.uk')
    def test_preview_does_not_use_fake_private_or_tailscale_ip(self):
        for address in ('198.18.1.2', '127.0.0.1', '192.168.1.1', '100.100.1.2', 'fc00::1'):
            self.assertEqual(rules.preview(dict(host='img.example.org', destination=address))['cidr'], '')
        self.assertEqual(rules.preview(dict(host='', destination='1.1.1.1'))['cidr'], '1.1.1.1/32')
        self.assertEqual(rules.preview(dict(host='2606:4700:4700::1111', destination=''))['cidr'], '2606:4700:4700::1111/128')
    def test_related_addresses_are_grouped_without_inventing_ownership(self):
        result = rules.preview(dict(host='img.example.org', destination='1.1.1.1', related=['cdn.example.org', 'api.other.co.uk', 'x.other.co.uk', 'https://bad.example']))
        self.assertEqual(result['site'], 'example.org')
        self.assertEqual(result['related'], ['other.co.uk'])


class OwnedRecords(unittest.TestCase):
    def settings(self):
        return core.validate_settings(dict(sections=[sec('A', id='a'*16, connection_rules=[]), sec('B', id='b'*16, connection_rules=[])]))
    def test_removal_preserves_manual_duplicates_and_other_records(self):
        settings = self.settings()
        owner = settings['sections'][0]
        owner['domains'].append('example.org')
        owner['cidrs'].append('1.1.1.1/32')
        owner['connection_rules'] = [record(cidrs=['1.1.1.1/32']), record('d'*16, domains=['other.org'])]
        rules.change(settings, 'delete', '', 'c'*16, {})
        self.assertIn('example.org', owner['domains'])
        self.assertIn('1.1.1.1/32', owner['cidrs'])
        self.assertEqual([r['id'] for r in owner['connection_rules']], ['d'*16])
    def test_repeat_is_idempotent_and_move_keeps_identity(self):
        settings = self.settings()
        payload = dict(name='Example', domains=['example.org'], cidrs=[])
        first = rules.change(settings, 'save', 'a'*16, '', payload)
        self.assertTrue(rules.change(settings, 'save', 'a'*16, '', payload)['unchanged'])
        rules.change(settings, 'save', 'b'*16, first['id'], payload)
        self.assertEqual(settings['sections'][0]['connection_rules'], [])
        self.assertEqual(settings['sections'][1]['connection_rules'][0]['id'], first['id'])
        core.validate_settings(settings)
    def test_empty_section_is_disabled_when_last_owned_rule_is_removed(self):
        settings = self.settings()
        settings['sections'][0].update(domains=[], connection_rules=[record()])
        self.assertTrue(rules.change(settings, 'delete', '', 'c'*16, {})['section_disabled'])
        self.assertFalse(settings['sections'][0]['enabled'])
        core.validate_settings(settings)
    def test_invalid_input_never_expands_to_networks_or_url_patterns(self):
        for values in (dict(domains=['https://example.org']), dict(cidrs=['1.1.1.0/24']), dict(cidrs=['198.18.1.1/32']), dict(cidrs=['224.0.0.1/32']), dict(domains=[], cidrs=[])):
            with self.subTest(values=values), self.assertRaises(core.AtlasError):
                rules.normalize([record(**values)])
    def test_duplicate_identifiers_and_nonproxy_owner_are_rejected(self):
        settings = self.settings()
        for section in settings['sections']:
            section['connection_rules'] = [record()]
        with self.assertRaises(core.AtlasError):
            core.validate_settings(settings)
        settings['sections'][1]['connection_rules'] = []
        settings['sections'][1]['policy'] = 'direct'
        with self.assertRaises(core.AtlasError):
            rules.change(settings, 'save', 'b'*16, '', dict(domains=['example.org']))
    def test_conflicting_assignment_is_rejected_without_removing_original(self):
        settings = self.settings()
        rules.change(settings, 'save', 'a'*16, '', dict(domains=['example.org']))
        before = copy.deepcopy(settings)
        with self.assertRaises(core.AtlasError):
            rules.change(settings, 'save', 'b'*16, '', dict(domains=['example.org']))
        self.assertEqual(settings, before)
    def test_section_editor_cannot_create_duplicate_active_assignments(self):
        settings = self.settings()
        for index, section in enumerate(settings['sections']):
            section['connection_rules'] = [record(str(index+1)*16)]
        with self.assertRaises(core.AtlasError):
            core.validate_settings(settings)
        settings['sections'][1]['enabled'] = False
        core.validate_settings(settings)


class CompiledAssignments(unittest.TestCase):
    def config(self, **values):
        state = state_with_node()
        state['settings'].update(fakeip=True, group_order=True, sections=[sec('A', id='a'*16, pools=[], source_ips=['192.168.1.0/24']), sec('B', id='b'*16, pools=[], connection_rules=[record()])])
        state['settings'].update(values)
        return core.make_config(state)
    def test_assignment_precedes_broad_device_rule_and_covers_subdomains(self):
        config = self.config()
        result = planner.explain_route(config, dict(domain='img.example.org', ip='93.184.216.34', source_ip='192.168.1.2', port=443, network='tcp', protocol='tls', inbound='tun'))
        self.assertTrue(result['certain'])
        self.assertEqual(result['outbound'], 'section_'+'b'*16+'_control')
        matching = [r for r in config['route']['rules'] if r.get('domain_suffix') == ['example.org']]
        self.assertEqual(len(matching), 1)
        dns = next(r for r in config['dns']['rules'] if r.get('domain_suffix') == ['example.org'])
        self.assertEqual(dns['server'], 'fakeip')
    def test_global_bypass_and_dns_reject_keep_priority(self):
        config = self.config(bypass_domains=['example.org'], blocked_domains=['blocked.example.org'])
        result = planner.explain_route(config, dict(domain='img.example.org', ip='93.184.216.34', source_ip='192.168.1.2', port=443, network='tcp', protocol='tls', inbound='tun'))
        self.assertEqual(result['outbound'], 'direct')
        self.assertEqual(config['dns']['rules'][0]['action'], 'reject')
    def test_narrow_explicit_rule_wins_over_parent_assignment(self):
        config = self.config(sections=[sec('A', id='a'*16, pools=[], connection_rules=[record()]), sec('B', id='b'*16, pools=[], connection_rules=[record('d'*16, domains=['img.example.org'])])])
        result = planner.explain_route(config, dict(domain='img.example.org', ip='93.184.216.34', port=443, network='tcp', protocol='tls', inbound='tun'))
        self.assertEqual(result['outbound'], 'section_'+'b'*16+'_control')
    @unittest.skipUnless(os.environ.get('ATLAS_RULE_ENGINE'), 'Requires installed Atlas Engine')
    def test_native_engine_accepts_domains_ips_and_section_dns(self):
        for fakeip in (False, True):
            config = self.config(fakeip=fakeip, resolve_real_ip=True, sections=[sec('B', id='b'*16, pools=[], connection_rules=[record(cidrs=['1.1.1.1/32', '2606:4700:4700::1111/128'])])])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(config))
                result = subprocess.run([os.environ['ATLAS_RULE_ENGINE'], 'check', '-c', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


class ConnectionRuleRPC(unittest.TestCase):
    setUp = fixtures.ExtensionsRPC.setUp
    tearDown = fixtures.ExtensionsRPC.tearDown
    def test_save_delete_and_public_settings_keep_manual_values(self):
        sid = atlas.state()['settings']['sections'][0]['id']
        saved = atlas.dispatch('connection_rule', dict(operation='save', section=sid, id='', target=dict(domains=['example.org'], cidrs=['1.1.1.1/32'])))
        public = atlas.public_status()['settings']
        self.assertIn('connection_rules_revision', public['sections'][0])
        atlas.dispatch('save_settings', dict(settings=public))
        self.assertEqual(len(atlas.state()['settings']['sections'][0]['connection_rules']), 1)
        atlas.dispatch('connection_rule', dict(operation='delete', section=sid, id=saved['id'], target={}))
        self.assertEqual(atlas.state()['settings']['sections'][0]['connection_rules'], [])
    def test_stale_form_does_not_erase_new_monitor_assignment(self):
        public = atlas.public_status()['settings']
        sid = public['sections'][0]['id']
        atlas.dispatch('connection_rule', dict(operation='save', section=sid, id='', target=dict(domains=['example.org'])))
        with self.assertRaises(core.AtlasError):
            atlas.dispatch('save_settings', dict(settings=public))
        self.assertEqual(len(atlas.state()['settings']['sections'][0]['connection_rules']), 1)
    def test_old_client_omitting_owned_field_preserves_it(self):
        sid = atlas.state()['settings']['sections'][0]['id']
        atlas.dispatch('connection_rule', dict(operation='save', section=sid, id='', target=dict(domains=['example.org'])))
        public = atlas.public_status()['settings']
        public['sections'][0].pop('connection_rules')
        public['sections'][0].pop('connection_rules_revision')
        atlas.dispatch('save_settings', dict(settings=public))
        self.assertEqual(len(atlas.state()['settings']['sections'][0]['connection_rules']), 1)
    def test_cloning_allocates_new_record_ids(self):
        sid = atlas.state()['settings']['sections'][0]['id']
        atlas.dispatch('connection_rule', dict(operation='save', section=sid, id='', target=dict(domains=['example.org'])))
        atlas.dispatch('section_clone', dict(id=sid, name='Clone'))
        sections = atlas.state()['settings']['sections']
        self.assertNotEqual(sections[0]['connection_rules'][0]['id'], sections[1]['connection_rules'][0]['id'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
