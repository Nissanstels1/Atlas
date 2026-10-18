"""Avoid needless video reconnects without weakening managed selection guards."""
import copy
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
import engine_features
from test_independent_sections import sec
from test_selection import sample


class VideoSelection(unittest.TestCase):
    def test_150ms_is_improvement_margin_not_maximum_rtt(self):
        rows=[(0,0,151,151,'current'),(0,0,73,73,'finland')]
        settings=core.validate_settings({'auto_tolerance_ms':150})
        self.assertEqual(core.rank_auto_candidates(rows,settings,'current'),'current')
        settings['auto_tolerance_ms']=20
        self.assertEqual(core.rank_auto_candidates(rows,settings,'current'),'finland')
        self.assertEqual(core.rank_auto_candidates(rows[1:],settings,'current'),'finland')

    def measured(self, **settings):
        current = sample()
        current['settings'].update(max_ping_ms=1000, auto_tolerance_ms=50, **settings)
        current['settings'] = core.validate_settings(current['settings'])
        nodes = core.all_nodes(current)
        stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        proxies = {node['key']: {'history': [{'delay': delay, 'time': stamp}]}
                   for node, delay in zip(nodes, (130, 129, 999))}
        return current, nodes, proxies

    def test_rank_tolerance_keeps_only_same_priority_qualified_current(self):
        settings = core.validate_settings({'auto_tolerance_ms': 50})
        rows = [(0, 0, 129, 129, 'new'), (0, 0, 130, 130, 'current')]
        self.assertEqual(core.rank_auto_candidates(rows, settings, 'current'), 'current')
        self.assertEqual(core.rank_auto_candidates(rows, settings, 'missing'), 'new')
        self.assertIsNone(core.rank_auto_candidates([], settings, 'current'))
        self.assertEqual(core.rank_auto_candidates([(0, 0, 60, 60, 'new'), rows[1]], settings, 'current'), 'new')
        for lower_priority in ((1, 0, 100, 100, 'current'), (0, 1, 100, 100, 'current')):
            self.assertEqual(core.rank_auto_candidates([rows[0], lower_priority], settings, 'current'), 'new')
        self.assertEqual(core.rank_auto_candidates([(0, 0, -130, 130, 'new'), (0, 0, -129, 129, 'current')], settings, 'current'), 'current')

    def test_auto_choice_tolerance_does_not_retain_stale_or_disallowed_current(self):
        current, nodes, proxies = self.measured()
        previous = nodes[0]['key']
        self.assertEqual(atlas.auto_choice(nodes, current['settings'], proxies, previous=previous), previous)
        proxies[previous]['history'][-1]['time'] = '2020-01-01T00:00:00Z'
        self.assertEqual(atlas.auto_choice(nodes, current['settings'], proxies, previous=previous), nodes[1]['key'])
        proxies[previous]['history'][-1]['time'] = proxies[nodes[1]['key']]['history'][-1]['time']
        proxies[previous]['history'][-1]['delay'] = 1001
        self.assertEqual(atlas.auto_choice(nodes, current['settings'], proxies, previous=previous), nodes[1]['key'])
        self.assertEqual(atlas.auto_choice(nodes[1:], current['settings'], proxies, previous=previous), nodes[1]['key'])

    def test_guarded_selection_honours_section_override_and_avoids_put(self):
        current, nodes, proxies = self.measured(sections=[sec(id='a' * 16, pools=[], auto_tolerance_ms=100)])
        previous = nodes[0]['key']
        control = 'section_' + 'a' * 16 + '_control'
        proxies.update(proxy={'now': previous}, **{control: {'now': previous}})
        calls = []
        def request(method='GET', path='/proxies', body=None, **kwargs):
            if method == 'GET':
                return {'proxies': proxies}
            calls.append((path, body))
            return {}
        with mock.patch.object(atlas, 'service_running', return_value=True), \
                mock.patch.object(atlas, 'clash_request', side_effect=request), mock.patch.object(atlas, 'atomic'):
            result = atlas.automatic_select(current)
            self.assertFalse(result['changed'])
            self.assertEqual(calls, [])
            proxies[nodes[1]['key']]['history'][-1]['delay'] = 60
            result = atlas.automatic_select(current)
        main = next(group for group in result['groups'] if group['group'] == 'proxy')
        section = next(group for group in result['groups'] if group['group'] == control)
        self.assertEqual(main['selected'], nodes[1]['key'])
        self.assertTrue(main['changed'])
        self.assertEqual(section['selected'], previous)
        self.assertFalse(section['changed'])
        self.assertEqual(calls, [('/proxies/proxy', {'name': nodes[1]['key']})])

    def config(self, sections, **settings):
        current = sample()
        current['settings'].update(sections=sections, **settings)
        current['settings'] = core.validate_settings(current['settings'])
        with mock.patch.object(engine_features, 'capabilities', return_value={'urltest.background', 'urltest.fallbacks'}):
            config = core.make_config(current, tun=False)
        return current, config

    def test_distinct_urls_have_private_nodes_and_same_url_reuses_nodes(self):
        a, b, same = ('a' * 16, 'b' * 16, 'c' * 16)
        global_url = core.defaults()['settings']['urltest_url']
        current, config = self.config([
            sec('A', id=a, urltest_url='https://one.example.org/check'),
            sec('B', id=b, urltest_url='https://two.example.org/check'),
            sec('C', id=same, urltest_url=global_url)])
        groups = {item['tag']: item for item in config['outbounds'] if item['type'] == 'urltest'}
        main = set(groups['auto']['outbounds'])
        first = set(groups['section_' + a + '_auto']['outbounds'])
        second = set(groups['section_' + b + '_auto']['outbounds'])
        self.assertFalse(main & first or main & second or first & second)
        self.assertEqual(set(groups['section_' + same + '_auto']['outbounds']), main)
        self.assertTrue(all(tag.startswith('section_' + a + '_') for tag in first))
        for outbound in config['outbounds']:
            if outbound['tag'] in first | second:
                self.assertNotIn('udp_over_tcp', outbound)

    def test_url_only_isolation_preserves_transport_and_reserve_members(self):
        current = sample()
        current['subscriptions'][0]['nodes'] = [core.uri_node('socks5://fixture:fixture@127.0.0.1:%d#node%d' % (10000 + i, i)) for i in range(2)]
        nodes = core.all_nodes(current)
        sid = 'a' * 16
        current['settings'].update(udp_over_tcp=True, sections=[sec(id=sid, urltest_url='https://one.example.org/check', urltest_fallbacks=[nodes[1]['key']])])
        with mock.patch.object(engine_features, 'capabilities', return_value={'urltest.fallbacks'}):
            config = core.make_config(current, tun=False)
        prefix = 'section_' + sid + '_'
        group = next(item for item in config['outbounds'] if item['tag'] == prefix + 'auto')
        self.assertEqual(group['outbounds'], [prefix + nodes[0]['key']])
        self.assertEqual(group['fallbacks'], [prefix + nodes[1]['key']])
        concrete = {item['tag']: item for item in config['outbounds'] if item['type'] == 'socks'}
        self.assertEqual(concrete[prefix + nodes[0]['key']]['udp_over_tcp'], {'enabled': True, 'version': 2})

    def test_manual_choice_survives_adding_and_removing_private_test(self):
        current = sample()
        key = core.all_nodes(current)[0]['key']
        sid = 'a' * 16
        control = 'section_' + sid + '_control'
        current['settings'].update(sections=[sec(id=sid, urltest_url='https://one.example.org/check')], section_choices={control: key})
        original = copy.deepcopy(current['settings'])
        validated = core.validate_settings(current['settings'])
        self.assertEqual(current['settings'], original)
        private = 'section_' + sid + '_' + key
        self.assertEqual(validated['section_choices'][control], private)
        current['settings'] = validated
        with mock.patch.object(engine_features, 'capabilities', return_value=[]):
            config = core.make_config(current, tun=False)
        self.assertEqual(next(item for item in config['outbounds'] if item['tag'] == control)['default'], private)
        validated['sections'][0]['urltest_url'] = ''
        self.assertEqual(core.validate_settings(validated)['section_choices'][control], key)

    def test_guarded_selection_uses_url_private_nodes_and_reserve_identity(self):
        sid = 'a' * 16
        current, nodes, proxies = self.measured(sections=[sec(id=sid, urltest_url='https://one.example.org/check')])
        prefix = 'section_' + sid + '_'
        for node in nodes:
            proxies[prefix + node['key']] = proxies[node['key']]
        control = prefix + 'control'
        proxies[control] = {'now': prefix + nodes[0]['key']}
        with mock.patch.object(atlas, 'service_running', return_value=True), \
                mock.patch.object(atlas, 'clash_request', return_value={'proxies': proxies}), mock.patch.object(atlas, 'atomic'):
            result = atlas.automatic_select(current)
        group = next(item for item in result['groups'] if item['group'] == control)
        self.assertEqual(group['selected'], prefix + nodes[0]['key'])
        self.assertFalse(group['changed'])
