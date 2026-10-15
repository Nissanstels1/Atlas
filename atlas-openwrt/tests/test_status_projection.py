"""Large list status remains compact and round-trips without changing rules."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import test_extensions_rpc as fixtures


class StatusProjection(unittest.TestCase):
    setUp = fixtures.ExtensionsRPC.setUp
    tearDown = fixtures.ExtensionsRPC.tearDown

    def test_large_rule_body_is_hidden_and_preserved_after_settings_save(self):
        self.initial['settings']['remote_lists'] = [dict(
            id='c' * 16, name='Large list', url='https://example.org/list?secret=SOURCE_SECRET',
            policy='proxy', format='domains', enabled=True,
            domains=['site%d.example' % i for i in range(1000)], cidrs=['203.0.113.0/24'])]
        atlas.atomic(atlas.STATE, self.initial)
        before = atlas.state()
        public = atlas.public_status()
        source = public['settings']['remote_lists'][0]
        self.assertEqual(source['count'], 1001)
        self.assertFalse({'domains', 'cidrs', 'source_rules'} & source.keys())
        encoded = json.dumps(public)
        self.assertNotIn('SOURCE_SECRET', encoded)
        self.assertNotIn('site999.example', encoded)
        self.assertLess(len(json.dumps(source)), 1500)
        self.assertEqual(atlas.state(), before)
        source['name'] = 'Renamed list'
        atlas.dispatch('save_settings', {'settings': public['settings']})
        saved = atlas.state()['settings']['remote_lists'][0]
        self.assertEqual(saved['domains'], before['settings']['remote_lists'][0]['domains'])
        self.assertEqual(saved['cidrs'], ['203.0.113.0/24'])
        self.assertEqual(saved['name'], 'Renamed list')

    def test_status_audit_reuses_normalized_settings_with_same_result(self):
        current = atlas.state()
        config = atlas.runtime_config(current)
        expected = atlas.privacy_checks(current['settings'], config, True)
        self.assertEqual(atlas.privacy_checks(current['settings'], config, True, validated=True), expected)
        with self.assertRaises(atlas.AtlasError):
            atlas.privacy_checks({'mode': 'invalid'}, config)

    def test_public_mutable_metadata_does_not_alias_persisted_state(self):
        current = atlas.state()
        before = copy.deepcopy(current)
        with mock.patch.object(atlas, 'state', return_value=current):
            public = atlas.public_status()
        public['settings']['sections'][0]['domains'].append('new.example')
        public['settings']['sections'][0]['mixed_proxy']['username'] = 'changed'
        self.assertEqual(current, before)

    def test_runtime_subscription_groups_keep_actual_choices(self):
        current = atlas.state()
        atlas.atomic(atlas.CONFIG, atlas.runtime_config(current))
        nodes = atlas.all_nodes(current)
        chosen = nodes[0]['key']
        groups = {('pool_%016x' % i): {'now': chosen} for i in range(64)}
        groups['proxy'] = {'now': chosen}
        groups[chosen] = {'history': []}
        groups['pool_0000000000000001']['now'] = 'policy-block'
        groups['pool_0000000000000002']['now'] = 'auto_0000000000000002'
        groups['auto_0000000000000002'] = {'now': chosen}
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps({'proxies': groups}).encode()
        with mock.patch.object(atlas.http.client, 'HTTPConnection', return_value=connection):
            result = atlas.runtime_status(nodes, True)
        self.assertTrue(result['available'])
        self.assertEqual(len(result['groups']), 64)
        self.assertEqual(result['groups'][0]['selected'], chosen)
        self.assertTrue(result['groups'][1]['blocked'])
        self.assertEqual(result['groups'][2]['selected'], chosen)
        connection.close.assert_called_once()
