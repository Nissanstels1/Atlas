"""Transactional imports, measured country policy and real DNS response validation."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
from test_selection import sample


class ImportAndCountry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name)
        self.patches = [mock.patch.object(atlas, 'DATA', path), mock.patch.object(atlas, 'RUN', path),
                        mock.patch.object(atlas, 'STATE', path / 'state.json'),
                        mock.patch.object(atlas, 'CONFIG', path / 'config.json')]
        for patch in self.patches:
            patch.start()
        atlas.atomic(atlas.STATE, sample())

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        self.tmp.cleanup()

    def test_inline_json_import_is_validated_and_never_fetched(self):
        content = json.dumps({'outbounds': [sample()['subscriptions'][0]['nodes'][0]['outbound']]})
        with mock.patch.object(atlas, 'fetch') as fetch, mock.patch.object(atlas, 'check') as check:
            result = atlas.dispatch('import_profiles', {'name': 'Local', 'content': content})
        self.assertEqual(result['count'], 1)
        check.assert_called_once()
        fetch.assert_not_called()
        local = atlas.state()['subscriptions'][-1]
        self.assertEqual((local['source'], local['url']), ('local', ''))
        with mock.patch.object(atlas, 'fetch') as fetch, mock.patch.object(atlas, 'service_running', return_value=False):
            atlas.refresh(atlas.state(), local['id'])
        fetch.assert_not_called()
        with mock.patch.object(atlas, 'service_running', return_value=False), mock.patch.object(atlas, 'engine_version', return_value='test'):
            public = atlas.public_status()['subscriptions'][-1]
        self.assertEqual(public['host'], 'Локальный импорт')
        self.assertNotIn('outbound', json.dumps(public))

    def test_invalid_or_oversized_inline_content_does_not_modify_state(self):
        before = atlas.STATE.read_bytes()
        for content in ('invalid', 'x' * (atlas.MAX_INLINE_PROFILE_BYTES + 1), None):
            with self.subTest(content_type=type(content).__name__), self.assertRaises(core.AtlasError):
                atlas.dispatch('import_profiles', {'name': 'Local', 'content': content})
            self.assertEqual(atlas.STATE.read_bytes(), before)
        content = json.dumps({'outbounds': [sample()['subscriptions'][0]['nodes'][0]['outbound']]})
        with mock.patch.object(atlas, 'check', side_effect=core.AtlasError('bad engine config')):
            with self.assertRaises(core.AtlasError):
                atlas.dispatch('import_profiles', {'name': 'Local', 'content': content})
        self.assertEqual(atlas.STATE.read_bytes(), before)

    def test_local_source_can_be_disabled_without_becoming_remote(self):
        current = atlas.state()
        current['subscriptions'][0].update(source='local', url='')
        atlas.atomic(atlas.STATE, current)
        atlas.dispatch('save_subscription', {'id': current['subscriptions'][0]['id'], 'name': 'Local', 'enabled': False})
        saved = atlas.state()['subscriptions'][0]
        self.assertFalse(saved['enabled'])
        self.assertEqual(saved['source'], 'local')

    def test_measured_country_overrides_misleading_name(self):
        node = core.all_nodes(sample())[0]
        node.update(verified_country='RU', country_verified_at=int(time.time()))
        settings = core.validate_settings({'excluded_countries': ['RU']})
        self.assertEqual(core.country_for_node(node), 'RU')
        self.assertEqual(core.country_source_for_node(node), 'exit-ip')
        self.assertEqual(core.filter_nodes([node], settings), [])

    def test_strict_country_filter_rejects_missing_stale_or_future_evidence(self):
        node = core.all_nodes(sample())[0]
        settings = core.validate_settings({'excluded_countries': ['RU'], 'require_verified_countries': True})
        for stamp in (None, True, int(time.time()) - core.COUNTRY_VERIFICATION_TTL - 5, int(time.time()) + 600):
            node.update(verified_country='EE', country_verified_at=stamp)
            self.assertEqual(core.filter_nodes([node], settings), [])
        node.update(verified_country='EE', country_verified_at=int(time.time()))
        self.assertEqual(core.filter_nodes([node], settings), [node])
        with self.assertRaises(core.AtlasError):
            core.validate_settings({'require_verified_countries': 'true'})

    def test_subscription_refresh_keeps_local_evidence_for_unchanged_outbound(self):
        current = atlas.state()
        current['subscriptions'][0]['nodes'][0].update(verified_country='EE', country_verified_at=int(time.time()))
        payload = json.dumps({'outbounds': [n['outbound'] for n in current['subscriptions'][0]['nodes']]}).encode()
        with mock.patch.object(atlas, 'fetch', return_value=(payload, {})), mock.patch.object(atlas, 'check'), mock.patch.object(atlas, 'service_running', return_value=False):
            atlas.refresh(current)
        node = atlas.state()['subscriptions'][0]['nodes'][0]
        self.assertEqual(node['verified_country'], 'EE')

    def test_geo_lookup_sends_country_path_and_validates_response(self):
        with mock.patch.object(atlas, 'proxied_https_get', return_value=b'EE\n') as request:
            self.assertEqual(atlas.proxied_exit_country({}), 'EE')
        request.assert_called_once_with({}, 'ipapi.co', '/country/', 16)
        with mock.patch.object(atlas, 'proxied_https_get', return_value=b'error'):
            with self.assertRaises(core.AtlasError):
                atlas.proxied_exit_country({})

    def test_country_results_store_no_public_ip_and_apply_filters(self):
        current = atlas.state()
        current['settings']['excluded_countries'] = ['RU']
        key = core.all_nodes(current)[0]['key']
        with mock.patch.object(atlas, 'service_running', return_value=True), mock.patch.object(atlas, 'apply') as apply:
            atlas.save_exit_country(current, key, 'EE')
        apply.assert_called_once()
        saved = atlas.state()['subscriptions'][0]['nodes'][0]
        self.assertEqual(saved['verified_country'], 'EE')
        self.assertIsInstance(saved['country_verified_at'], int)
        self.assertNotIn('exit_ip', saved)

    def test_empty_country_pool_is_guarded_and_cannot_be_watchdog_restored(self):
        current = atlas.state()
        current['settings']['countries'] = ['EE']
        key = core.all_nodes(current)[0]['key']
        with mock.patch.object(atlas, 'service_running', side_effect=[True, False]), mock.patch.object(atlas, 'manage_kill_switch') as guard, mock.patch.object(atlas, 'run') as run:
            message = atlas.save_exit_country(current, key, 'RU')
        guard.assert_called_once_with(True)
        self.assertTrue(atlas.state()['settings']['kill_switch'])
        self.assertIn('Пул пуст', message)
        self.assertEqual(run.call_args_list[0].args[0], ['/etc/init.d/atlas', 'disable'])
        self.assertEqual(run.call_args_list[1].args[0], ['/etc/init.d/atlas', 'stop'])

    def test_failed_apply_cannot_restore_a_now_disallowed_exit(self):
        current = atlas.state()
        current['settings']['excluded_countries'] = ['RU']
        key = core.all_nodes(current)[0]['key']
        with mock.patch.object(atlas, 'service_running', side_effect=[True, False]), mock.patch.object(atlas, 'manage_kill_switch') as guard, mock.patch.object(atlas, 'run') as run, mock.patch.object(atlas, 'apply', side_effect=core.AtlasError('restart failed')):
            with self.assertRaisesRegex(core.AtlasError, 'fail-closed'):
                atlas.save_exit_country(current, key, 'RU')
        guard.assert_called_once_with(True)
        self.assertIn(mock.call(['/etc/init.d/atlas', 'disable']), run.call_args_list)
        self.assertTrue(atlas.state()['settings']['kill_switch'])

    def test_expired_country_pool_cannot_continue_using_old_runtime(self):
        current = atlas.state()
        for node in current['subscriptions'][0]['nodes']:
            node.update(verified_country='EE', country_verified_at=int(time.time()))
        current['settings'].update(countries=['EE'], require_verified_countries=True)
        cfg = core.make_config(current)
        for node in current['subscriptions'][0]['nodes']:
            node['country_verified_at'] -= core.COUNTRY_VERIFICATION_TTL + 1
        with mock.patch.object(atlas, 'manage_kill_switch'), mock.patch.object(atlas, 'run'), mock.patch.object(atlas, 'service_running', return_value=False), mock.patch.object(atlas, 'apply') as apply:
            result = atlas.enforce_verified_country_policy(current, cfg)
        self.assertEqual(result['reason'], 'country-pool-blocked')
        apply.assert_not_called()

    def test_probe_tls_helper_keeps_country_path_and_bounds_response(self):
        node = core.all_nodes(sample())[0]
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 23111)
        process = mock.Mock()
        process.poll.return_value = None
        connection = mock.Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b'EE'
        with mock.patch.object(atlas.socket, 'socket', return_value=fake_socket), mock.patch.object(atlas.socket, 'create_connection'), mock.patch.object(atlas.subprocess, 'Popen', return_value=process), mock.patch.object(atlas.http.client, 'HTTPSConnection', return_value=connection):
            result = atlas.proxied_https_get(node, 'ipapi.co', '/country/', 16, directory=self.tmp.name)
        self.assertEqual(result, b'EE')
        self.assertEqual(connection.request.call_args.args, ('GET', '/country/'))
        connection.set_tunnel.assert_called_once_with('ipapi.co', 443)
        process.terminate.assert_called_once()
        for hostname, path, limit in [('bad\r\nHost: x', '/', 10), ('ipapi.co', '//other', 10), ('ipapi.co', '/country/?secret=x', 10), ('ipapi.co', '/', 0)]:
            with self.assertRaises(core.AtlasError):
                atlas.proxied_https_get(node, hostname, path, limit)

    def test_new_import_method_is_administrator_only(self):
        acl = json.loads((Path(__file__).resolve().parents[1] / 'root/usr/share/rpcd/acl.d/atlas.json').read_text())['luci-app-atlas']
        self.assertIn('import_profiles', acl['write']['ubus']['atlas'])
        self.assertNotIn('import_profiles', acl['read']['ubus']['atlas'])


class LocalDNS(unittest.TestCase):
    def test_local_dns_query_accepts_valid_fakeip_and_rejects_other_question(self):
        fake_socket = mock.MagicMock()
        sock = fake_socket.__enter__.return_value
        def response(_):
            query = sock.send.call_args.args[0]
            txid = struct.unpack('!H', query[:2])[0]
            return struct.pack('!HHHHHH', txid, 0x8180, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\xc6\x12\x00\x07'
        sock.recv.side_effect = response
        with mock.patch.object(atlas.socket, 'socket', return_value=fake_socket):
            self.assertEqual(atlas.query_local_dns_a('check.example.com'), ['198.18.0.7'])
        sock.connect.assert_called_once_with(('127.0.0.1', 53))
        for packet in (b'', struct.pack('!HHHHHH', 0, 0x8180, 1, 1, 0, 0), b'\0' * 4096):
            sock.recv.side_effect = None
            sock.recv.return_value = packet
            with mock.patch.object(atlas.socket, 'socket', return_value=fake_socket), self.assertRaises(core.AtlasError):
                atlas.query_local_dns_a('check.example.com')

    def test_fakeip_selftest_requires_actual_local_range(self):
        current = sample()
        current['settings'].update(fakeip=True, mode='global')
        cfg = core.make_config(current)
        with mock.patch.object(atlas, 'read_json', return_value=cfg), mock.patch.object(atlas, 'check'), mock.patch.object(atlas, 'service_running', return_value=False), mock.patch.object(atlas, 'system_interfaces', return_value=set()), mock.patch.object(atlas.socket, 'getaddrinfo', side_effect=OSError()), mock.patch.object(atlas, 'query_local_dns_a') as query:
            for addresses, expected in [(['198.18.0.8'], True), (['203.0.113.4'], False), ([], False), (['198.18.0.8', '203.0.113.4'], False)]:
                query.return_value = addresses
                result = atlas.selftest(current)
                self.assertEqual(next(x for x in result['checks'] if x['id'] == 'fakeip_dns')['ok'], expected)
                self.assertTrue(query.call_args.args[0].endswith('.example.com'))


if __name__ == '__main__':
    unittest.main()
