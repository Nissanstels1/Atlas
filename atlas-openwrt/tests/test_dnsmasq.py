import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core


def command_result(args, output=b''):
    return subprocess.CompletedProcess(args, 0, stdout=output, stderr=b'')


def dnsmasq_show(server=None, noresolv=None, cachesize=None):
    lines = ['dhcp.@dnsmasq[0]=dnsmasq']
    for key, value in [('server', server), ('noresolv', noresolv), ('cachesize', cachesize)]:
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        lines.extend("dhcp.@dnsmasq[0].%s='%s'" % (key, item) for item in values)
    return ('\n'.join(lines) + '\n').encode()


class DnsmasqIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.backup = Path(self.temp.name) / 'dhcp-dns-backup.json'
        self.patcher = mock.patch.object(atlas, 'DHCP_BACKUP', self.backup)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(self.temp.cleanup)

    def test_enable_saves_prior_values_then_sets_all_dnsmasq_sections(self):
        output = dnsmasq_show(['1.1.1.1', '9.9.9.9'], '0', '150')
        calls = []

        def run(args, timeout=10):
            calls.append(args)
            return command_result(args, output if args[-2:] == ['show', 'dhcp'] else b'')

        with mock.patch.object(atlas, 'run', side_effect=run):
            result = atlas.manage_dhcp_dns(True)
        self.assertEqual(result, {'enabled': True, 'restored': False, 'changed_by_admin': []})
        saved = json.loads(self.backup.read_text())['sections'][0]['options']
        self.assertEqual(saved['server'], {'present': True, 'values': ['1.1.1.1', '9.9.9.9']})
        self.assertEqual(saved['noresolv'], {'present': True, 'values': ['0']})
        self.assertEqual(saved['cachesize'], {'present': True, 'values': ['150']})
        self.assertIn(['/sbin/uci', 'add_list', 'dhcp.@dnsmasq[0].server=127.0.0.42'], calls)
        self.assertIn(['/sbin/uci', 'set', 'dhcp.@dnsmasq[0].noresolv=1'], calls)
        self.assertIn(['/sbin/uci', 'set', 'dhcp.@dnsmasq[0].cachesize=0'], calls)
        self.assertIn(['/etc/init.d/dnsmasq', 'restart'], calls)

    def test_dnsmasq_setting_builds_loopback_inbound_and_fake_dns_audit(self):
        current = core.defaults()
        current['settings']['dhcp_dns_enabled'] = True
        current['subscriptions'] = [{'id': 'a' * 16, 'name': 'Test', 'enabled': True,
                                     'nodes': [core.uri_node('vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&sni=example.com#Test')]}]
        config = core.make_config(current)
        self.assertIn({'type': 'direct', 'tag': 'dhcp-dns', 'listen': '127.0.0.42', 'listen_port': 53}, config['inbounds'])
        self.assertIn({'inbound': ['dhcp-dns'], 'action': 'hijack-dns'}, config['route']['rules'])
        checks = {item['id']: item['ok'] for item in core.privacy_checks(current['settings'], config)['checks']}
        self.assertTrue(checks['dnsmasq_ingress'])

    def test_storage_modes_use_ram_cache_or_validated_external_database_path(self):
        settings = core.validate_settings({'config_storage': 'ram', 'cache_storage': 'ram'})
        probe = {'id': 'a' * 32, 'key': 'a' * 32, 'outbound': {'type': 'direct', 'tag': 'probe'}}
        self.assertEqual(core.make_config({'settings': settings, 'subscriptions': []}, probe_node=probe)['experimental']['cache_file']['path'], '/tmp/atlas/cache.db')
        settings = core.validate_settings({'cache_storage': 'external', 'cache_custom_path': '/mnt/usb/atlas-cache.db'})
        self.assertEqual(core.make_config({'settings': settings, 'subscriptions': []}, probe_node=probe)['experimental']['cache_file']['path'], '/mnt/usb/atlas-cache.db')
        self.assertEqual(core.validate_settings({'cache_storage': 'external', 'cache_custom_path': '/tmp/cache.db'})['cache_custom_path'],'/tmp/cache.db')
        with self.assertRaises(core.AtlasError):
            core.validate_settings({'cache_storage': 'external', 'cache_custom_path': '/tmp/../cache.db'})

    def test_disable_restores_only_values_still_owned_by_atlas(self):
        self.backup.write_text(json.dumps({'sections': [{'section': '@dnsmasq[0]', 'options': {
            'server': {'present': True, 'values': ['9.9.9.9']},
            'noresolv': {'present': False, 'values': []},
            'cachesize': {'present': True, 'values': ['100']}}}]}))
        calls = []

        def run(args, timeout=10):
            calls.append(args)
            # An administrator changed `server` after Atlas took ownership.
            live = dnsmasq_show(['127.0.0.42', '192.0.2.53'], '1', '0')
            return command_result(args, live if args[-2:] == ['show', 'dhcp'] else b'')

        with mock.patch.object(atlas, 'run', side_effect=run):
            result = atlas.manage_dhcp_dns(False)
        self.assertEqual(result['changed_by_admin'], ['@dnsmasq[0].server'])
        self.assertIn(['/sbin/uci', '-q', 'delete', 'dhcp.@dnsmasq[0].noresolv'], calls)
        self.assertIn(['/sbin/uci', 'set', 'dhcp.@dnsmasq[0].cachesize=100'], calls)
        self.assertNotIn(['/sbin/uci', '-q', 'delete', 'dhcp.@dnsmasq[0].server'], calls)
        self.assertFalse(self.backup.exists())

    def test_enable_refuses_to_overwrite_dnsmasq_changes_during_existing_ownership(self):
        self.backup.write_text(json.dumps({'sections': [{'section': '@dnsmasq[0]', 'options': {}}]}))
        output = dnsmasq_show('192.0.2.53', '1', '0')
        with mock.patch.object(atlas, 'run', return_value=command_result([], output)):
            with self.assertRaises(atlas.AtlasError):
                atlas.manage_dhcp_dns(True)

    def test_monitor_returns_bounded_live_snapshot(self):
        payloads = {
            '/connections': {'connections': [{'id': str(i), 'metadata': {'network': 'tcp', 'host': '<x.example>'},
                                                'source': '192.168.1.2:12345', 'chains': ['proxy'],
                                                'upload': 10, 'download': 20} for i in range(105)],
                             'uploadTotal': 1000, 'downloadTotal': 2000},
            '/rules': {'rules': [{'type': 'domain', 'payload': 'example.org', 'proxy': 'proxy'} for _ in range(130)]},
        }

        def request(method='GET', path='/proxies', body=None, timeout=2):
            return payloads[path]

        with mock.patch.object(atlas, 'service_running', return_value=True), mock.patch.object(atlas, 'clash_request', side_effect=request), \
             mock.patch.object(atlas, 'process_memory', return_value={'inuse': 4096}):
            snapshot = atlas.dispatch('monitor', {})
        self.assertTrue(snapshot['available'])
        self.assertTrue(snapshot['truncated'])
        self.assertEqual(len(snapshot['connections']), 50)
        self.assertEqual(len(snapshot['rules']), 60)
        self.assertEqual(snapshot['memory'], {'inuse': 4096})
        self.assertIn('<x.example>', snapshot['connections'][0]['host'])
        acl = json.loads((Path(__file__).resolve().parents[1] / 'root/usr/share/rpcd/acl.d/atlas.json').read_text())['luci-app-atlas']
        self.assertNotIn('monitor', acl['read']['ubus']['atlas'])
        self.assertIn('monitor', acl['write']['ubus']['atlas'])

    def test_clash_api_requests_close_connection_after_bounded_json_body(self):
        config = Path(self.temp.name) / 'config.json'
        config.write_text(json.dumps({'experimental': {'clash_api': {
            'external_controller': '127.0.0.1:19090', 'secret': 'a' * 64}}}))
        response = mock.Mock(status=200)
        response.read.return_value = b'{}'
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(atlas, 'CONFIG', config), \
             mock.patch.object(atlas.http.client, 'HTTPConnection', return_value=connection):
            self.assertEqual(atlas.clash_request('GET', '/connections'), {})
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual(headers['Connection'], 'close')
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
