from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core


def state():
    s = core.defaults()
    s['subscriptions'] = [{'id': 'a' * 16, 'name': 'Test', 'enabled': True,
                           'url': 'https://example.com/sub',
                           'nodes': [core.uri_node('vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&sni=example.com#Node')]}]
    return s


class PrivacyFeatures(unittest.TestCase):
    def test_default_secure_dns_without_fakeip_or_ad_filter(self):
        c = core.make_config(state())
        secure = next(x for x in c['dns']['servers'] if x['tag'] == 'secure')
        self.assertEqual(secure['type'], 'https')
        self.assertEqual(secure['detour'], 'proxy')
        bootstrap = next(x for x in c['dns']['servers'] if x['tag'] == 'bootstrap')
        self.assertEqual((bootstrap['type'], bootstrap['server'], bootstrap['tls']['server_name']), ('https','1.1.1.1','cloudflare-dns.com'))
        self.assertFalse(any(x['type'] == 'fakeip' for x in c['dns']['servers']))

    def test_adguard_filter_uses_encrypted_dns_through_proxy(self):
        s = state(); s['settings']['dns_filter'] = 'adguard'
        secure = next(x for x in core.make_config(s)['dns']['servers'] if x['tag'] == 'secure')
        self.assertEqual(secure['server'], '94.140.14.14')
        self.assertEqual(secure['tls']['server_name'], 'dns.adguard-dns.com')
        self.assertEqual(secure['detour'], 'proxy')

    def test_custom_encrypted_dns_and_client_doh_restriction(self):
        s=state();s['settings'].update(dns_filter='custom',custom_dns_type='tls',custom_dns_server='9.9.9.9',
            custom_dns_sni='dns.quad9.net',block_known_doh=True)
        c=core.make_config(s)
        secure=next(x for x in c['dns']['servers'] if x['tag']=='secure')
        self.assertEqual(secure['type'],'tls');self.assertEqual(secure['detour'],'proxy')
        checks={x['id']:x['ok'] for x in core.privacy_checks(s['settings'],c)['checks']}
        self.assertTrue(checks['encrypted_dns_bypass'])

    def test_blocked_domains_are_rejected_before_fakeip(self):
        s = state(); s['settings'].update(blocked_domains=['ads.example'], domains=['video.example'], fakeip=True)
        c = core.make_config(s); rules = c['dns']['rules']
        self.assertEqual(rules[0], {'domain_suffix': ['ads.example'], 'action': 'reject'})
        self.assertEqual(rules[1]['domain_suffix'], ['video.example'])
        self.assertEqual(rules[1]['server'], 'fakeip')
        self.assertEqual(c['dns']['servers'][-1]['type'], 'fakeip')

    def test_fakeip_covers_all_names_only_in_global_mode(self):
        s = state(); s['settings'].update(mode='global', fakeip=True)
        c = core.make_config(s)
        self.assertEqual(c['dns']['rules'][0], {'action': 'route', 'server': 'fakeip', 'rewrite_ttl': 60})
        s['settings']['fakeip_ttl_seconds'] = 20
        self.assertEqual(core.make_config(s)['dns']['rules'][0]['rewrite_ttl'], 20)

    def test_real_ip_resolution_uses_secure_dns_not_fakeip(self):
        s=state();s['settings'].update(resolve_real_ip=True, fakeip=True, domains=['media.example'])
        c=core.make_config(s)
        self.assertEqual(c['route']['default_domain_resolver'],'bootstrap')
        self.assertTrue(core.real_ip_resolution_active(c))
        self.assertEqual(next(x for x in c['dns']['servers'] if x['tag']=='secure')['detour'],'proxy')
        checks={x['id']:x['ok'] for x in core.privacy_checks(s['settings'],c)['checks']}
        self.assertTrue(checks['real_ip_resolution'])

    def test_privacy_audit_checks_dns_and_full_routing(self):
        s = state(); s['settings'].update(mode='global', dns_filter='adguard', fakeip=True)
        c = core.make_config(s)
        result = core.privacy_checks(s['settings'], c, running=True)
        checks = {item['id']: item['ok'] for item in result['checks']}
        self.assertTrue(checks['running'])
        self.assertTrue(checks['dns_hijack'])
        self.assertTrue(checks['dnsmasq_ingress'])
        self.assertTrue(checks['encrypted_dns'])
        self.assertTrue(checks['bootstrap_dns'])
        self.assertTrue(checks['strict_route'])
        self.assertTrue(checks['adblock'])
        self.assertTrue(checks['fakeip'])
        self.assertTrue(checks['fakeip_persistence'])
        self.assertTrue(checks['fakeip_ttl'])
        self.assertTrue(checks['real_ip_resolution'])
        self.assertTrue(checks['coverage'])
        self.assertIn('не проверка', result['notice'])

    def test_fakeip_is_warned_when_proxy_domain_list_is_empty(self):
        s = state(); s['settings']['fakeip'] = True
        c = core.make_config(s)
        result = core.privacy_checks(s['settings'], c)
        checks = {item['id']: item['ok'] for item in result['checks']}
        self.assertFalse(checks['fakeip'])

    def test_external_ip_test_reports_only_difference_not_addresses(self):
        node = {'key': 'node'}
        result = __import__('atlas').privacy_egress_test(node, lambda: '203.0.113.1', lambda n: '198.51.100.2')
        self.assertTrue(result['ok'])
        self.assertFalse(result['same_exit'])
        self.assertNotIn('203.0.113.1', str(result))
        self.assertNotIn('198.51.100.2', str(result))

    def test_external_ip_test_handles_equal_address_and_failure(self):
        atlas = __import__('atlas')
        equal = atlas.privacy_egress_test({'key': 'node'}, lambda: '203.0.113.1', lambda n: '203.0.113.1')
        self.assertFalse(equal['ok'])
        self.assertTrue(equal['same_exit'])
        failed = atlas.privacy_egress_test({'key': 'node'}, mock.Mock(side_effect=OSError()), lambda n: '198.51.100.2')
        self.assertEqual(failed['status'], 'error')
        self.assertNotIn('198.51.100.2', str(failed))

    def test_router_selftest_separately_checks_config_dns_api_tun_and_https(self):
        atlas=__import__('atlas');current=state();config=core.make_config(current,api_secret='a'*64)
        with tempfile.TemporaryDirectory() as temp:
            config_path=Path(temp)/'config.json';config_path.write_text(__import__('json').dumps(config))
            with mock.patch.object(atlas,'CONFIG',config_path),mock.patch.object(atlas,'service_running',return_value=True), \
                 mock.patch.object(atlas,'check'),mock.patch.object(atlas,'clash_request',return_value={'proxies':{}}), \
                 mock.patch.object(atlas,'system_interfaces',return_value={'atlas0'}), \
                 mock.patch.object(atlas.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.1',443))]), \
                 mock.patch.object(atlas,'runtime_status',return_value={'selected':core.all_nodes(current)[0]['key']}), \
                 mock.patch.object(atlas,'probe',return_value={'ok':True,'latency_ms':42}):
                result=atlas.selftest(current)
        self.assertTrue(result['ok']);self.assertEqual({x['id'] for x in result['checks']},
            {'config','service','kill_switch','controller','tun','dns_hijack','router_dns','dns_tls','real_ip_resolution','dhcp_dnsmasq','fakeip_dns','outbound_https'})
        self.assertNotIn('203.0.113.',str(result))


if __name__ == '__main__':
    unittest.main()
