import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
import atlas

UUID = '11111111-1111-4111-8111-111111111111'
BASE = 'vless://' + UUID + '@example.com:443'
REALITY = BASE + '?security=reality&pbk=' + 'a' * 43 + '&sid=abcd&fp=chrome&flow=xtls-rprx-vision&type=tcp&headerType=#Test'

def encoded(s):
    return base64.b64encode(s.encode()).decode().rstrip('=')

def state_with_node():
    s = core.defaults()
    s['subscriptions'] = [{'id': 'b' * 16, 'name': 'Test', 'enabled': True, 'url': 'https://example.com/sub/private',
                           'nodes': [core.uri_node(REALITY)]}]
    return s

class Parsing(unittest.TestCase):
    def test_rule_lists_domains_hosts_cidrs_and_adguard(self):
        domains, cidrs = atlas.parse_rule_list('''# comments\nads.example\n||tracker.example^\n0.0.0.0 metrics.example analytics.example\n203.0.113.9/24\n''')
        self.assertEqual(set(domains), {'ads.example','tracker.example','metrics.example','analytics.example'})
        self.assertEqual(cidrs, ['203.0.113.0/24'])

    def test_sing_box_json_rule_list_domains_and_subnets(self):
        payload='{"version":3,"rules":[{"domain_suffix":["example.com","sub.example.net"]},{"ip_cidr":["192.0.2.7/24"]}]}'
        self.assertEqual(atlas.parse_rule_list(payload,'json'),json.loads(payload))
        self.assertEqual(atlas.parse_rule_list('{"rules":[{"process_name":["browser"]}]}','json')['rules'][0]['process_name'],['browser'])
        cfg=core.validate_settings({'remote_lists':[{'name':'JSON list','url':'https://lists.example.org/rules.json','policy':'proxy','format':'json','enabled':True}]})
        self.assertEqual(cfg['remote_lists'][0]['format'],'json')

    def test_rule_lists_reject_empty_and_accept_over_10000(self):
        with self.assertRaises(core.AtlasError): atlas.parse_rule_list('! empty rules\n')
        self.assertEqual(len(atlas.parse_rule_list('\n'.join('d%d.example' % i for i in range(10001)))[0]),10001)

    def test_rule_list_urls_allow_query_but_disallow_credentials_and_local_names(self):
        self.assertEqual(core.rule_list_url('http://example.com/list'),'http://example.com/list')
        self.assertEqual(core.rule_list_url('https://example.com/list?token=secret'),'https://example.com/list?token=secret')
        for url in ('https://user@example.com/list','https://router.local/list'):
            with self.assertRaises(core.AtlasError): core.rule_list_url(url)

    def test_actual_style_reality_empty_header_type(self):
        n = core.uri_node(REALITY)
        self.assertEqual(n['outbound']['tls']['reality']['short_id'], 'abcd')
        self.assertEqual(n['outbound']['flow'], 'xtls-rprx-vision')
        self.assertNotIn('transport', n['outbound'])

    def test_base64_urlsafe_padding_and_dedup(self):
        p = core.parse_subscription(encoded(REALITY + '\n' + REALITY).encode())
        self.assertEqual(len(p['nodes']), 1)
        self.assertEqual(p['format'], 'Base64 URI')

    def test_name_change_preserves_identity(self):
        self.assertEqual(core.uri_node(REALITY)['id'], core.uri_node(REALITY.replace('#Test', '#Other'))['id'])

    def test_ipv6_ws(self):
        n = core.uri_node('vless://' + UUID + '@[2001:db8::1]:8443?security=tls&sni=example.org&type=ws&host=example.org&path=%2Fws#IPv6')
        self.assertEqual(n['outbound']['server'], '2001:db8::1')
        self.assertEqual(n['outbound']['transport']['path'], '/ws')

    def test_vmess(self):
        n = core.uri_node('vmess://' + encoded(json.dumps({'add':'example.com','port':'443','id':UUID,'aid':0,'tls':'tls','net':'ws','path':'/v','ps':'VMess'})))
        self.assertEqual(n['outbound']['type'], 'vmess')

    def test_password_percent_encoding(self):
        n = core.uri_node('trojan://a%40b%3Ac@example.com:443?sni=example.com')
        self.assertEqual(n['outbound']['password'], 'a@b:c')

    def test_shadowsocks_sip002(self):
        n = core.uri_node('ss://' + encoded('aes-128-gcm:p:a:ss') + '@example.com:8388#SS')
        self.assertEqual(n['outbound']['password'], 'p:a:ss')

    def test_legacy_ss(self):
        n = core.uri_node('ss://' + encoded('aes-256-gcm:password@example.com:8388') + '#SS')
        self.assertEqual(n['outbound']['server_port'], 8388)

    def test_hysteria_obfs(self):
        n = core.uri_node('hy2://password@example.com:443?obfs=salamander&obfs-password=secret')
        self.assertEqual(n['outbound']['obfs']['type'], 'salamander')

    def test_socks_http_and_tuic_uris(self):
        socks = core.uri_node('socks5://user:pass@example.com:1080#SOCKS')
        http = core.uri_node('http://user:pass@example.com:8080#HTTP')
        tuic = core.uri_node('tuic://' + UUID + ':secret@example.com:443?sni=example.org&alpn=h3&congestion_control=bbr&udp_relay_mode=quic#TUIC')
        self.assertEqual((socks['outbound']['type'], socks['outbound']['version'], socks['outbound']['username']), ('socks','5','user'))
        self.assertEqual((http['outbound']['type'], http['outbound']['password']), ('http','pass'))
        self.assertEqual((tuic['outbound']['type'], tuic['outbound']['congestion_control'], tuic['outbound']['tls']['server_name']), ('tuic','bbr','example.org'))

    def test_anytls_uri_is_normalized_with_certificate_validation(self):
        node = core.uri_node('anytls://secret%3Avalue@example.com:443?sni=edge.example#AnyTLS')
        self.assertEqual(node['outbound']['type'], 'anytls')
        self.assertEqual(node['outbound']['password'], 'secret:value')
        self.assertEqual(node['outbound']['tls']['server_name'], 'edge.example')
        with self.assertRaises(core.AtlasError): core.normalize({'type':'anytls','server':'example.com','server_port':443,'password':'x'})

    def test_clash_yaml_imports_multiple_protocols_and_transports(self):
        payload = '''proxies:
  - name: Reality WS
    type: vless
    server: edge.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    flow: xtls-rprx-vision
    tls: true
    servername: front.example
    client-fingerprint: chrome
    reality-opts:
      public-key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      short-id: abcd
    network: ws
    ws-opts:
      path: /gateway
      headers:
        Host: front.example
  - name: AnyTLS profile
    type: anytls
    server: tls.example
    port: 443
    password: any-secret
    tls: true
'''
        result = core.parse_subscription(payload.encode())
        self.assertEqual(result['format'], 'Clash/Mihomo YAML')
        self.assertEqual([x['name'] for x in result['nodes']], ['Reality WS', 'AnyTLS profile'])
        reality = result['nodes'][0]['outbound']
        self.assertEqual(reality['transport']['path'], '/gateway')
        self.assertEqual(reality['tls']['reality']['short_id'], 'abcd')
        self.assertEqual(result['nodes'][1]['outbound']['type'], 'anytls')

    def test_clash_yaml_json_and_base64_detection(self):
        body = b'proxies:\n  - name: Test\n    type: trojan\n    server: edge.example\n    port: 443\n    password: secret\n'
        self.assertEqual(core.parse_subscription(base64.b64encode(body))["format"], 'Clash/Mihomo YAML')
        self.assertEqual(core.parse_subscription(b'# generated by provider\n---\n' + body)['format'], 'Clash/Mihomo YAML')
        self.assertEqual(core.parse_subscription(b'{"proxies": [{"name":"Test","type":"trojan","server":"edge.example","port":443,"password":"secret"}]}')['nodes'][0]['name'], 'Test')

    def test_clash_yaml_rejects_aliases_duplicates_and_insecure_tls(self):
        with self.assertRaises(core.AtlasError):
            core.parse_subscription(b'proxies: &nodes []\ncopy: *nodes\n')
        with self.assertRaises(core.AtlasError):
            core.parse_subscription(b'proxies:\n  - name: first\n    name: second\n')
        body = b'proxies:\n  - name: insecure\n    type: trojan\n    server: edge.example\n    port: 443\n    password: secret\n    skip-cert-verify: true\n'
        with self.assertRaises(core.AtlasError): core.parse_subscription(body)

    def test_custom_subscription_headers_are_bounded_and_restricted(self):
        headers = core.subscription_headers('Authorization: Bearer token\nX-Provider-Key: abc')
        self.assertEqual(headers, {'Authorization':'Bearer token','X-Provider-Key':'abc'})
        for bad in ('Host: attacker.example', 'Proxy-Authorization: Basic token', 'X-Test: a\nx-test: b', 'X-Test: bad\rvalue'):
            with self.assertRaises(core.AtlasError): core.subscription_headers(bad)

    def test_unsupported_transport_not_silent(self):
        with self.assertRaises(core.AtlasError):
            core.parse_subscription((BASE + '?type=xhttp').encode())

    def test_mixed_unsupported_reported(self):
        result = core.parse_subscription((REALITY + '\n' + BASE + '?type=xhttp').encode())
        self.assertEqual(len(result['nodes']), 1)
        self.assertEqual(len(result['warnings']), 1)

    def test_insecure_tls_rejected(self):
        with self.assertRaises(core.AtlasError):
            core.uri_node(BASE + '?security=tls&allowInsecure=1')

    def test_remote_file_path_rejected(self):
        out = core.uri_node(REALITY)['outbound']
        out['tls']['certificate_path'] = '/etc/shadow'
        with self.assertRaises(core.AtlasError):
            core.normalize(out)

    def test_remote_route_and_inbound_not_imported(self):
        out = core.uri_node(REALITY)['outbound']
        parsed = core.parse_subscription(json.dumps({'outbounds':[out], 'inbounds':[{'listen':'0.0.0.0'}], 'route':{'final':'evil'}}).encode())
        self.assertEqual(len(parsed['nodes']), 1)
        self.assertNotIn('inbounds', parsed)

    def test_custom_sing_box_outbound_is_imported_with_routing_fields_rejected(self):
        custom={'type':'anytls','tag':'Custom AnyTLS','server':'example.com','server_port':443,'password':'secret',
                'tls':{'enabled':True,'server_name':'example.com'}}
        parsed=core.parse_subscription(json.dumps({'outbounds':[custom]}).encode())
        self.assertEqual(parsed['nodes'][0]['name'],'Custom AnyTLS')
        self.assertEqual(parsed['nodes'][0]['outbound']['type'],'anytls')
        for field in ('detour','bind_interface','routing_mark','network_namespace'):
            with self.assertRaises(core.AtlasError): core.normalize_custom(dict(custom,**{field:'direct'}))
        with self.assertRaises(core.AtlasError): core.normalize_custom(dict(custom,tls={'enabled':True,'insecure':True}))

    def test_detour_rejected(self):
        out = core.uri_node(REALITY)['outbound'];out['detour'] = 'direct'
        with self.assertRaises(core.AtlasError):core.normalize(out)

    def test_size_and_limit(self):
        for body in [b'', b'a' * (core.MAX_BYTES + 1), ('\n'.join([REALITY]*(core.MAX_NODES+1))).encode()]:
            with self.assertRaises(core.AtlasError):core.parse_subscription(body)

    def test_url_security(self):
        for url in ['file:///etc/shadow','http://example.com','https://user:pass@example.com','https://example.com/\nheader','https://example.com/#foo']:
            with self.assertRaises(core.AtlasError):core.subscription_url(url)

    def test_non_https_redirect(self):
        req = atlas.urllib.request.Request('https://example.com/sub')
        with self.assertRaises(core.AtlasError):atlas.HTTPSRedirect().redirect_request(req,None,302,'',{},'http://example.com/sub')

    def test_cross_origin_subscription_redirect_is_blocked(self):
        req = atlas.urllib.request.Request('https://provider.example/sub', headers={'Authorization':'Bearer private'})
        with self.assertRaises(core.AtlasError):
            atlas.HTTPSRedirect().redirect_request(req,None,302,'',{},'https://cdn.example/sub')

    def test_fetch_sends_auth_and_conditional_headers_and_reads_validators(self):
        class Response:
            headers={'ETag':'"new-etag"','Last-Modified':'Tue, 02 Jan 2024 00:00:00 GMT'}
            sent=False
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def geturl(self): return 'https://provider.example/sub'
            def read(self,size=-1):
                if self.sent: return b''
                self.sent=True;return b'vless://subscription'
        opener=mock.Mock();opener.open.return_value=Response()
        with mock.patch.object(atlas.urllib.request,'build_opener',return_value=opener):
            result=atlas.fetch('https://provider.example/sub',{'Authorization':'Bearer private'},'"old-etag"','Mon, 01 Jan 2024 00:00:00 GMT')
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_header('Authorization'),'Bearer private')
        self.assertEqual(request.get_header('If-none-match'),'"old-etag"')
        self.assertEqual(result[2:4],('"new-etag"','Tue, 02 Jan 2024 00:00:00 GMT'))

class ListFetchProxy(unittest.TestCase):
    def test_proxy_url_is_read_only_from_authenticated_loopback_inbound(self):
        active={'inbounds':[{'type':'mixed','tag':'list-fetch','listen':'127.0.0.1','listen_port':18443,
                             'users':[{'username':'atlas-fetch','password':'secret/@token'}]}]}
        with mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'read_json',return_value=active):
            proxy=atlas.fetch_rule_proxy_url()
        self.assertEqual(proxy,'http://atlas-fetch:secret%2F%40token@127.0.0.1:18443')

    def test_proxy_fetch_sets_http_and_https_proxy_without_direct_fallback(self):
        class Response:
            headers={}
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def geturl(self): return 'https://rules.example.org/ads.txt'
            def read(self,size=-1):
                if getattr(self,'sent',False): return b''
                self.sent=True;return b'ads.example\n'
        opener=mock.Mock();opener.open.return_value=Response()
        with mock.patch.object(atlas,'require_public_https'), mock.patch.object(atlas.urllib.request,'build_opener',return_value=opener) as build:
            domains,cidrs=atlas.fetch_rule_list('https://rules.example.org/ads.txt','domains',
                proxy_url='http://atlas-fetch:secret@127.0.0.1:18443')
        self.assertEqual(domains,['ads.example']);self.assertEqual(cidrs,[])
        proxies=build.call_args.args[0].proxies
        self.assertEqual(proxies,{'http':'http://atlas-fetch:secret@127.0.0.1:18443','https':'http://atlas-fetch:secret@127.0.0.1:18443'})
        self.assertEqual(opener.open.call_count,1)

    def test_proxy_setting_fails_closed_if_service_or_listener_is_unavailable(self):
        with mock.patch.object(atlas,'service_running',return_value=False):
            with self.assertRaises(core.AtlasError): atlas.fetch_rule_proxy_url()
        with mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'read_json',return_value={'inbounds':[]}):
            with self.assertRaises(core.AtlasError): atlas.fetch_rule_proxy_url()

class Routing(unittest.TestCase):
    def test_safe_defaults_and_private_bypass(self):
        c = core.make_config(state_with_node())
        self.assertEqual(c['route']['final'], 'direct')
        self.assertTrue(c['inbounds'][0]['auto_redirect'])
        self.assertEqual(c['route']['rules'][2]['outbound'], 'direct')
        self.assertEqual(c['route']['default_domain_resolver'], 'bootstrap')

    def test_rule_order(self):
        s=state_with_node();s['settings'].update(domains=['example.org'],bypass_domains=['local.example.org'],cidrs=['203.0.113.0/24'])
        rules=core.make_config(s)['route']['rules']
        self.assertEqual(next(r for r in rules if r.get('domain_suffix') == ['local.example.org'])['outbound'],'direct')
        self.assertEqual(next(r for r in rules if r.get('domain_suffix') == ['example.org'])['outbound'],'proxy')

    def test_device_routes_quic_ntp_and_exclusions(self):
        s=state_with_node();s['settings'].update(routed_source_ips=['192.168.1.25/32'],routing_excluded_ips=['192.168.1.26/32'],disable_quic=True,exclude_ntp=True,
            sections=[{'name':'Work','policy':'proxy','domains':['corp.example'],'cidrs':[],'source_ips':['192.168.1.27/32']},
                      {'name':'TV','policy':'direct','domains':[],'cidrs':[],'source_ips':['192.168.1.30/32']},
                      {'name':'Trackers','policy':'block','domains':['tracker.example'],'cidrs':[],'source_ips':[]}])
        rules=core.make_config(s)['route']['rules']
        self.assertIn({'source_ip_cidr':['192.168.1.26/32'],'action':'route','outbound':'direct'},rules)
        self.assertIn({'network':'udp','port':443,'action':'reject'},rules)
        self.assertIn({'network':'udp','port':123,'action':'route','outbound':'direct'},rules)
        self.assertIn({'source_ip_cidr':['192.168.1.25/32'],'action':'route','outbound':'proxy'},rules)
        self.assertIn({'domain_suffix':['corp.example'],'source_ip_cidr':['192.168.1.27/32'],'action':'route','outbound':'proxy'},rules)
        self.assertIn({'source_ip_cidr':['192.168.1.30/32'],'action':'route','outbound':'direct'},rules)
        self.assertIn({'domain_suffix':['tracker.example'],'action':'reject'},rules)
        self.assertLess(next(i for i,r in enumerate(rules) if r.get('action') == 'reject'), rules.index({'source_ip_cidr':['192.168.1.25/32'],'action':'route','outbound':'proxy'}))
        self.assertLess(rules.index({'ip_is_private':True,'action':'route','outbound':'direct'}), rules.index({'source_ip_cidr':['192.168.1.25/32'],'action':'route','outbound':'proxy'}))

    def test_section_uses_provider_specific_pool_and_vpn_interface(self):
        s=state_with_node()
        other=copy.deepcopy(s['subscriptions'][0]);other.update(id='c'*16,name='Backup',nodes=[core.uri_node('trojan://secret@example.net:443')])
        s['subscriptions'].append(other)
        s['settings']['sections']=[
            {'name':'Backup-sites','policy':'proxy','domains':['backup.example'],'cidrs':[],'source_ips':[],'pool':'c'*16},
            {'name':'VPN-work','policy':'interface','domains':['intranet.example'],'cidrs':[],'source_ips':[],'interface':'wg0','pool':''}]
        config=core.make_config(s)
        pool=next(x for x in config['outbounds'] if x.get('tag')=='pool_'+'c'*16)
        self.assertTrue(all(tag.startswith('c'*16) for tag in [t for t in pool['outbounds'] if t not in ('auto_' + 'c'*16, 'policy-block')]))
        bound=next(x for x in config['outbounds'] if x.get('tag','').startswith('if_'))
        self.assertEqual(bound['bind_interface'],'wg0')
        rules=config['route']['rules']
        self.assertIn({'domain_suffix':['backup.example'],'action':'route','outbound':'pool_'+'c'*16},rules)
        self.assertIn({'domain_suffix':['intranet.example'],'action':'route','outbound':bound['tag']},rules)

    def test_vpn_section_split_dns_uses_bound_interface_and_fakeip_ttl(self):
        s=state_with_node();s['settings'].update(fakeip=True,fakeip_ttl_seconds=45,domains=['video.example'])
        s['settings']['sections']=[{'name':'Corp DNS','policy':'interface','domains':['intranet.example'],'cidrs':[],
            'source_ips':[],'interface':'wg0','resolver':'https://dns.example/dns-query'}]
        config=core.make_config(s)
        outbound=next(x for x in config['outbounds'] if x.get('tag','').startswith('if_'))
        resolver=next(x for x in config['dns']['servers'] if x.get('tag','').startswith('vpn_dns_'))
        self.assertEqual(resolver['type'],'https');self.assertEqual(resolver['server'],'dns.example')
        self.assertEqual(resolver['detour'],outbound['tag']);self.assertEqual(resolver['path'],'/dns-query')
        self.assertIn({'domain_suffix':['intranet.example'],'action':'route','server':resolver['tag']},config['dns']['rules'])
        fakeip=next(x for x in config['dns']['rules'] if x.get('server')=='fakeip')
        self.assertEqual(fakeip['rewrite_ttl'],45)

    def test_proxy_and_direct_sections_can_use_domain_specific_dns(self):
        s=state_with_node();s['settings']['sections']=[
            {'name':'Work','policy':'proxy','domains':['work.example'],'cidrs':[],'source_ips':[],
             'pool':'','interface':'','resolver':'https://dns.example/dns-query'},
            {'name':'Local','policy':'direct','domains':['local.example'],'cidrs':[],'source_ips':[],
             'pool':'','interface':'','resolver':'tls://10.0.0.53'}]
        config=core.make_config(s)
        servers={x['tag']:x for x in config['dns']['servers']}
        rules={tuple(x.get('domain_suffix', [])):x for x in config['dns']['rules'] if 'domain_suffix' in x and 'server' in x}
        self.assertEqual(servers[rules[('work.example',)]['server']]['detour'],'proxy')
        self.assertNotIn('detour',servers[rules[('local.example',)]['server']])

    def test_exclusion_policy_is_direct_and_resolver_uri_is_restricted(self):
        s=state_with_node();s['settings']['sections']=[
            {'name':'Work proxy','policy':'proxy','domains':['local.example'],'cidrs':[],'source_ips':[],'interface':'','pool':'','resolver':''},
            {'name':'Never proxy','policy':'exclude','domains':['local.example'],'cidrs':[],'source_ips':[],'interface':'','pool':'','resolver':''}]
        config=core.make_config(s)
        direct={'domain_suffix':['local.example'],'action':'route','outbound':'direct'}
        proxy={'domain_suffix':['local.example'],'action':'route','outbound':'proxy'}
        self.assertLess(config['route']['rules'].index(direct),config['route']['rules'].index(proxy))
        s['settings']['sections']=[{'name':'VPN DNS','policy':'interface','domains':['local.example'],
            'cidrs':[],'source_ips':[],'interface':'wg0','pool':'','resolver':'tls://10.0.0.53:853'}]
        self.assertEqual(core.validate_settings(s['settings'])['sections'][0]['resolver'],'tls://10.0.0.53')
        for resolver in ('https://dns.example/dns-query?token=x','http://dns.example/dns-query','udp://dns.example/path'):
            s['settings']['sections'][0]['resolver']=resolver
            with self.assertRaises(core.AtlasError): core.validate_settings(s['settings'])
        for ttl in (0,86401,True):
            s['settings']['fakeip_ttl_seconds']=ttl
            with self.assertRaises(core.AtlasError): core.validate_settings(s['settings'])

    def test_custom_doh_listener_and_known_doh_block(self):
        s=state_with_node();s['settings'].update(dns_filter='custom',custom_dns_type='https',custom_dns_server='1.1.1.1',
            custom_dns_sni='cloudflare-dns.com',mixed_proxy_enabled=True,mixed_proxy_listen='192.168.1.1',
            mixed_proxy_port=2080,mixed_proxy_username='atlas',mixed_proxy_password='example-secret-password',block_known_doh=True)
        config=core.make_config(s)
        secure=next(x for x in config['dns']['servers'] if x['tag']=='secure')
        self.assertEqual(secure['server'],'1.1.1.1');self.assertEqual(secure['detour'],'proxy')
        self.assertEqual(config['inbounds'][1]['listen'],'192.168.1.1')
        self.assertEqual(config['inbounds'][1]['users'][0]['password'],'example-secret-password')
        self.assertIn({'domain_suffix':core.KNOWN_DOH_DOMAINS,'action':'reject'},config['route']['rules'])

    def test_remote_lists_route_and_dns_block(self):
        s=state_with_node();s['settings']['remote_lists']=[
            {'name':'Tracker DNS','url':'https://lists.example.org/dns.txt','policy':'dnsblock','format':'domains','enabled':True,'domains':['tracker.example'],'cidrs':[]},
            {'name':'Proxy domains','url':'https://lists.example.org/proxy.txt','policy':'proxy','format':'domains','enabled':True,'domains':['corp.example'],'cidrs':[]}]
        config=core.make_config(s)
        self.assertIn({'domain_suffix':['tracker.example'],'action':'reject'},config['dns']['rules'])
        self.assertIn({'domain_suffix':['corp.example'],'action':'route','outbound':'proxy'},config['route']['rules'])

    def test_remote_list_routes_through_existing_vpn_interface(self):
        s=state_with_node();s['settings']['remote_lists']=[
            {'name':'Private destinations','url':'https://lists.example.org/private.srs','policy':'interface','format':'domains','enabled':True,
             'interface':'wg0','domains':['intranet.example'],'cidrs':['10.20.0.0/16']}]
        config=core.make_config(s)
        bound=next(x for x in config['outbounds'] if x.get('bind_interface')=='wg0')
        self.assertIn({'domain_suffix':['intranet.example'],'action':'route','outbound':bound['tag']},config['route']['rules'])
        self.assertIn({'ip_cidr':['10.20.0.0/16'],'action':'route','outbound':bound['tag']},config['route']['rules'])

    def test_remote_interface_policy_requires_a_valid_existing_interface_name(self):
        base={'name':'Private','url':'https://lists.example.org/private.srs','policy':'interface','format':'srs','enabled':True}
        with self.assertRaises(core.AtlasError): core.validate_settings({'remote_lists':[base]})
        base['interface']='wg0'
        self.assertEqual(core.validate_settings({'remote_lists':[base]})['remote_lists'][0]['interface'],'wg0')

    def test_disabled_subscription(self):
        s=state_with_node();s['subscriptions'][0]['enabled']=False
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_removed_selection_never_falls_back_silently(self):
        s=state_with_node();s['settings']['selected']='f'*32
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_probe_loopback_only(self):
        c=core.make_config(core.defaults(),False,9988,core.uri_node(REALITY))
        self.assertEqual(c['inbounds'][0]['listen'],'127.0.0.1')
        self.assertTrue(c['route']['auto_detect_interface'])

    def test_output_interface_overrides_auto_detection(self):
        settings=core.validate_settings({'default_interface':'eth0.2','log_level':'info'})
        c=core.make_config({'settings':settings,'subscriptions':[]},False,9988,core.uri_node(REALITY))
        self.assertFalse(c['route']['auto_detect_interface'])
        self.assertEqual(c['route']['default_interface'],'eth0.2')
        self.assertEqual(c['log']['level'],'info')
        for bad in [{'default_interface':'lo'},{'default_interface':'br-lan;drop'},{'log_level':'trace'}]:
            with self.assertRaises(core.AtlasError):core.validate_settings(bad)

    def test_remote_list_fetch_can_use_a_subscription_specific_auto_pool(self):
        s=state_with_node();s['settings'].update(fetch_lists_via_proxy=True,fetch_lists_subscription='b'*16)
        c=core.make_config(s)
        self.assertTrue(any(x.get('tag')=='pool_'+'b'*16 for x in c['outbounds']))
        self.assertIn({'inbound':['list-fetch'],'action':'route','outbound':'pool_'+'b'*16},c['route']['rules'])
        s['settings']['fetch_lists_subscription']='c'*16
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_settings_and_normalization(self):
        s=core.validate_settings({'domains':['*.Example.COM'],'cidrs':['192.0.2.7/24']})
        self.assertEqual(s['domains'],['example.com']);self.assertEqual(s['cidrs'],['192.0.2.0/24'])
        for bad in [{'interval_hours':0},{'domains':['foo;bar']},{'cidrs':['not-an-ip']},{'mode':'evil'},{'selected':'$(id)'}]:
            with self.assertRaises(core.AtlasError):core.validate_settings(bad)

class Persistence(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
        self.patches=[mock.patch.object(atlas,'DATA',self.path),mock.patch.object(atlas,'RUN',self.path),mock.patch.object(atlas,'STATE',self.path/'state.json'),mock.patch.object(atlas,'CONFIG',self.path/'config.json')]
        for p in self.patches:p.start()
        atlas.atomic(atlas.STATE,state_with_node())
    def tearDown(self):
        for p in self.patches:p.stop()
        self.tmp.cleanup()

    def test_atomic_permissions(self):
        self.assertEqual(atlas.STATE.stat().st_mode & 0o777,0o600)

    def test_local_rule_file_import_merges_verified_domains_and_cidrs(self):
        content=base64.b64encode(b'ads.example\n203.0.113.8/24\n').decode()
        result=atlas.dispatch('import_rules',{'content':content,'target':'block'})
        self.assertEqual(result,{'ok':True,'domains':1,'cidrs':1})
        section=atlas.state()['settings']['sections'][0]
        self.assertEqual(section['policy'],'block')
        self.assertEqual(section['domains'],['ads.example'])
        self.assertEqual(section['cidrs'],['203.0.113.0/24'])

    def test_local_rule_file_import_rejects_invalid_payload_without_state_change(self):
        old=atlas.STATE.read_bytes()
        with self.assertRaises(core.AtlasError): atlas.dispatch('import_rules',{'content':'aW52YWxpZC0tLQo=','target':'proxy'})
        self.assertEqual(atlas.STATE.read_bytes(),old)

    def test_runtime_config_uses_exact_ingress_not_interface_subnets(self):
        s=atlas.state();s['settings']['sections']=[{'name':'IoT','policy':'proxy','domains':[],
            'cidrs':[],'source_ips':[],'source_interfaces':['br-iot']}]
        with mock.patch.object(atlas,'source_interface_networks',return_value=['192.168.8.0/24','fd00:8::/64']):
            config=atlas.runtime_config(s)
        ingress=next(x for x in config['inbounds'] if x.get('include_interface')==['br-iot'])
        self.assertIn({'type':'logical','mode':'and','rules':[{}, {'inbound':[ingress['tag']]}],'action':'route','outbound':'proxy'},config['route']['rules'])

    def test_kill_switch_settings_are_rolled_back_when_firewall_setup_fails(self):
        before=atlas.STATE.read_bytes()
        settings=atlas.state()['settings'];settings['kill_switch']=True
        with mock.patch.object(atlas,'manage_kill_switch',side_effect=core.AtlasError('firewall unavailable')):
            with self.assertRaises(core.AtlasError): atlas.dispatch('save_settings',{'settings':settings})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_kill_switch_creates_named_fw4_rule_and_removes_it(self):
        calls=[]
        def fake_run(args, timeout=15):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,b'',b'')
        with mock.patch.object(atlas,'run',side_effect=fake_run):
            atlas.manage_kill_switch(True)
            atlas.manage_kill_switch(False)
        self.assertIn(['/sbin/uci','set','firewall.atlas_kill_switch=rule'],calls)
        self.assertIn(['/sbin/uci','set','firewall.atlas_kill_switch.target=DROP'],calls)
        self.assertIn(['/sbin/uci','-q','delete','firewall.atlas_kill_switch'],calls)
        self.assertEqual(calls.count(['/etc/init.d/firewall','reload']),2)

    def test_status_redacts_secrets(self):
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'engine_version',return_value='test'):
            status=json.dumps(atlas.public_status())
        for secret in [UUID,'/sub/private','public_key','password']:
            self.assertNotIn(secret,status)

    def test_status_masks_remote_list_paths(self):
        s=atlas.state();s['settings']['remote_lists']=[{'name':'a','url':'https://lists.example.org/secret-feed','policy':'dnsblock','format':'domains','enabled':True}]
        atlas.atomic(atlas.STATE,s)
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'engine_version',return_value='test'):
            status=json.dumps(atlas.public_status())
        self.assertNotIn('secret-feed',status)
        self.assertIn('https://lists.example.org/[saved]',status)
        self.assertNotIn('old.example',status)

    def test_settings_save_preserves_hidden_url_and_cached_rules(self):
        s=atlas.state();s['settings']['remote_lists']=[{'name':'ads','url':'https://lists.example.org/secret-feed','policy':'dnsblock','format':'domains','enabled':True,'domains':['cached.example'],'cidrs':[]}]
        atlas.atomic(atlas.STATE,s)
        submitted=atlas.public_status()['settings']
        atlas.dispatch('save_settings',{'settings':submitted})
        saved=atlas.state()['settings']['remote_lists'][0]
        self.assertEqual(saved['url'],'https://lists.example.org/secret-feed')
        self.assertEqual(saved['domains'],['cached.example'])

    def test_refresh_remote_list_caches_last_good_data(self):
        s=atlas.state();s['subscriptions']=[];s['settings']['remote_lists']=[{'name':'ads','url':'https://lists.example.org/list.txt','policy':'dnsblock','format':'domains','enabled':True,'domains':['old.example'],'cidrs':[]}]
        with mock.patch.object(atlas,'fetch_rule_list',return_value=(['new.example'],[])),mock.patch.object(atlas,'service_running',return_value=False):
            message=atlas.refresh(s)
        self.assertIn('списков правил: 1',message)
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['domains'],['new.example'])

    def test_refresh_remote_list_failure_keeps_last_good_data(self):
        s=atlas.state();s['subscriptions']=[];s['settings']['remote_lists']=[{'name':'ads','url':'https://lists.example.org/list.txt','policy':'dnsblock','format':'domains','enabled':True,'domains':['old.example'],'cidrs':[]}]
        with mock.patch.object(atlas,'fetch_rule_list',side_effect=core.AtlasError('offline')):
            with self.assertRaises(core.AtlasError): atlas.refresh(s)
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['domains'],['old.example'])

    def test_refresh_failure_preserves_nodes(self):
        old=atlas.state()
        with mock.patch.object(atlas,'fetch',side_effect=core.AtlasError('HTTP 500')):
            with self.assertRaises(core.AtlasError):atlas.refresh(atlas.state())
        self.assertEqual(atlas.state()['subscriptions'][0]['nodes'],old['subscriptions'][0]['nodes'])
        self.assertEqual(atlas.state()['subscriptions'][0]['error'],'HTTP 500')

    def test_conditional_refresh_keeps_last_good_nodes_and_records_unchanged(self):
        old=atlas.state(); nodes=copy.deepcopy(old['subscriptions'][0]['nodes'])
        old['subscriptions'][0].update(etag='"etag1"',last_modified='Mon, 01 Jan 2024 00:00:00 GMT')
        with mock.patch.object(atlas,'fetch',return_value=(None,{},'"etag1"','Mon, 01 Jan 2024 00:00:00 GMT',True)), mock.patch.object(atlas,'service_running',return_value=False):
            atlas.refresh(old)
        saved=atlas.state()['subscriptions'][0]
        self.assertEqual(saved['nodes'],nodes)
        self.assertEqual(saved['etag'],'"etag1"')
        self.assertTrue(saved['change']['unchanged'])

    def test_save_subscription_keeps_headers_private_and_clears_them_on_new_origin(self):
        atlas.dispatch('save_subscription',{'id':'b'*16,'name':'Test','url':'','enabled':True,
            'headers':'Authorization: Bearer TOPSECRET_auth_header'})
        saved=atlas.state()['subscriptions'][0]
        self.assertEqual(saved['headers']['Authorization'],'Bearer TOPSECRET_auth_header')
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'engine_version',return_value='test'):
            status=json.dumps(atlas.public_status())
        self.assertNotIn('TOPSECRET_auth_header',status)
        self.assertIn('"headers_set": true',status)
        atlas.dispatch('save_subscription',{'id':'b'*16,'name':'Test','url':'https://other.example/sub','enabled':True})
        self.assertEqual(atlas.state()['subscriptions'][0]['headers'],{})

    def test_batch_import_adds_valid_urls_deduplicates_and_reports_errors(self):
        result=atlas.dispatch('import_subscriptions',{'items':[
            {'name':'Duplicate','url':'https://example.com/sub/private'},
            {'name':'New pool','url':'https://new.example/sub'},
            {'name':'Bad','url':'http://insecure.example/sub'}]})
        self.assertEqual((result['added'],result['duplicates'],result['errors']),(1,1,1))
        self.assertEqual(len(atlas.state()['subscriptions']),2)
        self.assertEqual(atlas.state()['subscriptions'][1]['name'],'New pool')

    def test_invalid_subscription_never_replaces_good(self):
        old=atlas.state()
        with mock.patch.object(atlas,'fetch',return_value=(b'<html>Error</html>',{})):
            with self.assertRaises(core.AtlasError):atlas.refresh(atlas.state())
        self.assertEqual(atlas.state()['subscriptions'][0]['nodes'],old['subscriptions'][0]['nodes'])

    def test_engine_check_precedes_restart(self):
        with mock.patch.object(atlas,'service_running',return_value=False), mock.patch.object(atlas,'check',side_effect=core.AtlasError('bad')),mock.patch.object(atlas,'run') as run:
            with self.assertRaises(core.AtlasError):atlas.apply(atlas.state())
        run.assert_not_called();self.assertFalse(atlas.CONFIG.exists())

    def test_failed_start_rolls_back(self):
        old={'sentinel':'previous'};atlas.atomic(atlas.CONFIG,old)
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'check'),mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)),mock.patch.object(atlas.time,'sleep'):
            with self.assertRaises(core.AtlasError):atlas.apply(atlas.state())
        self.assertEqual(json.loads(atlas.CONFIG.read_text()),old)
        self.assertFalse((atlas.DATA/'active.json').exists())

    def test_start_command_timeout_is_bounded_and_restores_previous_config(self):
        old={'sentinel':'previous'};atlas.atomic(atlas.CONFIG,old)
        calls=[]
        def run(command,timeout=15):
            calls.append((command,timeout))
            if command==['/etc/init.d/atlas','restart']:raise subprocess.TimeoutExpired(command,timeout)
            return mock.Mock(returncode=0)
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'check'),mock.patch.object(atlas,'run',side_effect=run):
            with self.assertRaisesRegex(core.AtlasError,'восстановлена предыдущая'):atlas.apply(atlas.state())
        self.assertEqual(calls[0],(['/etc/init.d/atlas','restart'],90))
        self.assertEqual(json.loads(atlas.CONFIG.read_text()),old)

    def test_success_persists_last_good(self):
        def running(name='atlas'):return name=='atlas'
        with mock.patch.object(atlas,'service_running',side_effect=running),mock.patch.object(atlas,'check'),mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)),mock.patch.object(atlas.time,'sleep'),mock.patch.object(atlas,'clash_request',return_value={'proxies':{}}):
            atlas.apply(atlas.state())
        self.assertEqual(json.loads((atlas.DATA/'active.json').read_text()),json.loads(atlas.CONFIG.read_text()))

    def test_stop_waits_for_procd_exit(self):
        atlas.atomic(atlas.RUN / 'job.json', {'id': 'stop-test', 'operation': 'stop'})
        with mock.patch.object(atlas, 'run'), mock.patch.object(atlas, 'service_running', side_effect=[True, True, False]), mock.patch.object(atlas.time, 'sleep') as sleep:
            atlas.worker('stop-test')
        self.assertEqual(atlas.read_json(atlas.RUN / 'job.json', {})['status'], 'done')
        self.assertEqual(sleep.call_count, 2)

    def test_stop_reports_engine_that_wont_exit(self):
        atlas.atomic(atlas.RUN / 'job.json', {'id': 'stop-test', 'operation': 'stop'})
        with mock.patch.object(atlas, 'run'), mock.patch.object(atlas, 'service_running', return_value=True), mock.patch.object(atlas.time, 'sleep'):
            atlas.worker('stop-test')
        self.assertEqual(atlas.read_json(atlas.RUN / 'job.json', {})['status'], 'error')

    def test_blank_edit_preserves_url(self):
        atlas.dispatch('save_subscription',{'id':'b'*16,'name':'Renamed','url':'','enabled':True})
        self.assertEqual(atlas.state()['subscriptions'][0]['url'],'https://example.com/sub/private')

    def test_arbitrary_action_rejected(self):
        with self.assertRaises(core.AtlasError):atlas.dispatch('action',{'operation':'reboot; id'})

    def test_write_lock_busy(self):
        with atlas.locked():
            with self.assertRaises(core.AtlasError):
                atlas.dispatch('save_settings',{'settings':{}})

class EngineIntegration(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE to sing-box binary')
    def test_supported_protocols_and_both_modes(self):
        links=[REALITY,BASE+'?security=tls&type=ws&path=%2Fws','trojan://secret@example.com:443',
               'ss://'+encoded('aes-128-gcm:password')+'@example.com:8388',
               'hy2://secret@example.com:443',
               'anytls://secret@example.com:443?sni=example.com',
               'socks5://user:secret@example.com:1080','http://user:secret@example.com:8080',
               'tuic://'+UUID+':secret@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr',
               'vmess://'+encoded(json.dumps({'add':'example.com','port':443,'id':UUID,'net':'tcp','tls':'tls'}))]
        s=state_with_node();s['subscriptions'][0]['nodes']=[core.uri_node(x) for x in links]
        clash=core.parse_subscription(b'''proxies:\n  - name: Clash AnyTLS\n    type: anytls\n    server: example.com\n    port: 443\n    password: secret\n    sni: example.com\n''')
        s['subscriptions'][0]['nodes'].extend(clash['nodes'])
        s['settings'].update(domains=['example.org'],cidrs=['203.0.113.0/24'])
        for tun in (False,True):
            with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
                json.dump(core.make_config(s,tun=tun),f);f.flush()
                r=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',f.name],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE to sing-box binary')
    def test_optional_fakeip_and_adguard_dns_configs(self):
        for settings in (
            {'domains':['video.example'],'blocked_domains':['ads.example'],'fakeip':True,'dns_filter':'adguard'},
            {'mode':'global','fakeip':True,'dns_filter':'cloudflare'},
            {'disable_quic':True,'exclude_ntp':True,'routed_source_ips':['192.168.1.25/32'],'routing_excluded_ips':['192.168.1.26/32'],
             'sections':[{'name':'Work','policy':'proxy','domains':['corp.example'],'cidrs':[],'source_ips':['192.168.1.27/32']},
                         {'name':'TV','policy':'direct','domains':[],'cidrs':[],'source_ips':['192.168.1.30/32']},
                         {'name':'Trackers','policy':'block','domains':['tracker.example'],'cidrs':[],'source_ips':[]},
                         {'name':'VPN work','policy':'interface','domains':['corp.example'],'cidrs':[],'source_ips':[],'pool':'','interface':'wg0'}]},
            {'dns_filter':'custom','custom_dns_type':'tls','custom_dns_server':'1.1.1.1','custom_dns_sni':'cloudflare-dns.com',
             'bootstrap_dns_type':'tls','bootstrap_dns_server':'9.9.9.9','bootstrap_dns_sni':'dns.quad9.net',
             'udp_over_tcp':True,'udp_over_tcp_version':2},
            {'mixed_proxy_enabled':True,'mixed_proxy_listen':'192.168.1.1','mixed_proxy_port':2080,'mixed_proxy_username':'atlas','mixed_proxy_password':'strong-test-password'},
            {'remote_lists':[{'name':'Ad domains','url':'https://lists.example.org/ad.txt','policy':'dnsblock','format':'domains','enabled':True,'domains':['ads.example'],'cidrs':[]},
                             {'name':'Proxy ranges','url':'https://lists.example.org/proxy.txt','policy':'proxy','format':'cidrs','enabled':True,'domains':[],'cidrs':['203.0.113.0/24']}]},
        ):
            s=state_with_node();s['settings'].update(settings)
            with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
                json.dump(core.make_config(s),f);f.flush()
                r=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',f.name],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE to sing-box binary')
    def test_custom_anytls_and_real_ip_resolution_pass_engine_check(self):
        s=state_with_node()
        s['subscriptions'][0]['nodes'].append(core.normalize_custom({'type':'anytls','tag':'AnyTLS','server':'example.com',
            'server_port':443,'password':'secret','tls':{'enabled':True,'server_name':'example.com'}}))
        s['settings'].update(resolve_real_ip=True,default_interface='eth0.2',log_level='info')
        with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
            json.dump(core.make_config(s,tun=False),f);f.flush()
            r=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',f.name],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE')
    def test_vpn_split_dns_variants_and_fakeip_ttl_are_accepted_by_engine(self):
        for resolver in ('udp://10.0.0.53','tls://dns.example','https://dns.example/dns-query'):
            current=state_with_node();current['settings'].update(fakeip=True,fakeip_ttl_seconds=45,domains=['video.example'],
                sections=[{'name':'Work DNS','policy':'interface','domains':['corp.example'],'cidrs':[],
                           'source_ips':[],'interface':'wg0','resolver':resolver}])
            config=core.make_config(current)
            with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
                json.dump(config,f);f.flush()
                checked=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',f.name],capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stderr)

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE')
    def test_loopback_subscription_list_fetch_proxy_is_accepted_by_engine(self):
        current=state_with_node();current['settings'].update(fetch_lists_via_proxy=True,remote_lists=[
            {'id':'2'*16,'name':'Community','url':'https://rules.example.org/telegram.txt','policy':'proxy','format':'domains','enabled':True,'domains':['t.me']}])
        config=core.make_config(current)
        inbound=next(x for x in config['inbounds'] if x['tag']=='list-fetch')
        self.assertEqual(inbound['listen'],'127.0.0.1');self.assertTrue(inbound['users'][0]['password'])
        self.assertIn({'inbound':['list-fetch'],'action':'route','outbound':'proxy'},config['route']['rules'])
        with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
            json.dump(config,f);f.flush()
            checked=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',f.name],capture_output=True,text=True)
        self.assertEqual(checked.returncode,0,checked.stderr)

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE to sing-box binary')
    def test_srs_rule_set_uses_engine_compiler_and_route_matcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'rules.json';target=Path(tmp)/'rules.srs'
            source.write_text(json.dumps({'version':1,'rules':[{'domain_suffix':['ads.example'] }]}))
            compiled=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'rule-set','compile',str(source),'-o',str(target)],capture_output=True,text=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            s=state_with_node();s['settings']['remote_lists']=[{'id':'1'*16,'name':'Binary rules','url':'https://rules.example.org/test.srs',
                'policy':'interface','format':'srs','enabled':True,'interface':'wg0','srs_cached':True}]
            config=core.make_config(s)
            self.assertEqual(config['route']['rule_set'][0]['format'],'binary')
            interface_tag=next(x['tag'] for x in config['outbounds'] if x.get('bind_interface')=='wg0')
            self.assertIn({'rule_set':['rules_'+'1'*16],'action':'route','outbound':interface_tag},config['route']['rules'])
            config['route']['rule_set'][0]['path']=str(target)
            conf=Path(tmp)/'config.json';conf.write_text(json.dumps(config))
            checked=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(conf)],capture_output=True,text=True)
            self.assertEqual(checked.returncode,0,checked.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
