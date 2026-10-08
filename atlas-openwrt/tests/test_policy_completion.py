import copy
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
import atlas
from test_selection import sample

class CompletedPolicies(unittest.TestCase):
    def test_apply_waits_for_engine_api_when_launcher_is_running(self):
        state=sample()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with mock.patch.object(atlas,'DATA',root),mock.patch.object(atlas,'RUN',root),mock.patch.object(atlas,'CONFIG',root/'config.json'),mock.patch.object(atlas,'runtime_config',return_value={}),mock.patch.object(atlas,'check'),mock.patch.object(atlas,'service_running',side_effect=lambda name='atlas':name=='atlas'),mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)),mock.patch.object(atlas.time,'sleep'),mock.patch.object(atlas,'clash_request',side_effect=[ConnectionRefusedError(),ConnectionRefusedError(),{'proxies':{}}]) as api:
                atlas.apply(state)
                self.assertEqual(api.call_count,3)
                self.assertTrue((root/'applied.json').exists())

    def test_browser_diagnostic_routes_are_explicit_and_opt_in(self):
        state=sample()
        self.assertFalse(state['settings']['browser_diagnostics'])
        state['settings'].update(fakeip=True,browser_diagnostics=True,mode='global')
        cfg=core.make_config(state)
        rules=cfg['route']['rules']
        direct=next(x for x in rules if x.get('domain')==['fakeip.podkop.fyi'] and x.get('outbound')=='direct')
        self.assertEqual(direct['action'],'route')
        self.assertTrue(any(x.get('override_port')==8443 for x in rules))
        self.assertTrue(any(x.get('domain')==['ip.podkop.fyi'] and x.get('outbound')=='proxy' for x in rules))
        self.assertEqual(cfg['dns']['rules'][1]['server'],'fakeip')
        state['settings']['fakeip']=False
        with self.assertRaises(core.AtlasError):core.validate_settings(state['settings'])

    def test_each_pool_uses_its_own_evidence_and_fail_closed(self):
        state = sample()
        state['settings'].update(auto_strategy='slowest', max_ping_ms=200)
        nodes = core.all_nodes(state)
        sid = state['subscriptions'][0]['id']
        stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        proxies = {'proxy': {'now': nodes[0]['key']}, 'pool_' + sid: {'now': 'auto_' + sid}}
        for node, delay in zip(nodes, [80,180,220]):
            proxies[node['key']] = {'history': [{'delay':delay, 'time':stamp}]}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(atlas,'RUN',Path(directory)), mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}) as api:
            result = atlas.automatic_select(state)
            self.assertEqual([x['selected'] for x in result['groups']], [nodes[1]['key']]*2)
            self.assertEqual([x.args[1] for x in api.call_args_list if x.args], ['/proxies/proxy','/proxies/pool_'+sid])
            state['settings']['max_ping_ms']=50
            result=atlas.automatic_select(state)
            self.assertTrue(all(x['blocked'] for x in result['groups']))
            self.assertEqual(result['selected'],'policy-block')
            state['settings']['max_ping_ms']=200
            self.assertFalse(any(x['blocked'] for x in atlas.automatic_select(state)['groups']))

    def test_manual_main_does_not_disable_automatic_pool(self):
        state=sample();nodes=core.all_nodes(state);sid=state['subscriptions'][0]['id']
        state['settings'].update(selected=nodes[0]['key'],auto_strategy='slowest')
        proxies={'pool_'+sid:{'now':'auto_'+sid},nodes[1]['key']:{'history':[{'delay':100,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}]}}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(atlas,'RUN',Path(directory)), mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}):
            groups=atlas.automatic_select(state)['groups']
            self.assertEqual([x['group'] for x in groups],['pool_'+sid])

    def test_custom_policy_boot_cannot_restore_cached_choice(self):
        state=sample();state['settings'].update(max_ping_ms=50)
        cfg=core.make_config(state)
        self.assertEqual(cfg['outbounds'][0]['default'],'policy-block')
        self.assertTrue(cfg['outbounds'][0]['interrupt_exist_connections'])
        self.assertTrue(cfg['experimental']['cache_file']['enabled'])
        self.assertTrue(cfg['experimental']['cache_file']['store_fakeip'])
        first=atlas.prepare_engine_start(cfg);second=atlas.prepare_engine_start(first)
        self.assertEqual(first['experimental']['cache_file']['cache_id'],second['experimental']['cache_file']['cache_id'])
        self.assertEqual(first['experimental']['cache_file']['cache_id'],'atlas-policy-v2')
        self.assertNotEqual(first['outbounds'][0]['outbounds'],second['outbounds'][0]['outbounds'])
        self.assertEqual(cfg['experimental']['cache_file']['cache_id'],'atlas-policy')
        self.assertTrue(atlas.decode_runtime({'proxy':{'now':'policy-block'}},[])['blocked'])

    def test_fakeip_sections_lists_exclusions_and_real_resolve(self):
        state=sample();state['settings'].update(fakeip=True,resolve_real_ip=True,
            sections=[{'name':'Proxy','policy':'proxy','domains':['work.example'],'cidrs':[],'source_ips':[]},
                      {'name':'Bypass','policy':'exclude','domains':['local.work.example'],'cidrs':[],'source_ips':[]}],
            remote_lists=[{'name':'Proxy list','url':'https://example.org/list','policy':'proxy','format':'domains','enabled':True,'domains':['remote.example'],'cidrs':[]}])
        cfg=core.make_config(state)
        dns=cfg['dns']['rules']
        self.assertEqual(dns[0]['server'],'secure')
        self.assertTrue(any(x.get('server')=='fakeip' and 'work.example' in x.get('domain_suffix',[]) for x in dns))
        self.assertTrue(any(x.get('server')=='fakeip' and 'remote.example' in x.get('domain_suffix',[]) for x in dns))
        rules=cfg['route']['rules']
        route=next(i for i,x in enumerate(rules) if x.get('outbound')=='proxy')
        self.assertEqual(rules[route-1]['action'],'resolve')
        self.assertEqual(rules[route-1]['server'],'secure')
        broken=copy.deepcopy(cfg)
        broken['route']['rules']=[x for x in rules if x.get('action')!='resolve']
        self.assertFalse(core.real_ip_resolution_active(broken))
        self.assertFalse(next(x for x in core.privacy_checks(state['settings'],broken)['checks'] if x['id']=='real_ip_resolution')['ok'])

    def test_direct_ip_baseline_binds_wan_and_never_falls_back(self):
        reply=mock.Mock(returncode=0,stdout='{"up":true,"l3_device":"eth1"}')
        with mock.patch.object(atlas,'run',return_value=reply),mock.patch.object(atlas,'proxied_https_get',return_value=b'203.0.113.5') as fetch:
            self.assertEqual(atlas.direct_public_ip(),'203.0.113.5')
            self.assertEqual(fetch.call_args.args[0]['outbound']['bind_interface'],'eth1')
            reply.stdout='{"up":true,"l3_device":"atlas0"}'
            with self.assertRaises(core.AtlasError):atlas.direct_public_ip()
            self.assertEqual(fetch.call_count,1)

    def test_failed_latest_sample_and_missing_timestamp_do_not_restore_old_node(self):
        state=sample();settings=core.validate_settings(dict(state['settings'],auto_strategy='stable'))
        nodes=core.all_nodes(state);stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        for history in ([{'delay':10,'time':stamp},{'delay':0,'time':stamp}], [{'delay':10}]):
            self.assertIsNone(atlas.auto_choice(nodes,settings,{nodes[0]['key']:{'history':history}}))
