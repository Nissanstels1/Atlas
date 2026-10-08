import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,engine_features,outbounds
from test_selection import sample

FEATURES=['urltest.fallbacks','urltest.download_url','tools.decode-link']

class EngineFeatures(unittest.TestCase):
    def test_sidecar_is_selected_without_replacing_stock_binary(self):
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(engine_features.os,'access',return_value=True):self.assertEqual(engine_features.binary_path(),'/usr/lib/atlas-engine/bin/atlas-engine')
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(engine_features.os,'access',return_value=False):self.assertEqual(engine_features.binary_path(),'/usr/bin/sing-box')

    def config(self):
        current=sample()
        # Existing fixture has two nodes in one subscription.
        keys=[n['key'] for n in core.all_nodes(current)]
        return current,keys

    def test_version_features_and_stock_fallback(self):
        with mock.patch.object(engine_features.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'sing-box version 1.13.21\nFeatures: urltest.fallbacks,tools.decode-link,urltest.fallbacks\n')):
            self.assertEqual(engine_features.capabilities(),['tools.decode-link','urltest.fallbacks'])
        with mock.patch.object(engine_features.subprocess,'run',side_effect=FileNotFoundError):self.assertEqual(engine_features.capabilities(),[])

    def test_global_reserve_order_and_download_url(self):
        current,keys=self.config()
        current['settings'].update(urltest_fallbacks=[keys[-1]],urltest_download_check='custom',urltest_download_url='https://example.com/test.bin')
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES):cfg=core.make_config(current)
        auto=next(x for x in cfg['outbounds'] if x['tag']=='auto')
        self.assertEqual(auto['fallbacks'],[keys[-1]])
        self.assertNotIn(keys[-1],auto['outbounds'])
        self.assertEqual(auto['download_url'],'https://example.com/test.bin')
        self.assertIn(keys[-1],cfg['outbounds'][0]['outbounds'])

    def test_disabled_download_is_explicit_empty_string(self):
        group=dict(outbounds=['a'])
        engine_features.extend_group(group,dict(urltest_download_check='off'),FEATURES)
        self.assertEqual(group['download_url'],'')

    def test_stock_engine_rejects_requested_extensions(self):
        current,keys=self.config();current['settings']['urltest_fallbacks']=[keys[-1]]
        with mock.patch.object(engine_features,'capabilities',return_value=[]),self.assertRaises(core.AtlasError):core.make_config(current)

    def test_missing_reserve_and_empty_primary_rejected(self):
        for keys in [['c'*32],['a'*32]]:
            with self.assertRaises(ValueError):engine_features.extend_group(dict(outbounds=['a'*32]),dict(urltest_fallbacks=keys),FEATURES)

    def test_advanced_atlas_policy_is_not_bypassed(self):
        current,keys=self.config();current['settings'].update(max_ping_ms=100,urltest_fallbacks=[keys[-1]])
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES):cfg=core.make_config(current)
        self.assertEqual(cfg['outbounds'][0]['default'],'policy-block')
        auto=next(x for x in cfg['outbounds'] if x['tag']=='auto')
        self.assertEqual(auto['fallbacks'],[keys[-1]])
        current['settings'].update(urltest_download_check='custom',urltest_download_url='https://example.com/test.bin')
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES),self.assertRaises(core.AtlasError):core.make_config(current)

    def test_guarded_download_uses_member_api_and_disables_unselected_native_check(self):
        current,_=self.config();current['settings'].update(max_ping_ms=100,urltest_download_check='custom',urltest_download_url='https://example.com/data')
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES+['clash.download_test']):cfg=core.make_config(current)
        self.assertEqual(cfg['outbounds'][0]['default'],'policy-block')
        self.assertEqual(next(x for x in cfg['outbounds'] if x['tag']=='auto')['download_url'],'')

    def test_section_private_uot_reserve_uses_private_alias(self):
        current,keys=self.config();sid='c'*16
        current['settings']['sections']=[dict(id=sid,name='section',policy='proxy',domains=['example.com'],cidrs=[],source_ips=[],udp_over_tcp=True,urltest_fallbacks=[keys[-1]],urltest_download_check='off')]
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES):cfg=core.make_config(current)
        group=next(x for x in cfg['outbounds'] if x['tag']=='section_'+sid+'_auto')
        self.assertEqual(group['fallbacks'],['section_'+sid+'_'+keys[-1]])
        self.assertEqual(group['download_url'],'')

    def test_extended_engine_accepts_guarded_reserves_after_launch_rotation(self):
        binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
        if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine')
        from launch_cache import prepare,wire_request
        current,keys=self.config()
        current['settings'].update(max_ping_ms=100,urltest_fallbacks=[keys[-1]],urltest_download_check='off')
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES):cfg=prepare(core.make_config(current),'a'*32)
        auto=next(x for x in cfg['outbounds'] if x['tag']=='auto')
        self.assertEqual(auto['fallbacks'],['atlas_run_'+'a'*32+'_'+keys[-1]])
        self.assertNotIn('auto',cfg['outbounds'][0]['outbounds'])
        self.assertEqual(wire_request(cfg,'/proxies/proxy',{'name':'auto'})[1],{'name':'policy-block'})
        with tempfile.TemporaryDirectory() as directory:
            cfg['inbounds']=[dict(type='mixed',tag='test',listen='127.0.0.1',listen_port=19999)]
            cfg['experimental']['cache_file']['path']=str(Path(directory)/'cache.db')
            path=Path(directory)/'config.json';path.write_text(json.dumps(cfg),encoding='utf-8')
            result=subprocess.run([binary,'check','-c',str(path)],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def test_background_measurements_only_for_guarded_automatic_groups(self):
        current,keys=self.config();sid='c'*16
        current['settings'].update(max_ping_ms=100,sections=[dict(id=sid,name='private',policy='proxy',domains=['example.com'],cidrs=[],source_ips=[],udp_over_tcp=True)])
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES+['urltest.background']):cfg=core.make_config(current)
        groups={x['tag']:x for x in cfg['outbounds'] if x['type']=='urltest'}
        self.assertTrue(groups['auto']['background'])
        self.assertTrue(groups['section_'+sid+'_auto']['background'])
        current['settings']['selected']=keys[0]
        current['settings']['section_choices']={'section_'+sid+'_control':'section_'+sid+'_'+keys[0]}
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES+['urltest.background']):cfg=core.make_config(current)
        groups={x['tag']:x for x in cfg['outbounds'] if x['type']=='urltest'}
        self.assertNotIn('background',groups['auto'])
        self.assertNotIn('background',groups['section_'+sid+'_auto'])

    def test_background_extension_is_never_sent_to_stock_or_native_groups(self):
        current,_=self.config();current['settings']['max_ping_ms']=100
        with mock.patch.object(engine_features,'capabilities',return_value=[]):cfg=core.make_config(current)
        self.assertFalse(any('background' in x for x in cfg['outbounds']))
        current['settings']['max_ping_ms']=0
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES+['urltest.background']):cfg=core.make_config(current)
        self.assertFalse(any('background' in x for x in cfg['outbounds']))

    def test_reserve_validation_duplicates_and_urls(self):
        for value in [dict(urltest_fallbacks=['a'*32]*2),dict(urltest_download_check='custom',urltest_download_url='file:///etc/passwd')]:
            with self.assertRaises(ValueError):engine_features.validate_options(value,core.subscription_url)

    def test_expert_fallback_graph_namespaces_and_cycles(self):
        graph=[dict(type='urltest',tag='auto',outbounds=['one'],fallbacks=['two']),dict(type='socks',tag='one'),dict(type='socks',tag='two')]
        rewritten,_=outbounds.namespace_graph(graph,'fixture')
        self.assertEqual(rewritten[0]['fallbacks'],['fixture_two'])
        current,_=self.config()
        current['settings']['sections']=[dict(id='c'*16,name='expert',policy='proxy',domains=['example.com'],cidrs=[],source_ips=[],outbound_config=graph)]
        cfg=core.make_config(current)
        selector=next(x for x in cfg['outbounds'] if x['tag']=='section_'+'c'*16+'_control')
        self.assertIn('section_'+'c'*16+'_two',selector['outbounds'])
        graph[0]['fallbacks']=['auto']
        with self.assertRaises(ValueError):outbounds.outbound_graph(graph)

    def test_xhttp_decode_and_saved_profile_roundtrip(self):
        raw=dict(type='vless',server='example.com',server_port=443,uuid='11111111-1111-1111-1111-111111111111',tls=dict(enabled=True),transport=dict(type='xhttp',path='/transport',mode='packet-up',extra={'xmux':{'maxConcurrency':8}}))
        with mock.patch.object(engine_features,'decode_link',return_value=raw) as decoder:
            node=core.uri_node('vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&extra=%7B%7D#fixture')
        self.assertEqual(node['outbound']['transport'],raw['transport']);self.assertEqual(node['name'],'fixture')
        self.assertEqual(core.normalize(node['outbound'])['outbound'],node['outbound'])
        self.assertIn('extra=%7B%7D',decoder.call_args.args[0])

    def test_xhttp_forbidden_files_and_unverified_decoder(self):
        raw=dict(type='trojan',server='example.com',server_port=443,password='fixture',tls=dict(enabled=True),transport=dict(type='xhttp',extra={'certificate_path':'/etc/shadow'}))
        with self.assertRaises(core.AtlasError):core.normalize(raw)
        with mock.patch.object(engine_features,'capabilities',return_value=[]),self.assertRaises(ValueError):engine_features.decode_link('trojan://fixture@example.com?type=xhttp')

    def test_decoder_errors_never_expose_secret(self):
        with mock.patch.object(engine_features,'capabilities',return_value=FEATURES),mock.patch.object(engine_features.subprocess,'run',return_value=subprocess.CompletedProcess([],1)):
            with self.assertRaises(ValueError) as caught:engine_features.decode_link('trojan://secret@example.com?type=xhttp')
        self.assertNotIn('secret',str(caught.exception))
