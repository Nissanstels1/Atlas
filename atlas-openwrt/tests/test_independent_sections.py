import base64,copy,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
import core,atlas,sections
import test_extensions_rpc as fixtures
from test_expert_sections import sample

def sec(name='A',**kwargs):
    return dict(name=name,policy='proxy',domains=[name.lower()+'.example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='') | kwargs

class IndependentSections(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown
    def config(self,**settings):
        state=sample();state['settings'].update(settings);return state,core.make_config(state,tun=False)
    def test_real_ip_on_one_section_and_off_override_global(self):
        for global_flag in (False,True):
            state,cfg=self.config(resolve_real_ip=global_flag,sections=[sec('A',resolve_real_ip=True),sec('B',resolve_real_ip=False)])
            resolves=[r for r in cfg['route']['rules'] if r.get('action')=='resolve']
            self.assertTrue(any(r.get('domain_suffix')==['a.example.org'] for r in resolves))
            self.assertFalse(any(r.get('domain_suffix')==['b.example.org'] for r in resolves))
    def test_assigned_json_rules_and_mixed_inherit_section_resolution(self):
        sid='a'*16
        state,cfg=self.config(sections=[sec(id=sid,resolve_real_ip=True,mixed_proxy=dict(enabled=True,listen='127.0.0.1',port=2082,username='fixture',password='fixture-only-password'))],remote_lists=[dict(name='rules',id='c'*16,url='https://example.org/rules.json',format='json',policy='proxy',enabled=True,section=sid,source_cached=True,source_rules=dict(version=3,rules=[dict(domain=['other.example.org'])]))])
        cfg=core.make_config(state)
        self.assertTrue(any(r.get('action')=='resolve' and r.get('inbound')==['mixed_'+sid] for r in cfg['route']['rules']))
        self.assertTrue(any(r.get('action')=='resolve' and r.get('rule_set')==['rules_'+'c'*16] for r in cfg['route']['rules']))
    def test_each_pool_has_own_url_interval_tolerance_and_selector(self):
        state,cfg=self.config(sections=[sec('A',auto_interval_seconds=30,auto_tolerance_ms=50,urltest_url='https://one.example.org/check'),sec('B',auto_interval_seconds=300,auto_tolerance_ms=120,urltest_url='https://two.example.org/check')])
        validated=core.validate_settings(state['settings'])
        groups=[]
        for section,interval,url,tolerance in zip(validated['sections'],('30s','300s'),('one','two'),(50,120)):
            group=sections.groups_for_section(section,cfg);self.assertEqual(len(group),2)
            auto=next(x for x in group if x['type']=='urltest')
            self.assertEqual((auto['interval'],auto['url'],auto['tolerance']),(interval,'https://'+url+'.example.org/check',tolerance))
            groups.append(group[0]['tag'])
        self.assertNotEqual(*groups)
        dashboard=sections.section_dashboard(dict(state,settings=validated),cfg,lambda:{})
        self.assertTrue(all(not g['shared'] for row in dashboard for g in row['groups']))
    def test_manual_section_choice_and_return_to_auto_are_isolated(self):
        state,cfg=self.config(sections=[sec(auto_interval_seconds=90)])
        state['settings']=core.validate_settings(state['settings']);section=state['settings']['sections'][0]
        group=sections.groups_for_section(section,cfg)[0];node=next(x for x in group['outbounds'] if len(x)==32)
        request=mock.Mock(return_value={})
        sections.choose_section(state,cfg,section['id'],group['tag'],node,request)
        self.assertEqual(state['settings']['section_choices'][group['tag']],node)
        sections.choose_section(state,cfg,section['id'],group['tag'],group['outbounds'][0],request)
        self.assertNotIn(group['tag'],state['settings']['section_choices'])
    def test_auto_criteria_cover_private_section_pools(self):
        state,cfg=self.config(sections=[sec(auto_interval_seconds=90)],auto_strategy='stable')
        state['settings']=core.validate_settings(state['settings']);sid=state['settings']['sections'][0]['id']
        tag='section_'+sid+'_control'
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',return_value={'proxies':{tag:{'now':'x'}}}),mock.patch.object(atlas,'auto_choice',return_value=None):
            result=atlas.automatic_select(state)
        self.assertTrue(any(x['group']==tag and x['blocked'] for x in result['groups']))
    def test_old_clients_preserve_section_overrides(self):
        state=atlas.state();state['settings']['sections']=[sec(resolve_real_ip=True,auto_interval_seconds=90)]
        state['settings']=core.validate_settings(state['settings']);atlas.atomic(atlas.STATE,state)
        incoming=copy.deepcopy(state['settings'])
        for key in ('resolve_real_ip','auto_interval_seconds','auto_tolerance_ms','urltest_url'):incoming['sections'][0].pop(key)
        atlas.dispatch('save_settings',{'settings':incoming})
        self.assertEqual(atlas.state()['settings']['sections'][0]['auto_interval_seconds'],90)
        self.assertTrue(atlas.state()['settings']['sections'][0]['resolve_real_ip'])
    def test_invalid_overrides_and_delay_rejected(self):
        for values in (dict(resolve_real_ip=1),dict(auto_interval_seconds=0),dict(auto_tolerance_ms=3000),dict(urltest_url=False),dict(urltest_url='http://example.org'),dict(policy='direct',auto_interval_seconds=90),dict(outbound_config=[dict(type='direct')],auto_interval_seconds=90)):
            with self.assertRaises(core.AtlasError):core.validate_settings({'sections':[sec(**values)]})
        for delay in (-1,60001,True):
            with self.assertRaises(core.AtlasError):core.validate_settings({'interface_reload_delay_ms':delay})
    def test_direct_and_block_sections_start_without_profiles(self):
        for policy in ('direct','block','exclude'):
            state=core.defaults();state['settings']['sections']=[sec(policy=policy)]
            cfg=core.make_config(state,tun=False)
            self.assertTrue(any(x['tag']=='local-only-block' and x['type']=='block' for x in cfg['outbounds']))
            self.assertEqual(next(x for x in cfg['dns']['servers'] if x['tag']=='secure').get('detour','direct'),'direct')
    def test_missing_proxy_json_does_not_gain_direct_dns_fallback(self):
        state=core.defaults();state['settings']['remote_lists']=[dict(id='c'*16,name='proxy',url='https://example.org/rules.json',format='json',policy='proxy',enabled=True,source_cached=True,source_rules=dict(version=3,rules=[dict(domain=['example.org'])]))]
        cfg=core.make_config(state,tun=False)
        self.assertEqual(next(x for x in cfg['dns']['servers'] if x['tag']=='secure')['detour'],'proxy')
    def test_ifup_spawns_debounced_worker_ifdown_does_not(self):
        state=atlas.state();state['settings'].update(interface_monitoring=True,monitored_interfaces=['wan']);atlas.atomic(atlas.STATE,state)
        with mock.patch.object(atlas.subprocess,'Popen') as spawn:
            atlas.record_interface_event('ifdown','wan');spawn.assert_not_called()
            atlas.record_interface_event('ifup','wan');spawn.assert_called_once()
            self.assertEqual(spawn.call_args.args[0][2],'iface-recover')
            self.assertEqual(spawn.call_args.kwargs['pass_fds'],(int(spawn.call_args.args[0][-1]),))
    def test_worker_coalesces_events_without_holding_lock_during_delay(self):
        state=atlas.state();state['settings']['interface_reload_delay_ms']=250;atlas.atomic(atlas.STATE,state)
        atlas.atomic(atlas.RUN/'interface-event.json',dict(id='latest',action='ifup',interface='wan'))
        with mock.patch.object(atlas.time,'sleep') as sleep,mock.patch.object(atlas,'active_job',return_value={'status':'running'}),mock.patch.object(atlas,'interface_recover') as recover:
            self.assertEqual(atlas.interface_event_worker('old')['reason'],'superseded-or-busy');recover.assert_not_called();self.assertAlmostEqual(sleep.call_args.args[0],.25,places=2)
        with mock.patch.object(atlas.time,'sleep'),mock.patch.object(atlas,'active_job',return_value={}),mock.patch.object(atlas,'interface_recover',return_value={'ok':True,'reason':'interface-restarted'}) as recover:
            self.assertTrue(atlas.interface_event_worker('latest')['ok']);recover.assert_called_once()
    def test_recovery_uses_same_90_seconds_as_manual_start(self):
        state=atlas.state();state['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'])
        atlas.atomic(atlas.RUN/'interface-event.json',dict(id='latest',action='ifup',interface='wan',at=1))
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'wait_engine_ready',return_value=True),mock.patch.object(atlas,'run',return_value=SimpleNamespace(returncode=0)) as run:
            atlas.interface_recover(state);self.assertEqual(run.call_args.args,(['/etc/init.d/atlas','restart'],90))
    def test_recovery_waits_for_api_not_just_launcher(self):
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas.time,'sleep'),mock.patch.object(atlas,'clash_request',side_effect=[OSError('not ready'),{'proxies':{}}]):
            self.assertTrue(atlas.wait_engine_ready(attempts=2))
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas.time,'sleep'),mock.patch.object(atlas,'clash_request',side_effect=OSError('not ready')):
            self.assertFalse(atlas.wait_engine_ready(attempts=2))
    def test_browser_import_larger_than_64k_and_rpc_boundary(self):
        body=b'# fixture comment\n'*5000+b'example.org\n'
        result=atlas.dispatch('import_rules',dict(content=base64.b64encode(body).decode(),target='direct'))
        self.assertEqual(result['domains'],1)
        self.assertGreater(atlas.rpc_request_limit('import_rules'),len(base64.b64encode(body)))
        with self.assertRaises(core.AtlasError):atlas.dispatch('import_rules',dict(content='A'*(4*((4*1024*1024+2)//3)+1),target='direct'))
    @unittest.skipUnless(os.environ.get('ATLAS_RULE_ENGINE'),'Requires installed sing-box')
    def test_independent_pools_and_real_ip_accepted_by_engine(self):
        state,cfg=self.config(sections=[sec('A',resolve_real_ip=True,auto_interval_seconds=30),sec('B',resolve_real_ip=False,auto_interval_seconds=300)])
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'config.json';p.write_text(json.dumps(cfg))
            result=subprocess.run([os.environ['ATLAS_RULE_ENGINE'],'check','-c',str(p)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
