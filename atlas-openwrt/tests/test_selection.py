import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import time
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core
import atlas
from test_core import REALITY, state_with_node


def sample():
    value=state_with_node()
    value['subscriptions'][0]['nodes']=[]
    for i,name in enumerate(['🇪🇪 EE Hostslim','🇩🇪 DE Fast','🇳🇱 NL Backup']):
        n=core.uri_node(REALITY.replace('example.com','node%d.example.com'%i))
        n['name']=name
        value['subscriptions'][0]['nodes'].append(n)
    return value

class AutoSelection(unittest.TestCase):
    def test_country_recognition_is_label_only(self):
        cases={'🇪🇪 EE Hostslim':'EE','[EE] Hostslim':'EE','EE Hostslim':'EE','EE-host':'EE',
               'Fast Estonia server':'','stork.ee.example.com':'','FREE Server':'','🇩🇪 EE misleading':'DE'}
        for label,country in cases.items():self.assertEqual(core.country_from_name(label),country)

    def test_estonia_only_restricts_engine_outbounds(self):
        s=sample();s['settings']['countries']=['ee']
        c=core.make_config(s)
        nodes=[n for n in c['outbounds'] if n['type']=='vless']
        group=next(n for n in c['outbounds'] if n['tag']=='auto')
        self.assertEqual(len(nodes),1)
        self.assertEqual(nodes[0]['server'],'node0.example.com')
        self.assertEqual(group['outbounds'],[nodes[0]['tag']])
        self.assertEqual(c['outbounds'][0]['default'],'auto')

    def test_multiple_countries_or(self):
        s=sample();s['settings']['countries']=['EE','DE']
        self.assertEqual(len(core.selection_nodes(s)),2)

    def test_country_exclusion_removes_nodes_before_outbound_generation(self):
        s=sample();s['settings']['excluded_countries']=['ru','NL']
        self.assertEqual([n['name'] for n in core.selection_nodes(s)],['🇪🇪 EE Hostslim','🇩🇪 DE Fast'])

    def test_preferred_country_order_and_ping_scoring(self):
        nodes=core.all_nodes(sample()); now=int(time.time())
        stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now-30))
        def hist(delay): return {'history':[{'delay':delay,'time':stamp}]}
        proxies={nodes[0]['key']:hist(80),nodes[1]['key']:hist(160),nodes[2]['key']:hist(220)}
        settings=core.validate_settings({'preferred_countries':['DE','EE']})
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),nodes[1]['key'])
        settings=core.validate_settings({'auto_strategy':'slowest'})
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),nodes[2]['key'])
        settings=core.validate_settings({'auto_strategy':'slowest','max_ping_ms':200})
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),nodes[1]['key'])
        settings=core.validate_settings({'auto_strategy':'stable'})
        proxies[nodes[0]['key']]={'history':[{'delay':70,'time':stamp},{'delay':80,'time':stamp}]}
        proxies[nodes[1]['key']]={'history':[{'delay':100,'time':stamp},{'delay':300,'time':stamp}]}
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),nodes[0]['key'])

    def test_auto_selection_requires_recent_engine_measurements(self):
        nodes=core.all_nodes(sample()); settings=core.validate_settings({'auto_strategy':'slowest'})
        stale={n['key']:{'history':[{'delay':200,'time':'2020-01-01T00:00:00Z'}]} for n in nodes}
        self.assertIsNone(atlas.auto_choice(nodes,settings,stale,int(time.time())))

    def test_reserves_follow_order_and_return_to_qualifying_primary(self):
        nodes=core.all_nodes(sample()); keys=[n['key'] for n in nodes]
        now=int(time.time()); stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now))
        settings=core.validate_settings({'preferred_countries':['NL'],'max_ping_ms':100,'urltest_fallbacks':keys[1:]})
        proxies={key:{'history':[{'delay':delay,'time':stamp}]} for key,delay in zip(keys,[150,90,10])}
        # First reserve wins despite the second reserve's country and speed.
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),keys[1])
        proxies[keys[1]]['history'][-1]['delay']=0
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),keys[2])
        proxies[keys[0]]['history'][-1]['delay']=95
        self.assertEqual(atlas.auto_choice(nodes,settings,proxies,now),keys[0])

    def test_reserves_cannot_escape_staleness_or_ping_limits(self):
        nodes=core.all_nodes(sample()); keys=[n['key'] for n in nodes]
        now=int(time.time()); stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now))
        settings=core.validate_settings({'max_ping_ms':100,'urltest_fallbacks':keys[1:]})
        proxies={key:{'history':[{'delay':delay,'time':stamp}]} for key,delay in zip(keys,[200,150,50])}
        proxies[keys[2]]['history'][-1]['time']='2020-01-01T00:00:00Z'
        self.assertIsNone(atlas.auto_choice(nodes,settings,proxies,now))

    def test_exclusion_wins(self):
        s=sample();s['settings'].update(countries=['EE','DE'],include_names=['HOSTSLIM','FAST'],exclude_names=['hostslim'])
        self.assertEqual([n['name'] for n in core.selection_nodes(s)],['🇩🇪 DE Fast'])

    def test_protocol_filter_and_country_are_combined(self):
        s=sample();s['settings'].update(countries=['EE'],protocols=['trojan'])
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_unknown_country_no_silent_fallback(self):
        s=sample();s['settings']['countries']=['US']
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_name_filter_literal_not_regex(self):
        s=sample();s['settings']['include_names']=['.*']
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_manual_selection_cannot_escape_country_filter(self):
        s=sample();s['settings'].update(countries=['EE'],selected=core.all_nodes(s)[1]['key'])
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_disabled_subscription_not_candidate(self):
        s=sample();s['subscriptions'][0]['enabled']=False
        with self.assertRaises(core.AtlasError):core.make_config(s)

    def test_auto_intervals_tolerance_and_connection_policy(self):
        s=sample();s['settings'].update(auto_interval_seconds=30,auto_tolerance_ms=120,interrupt_connections=True)
        group=next(x for x in core.make_config(s)['outbounds'] if x['type']=='urltest')
        self.assertEqual(group['interval'],'30s');self.assertEqual(group['tolerance'],120)
        self.assertTrue(group['interrupt_exist_connections']);self.assertEqual(group['idle_timeout'],'30m')
        self.assertEqual(len(group['outbounds']),3)

    def test_legacy_settings_migrate_without_network_side_effects(self):
        s=core.validate_settings({'selected':'auto','mode':'rules'})
        self.assertEqual(s['countries'],[]);self.assertEqual(s['auto_interval_seconds'],60)
        self.assertFalse(s['interrupt_connections'])

    def test_bad_filter_parameters(self):
        cases=[{'countries':['Estonia']},{'countries':[None]},{'excluded_countries':['RUS']},{'preferred_countries':['?']},{'protocols':['exec']},
               {'include_names':['\n']},{'auto_interval_seconds':0},{'auto_interval_seconds':1801},{'auto_interval_seconds':True},
               {'auto_tolerance_ms':0},{'auto_tolerance_ms':2001},{'interrupt_connections':'true'},
               {'auto_strategy':'random'},{'min_ping_ms':400,'max_ping_ms':300},{'max_ping_ms':60001},
               {'urltest_url':'http://example.com/test'},
               {'exclude_names':['a']*51}]
        for data in cases:
            with self.assertRaises(core.AtlasError):core.validate_settings(data)

    def test_local_api_requires_secret_and_loopback(self):
        c=core.make_config(sample(),api_secret='a'*64)
        self.assertEqual(c['experimental']['clash_api']['external_controller'],'127.0.0.1:19090')
        with self.assertRaises(core.AtlasError):core.make_config(sample(),api_secret='')

class RuntimeObservation(unittest.TestCase):
    def setUp(self):
        self.nodes=core.all_nodes(sample());self.ee=self.nodes[0]['key'];self.de=self.nodes[1]['key']
        self.reply={'proxy':{'now':'auto'},'auto':{'now':self.ee,'all':[self.ee,self.de]},
                    self.ee:{'history':[{'delay':62,'time':'2026-09-22T12:00:00Z'}]}}

    def test_actual_auto_choice_and_measurement(self):
        r=atlas.decode_runtime(self.reply,self.nodes)
        self.assertEqual(r['country'],'EE');self.assertTrue(r['automatic'])
        self.assertEqual(r['last_delay_ms'],62);self.assertEqual(r['candidate_count'],2)

    def test_switch_is_reported_only_after_engine_changes(self):
        # Tests reporting, not the engine's failover implementation.
        r=atlas.decode_runtime(self.reply,self.nodes);self.assertEqual(r['selected'],self.ee)
        self.reply['auto']['now']=self.de
        r=atlas.decode_runtime(self.reply,self.nodes);self.assertEqual(r['selected'],self.de)
        self.assertNotIn('last_delay_ms',r)

    def test_manual_mode_not_reported_as_auto(self):
        self.reply['proxy']['now']=self.ee
        self.assertFalse(atlas.decode_runtime(self.reply,self.nodes)['automatic'])

    def test_no_fabricated_choice_when_api_has_none(self):
        self.reply['auto']['now']=''
        self.assertIsNone(atlas.decode_runtime(self.reply,self.nodes)['selected'])

    def test_cycle_rejected(self):
        self.reply['auto']['now']='proxy'
        with self.assertRaises(core.AtlasError):atlas.decode_runtime(self.reply,self.nodes)

    def test_direct_is_not_successful_proxy(self):
        self.reply['auto']['now']='direct'
        with self.assertRaises(core.AtlasError):atlas.decode_runtime(self.reply,self.nodes)

    def test_stopped_engine_does_not_report_old_choice(self):
        self.assertFalse(atlas.runtime_status(self.nodes,False)['available'])

class SavedFilters(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
        self.patches=[mock.patch.object(atlas,'DATA',self.path),mock.patch.object(atlas,'RUN',self.path),mock.patch.object(atlas,'STATE',self.path/'state.json'),mock.patch.object(atlas,'CONFIG',self.path/'config.json')]
        for p in self.patches:p.start()
        atlas.atomic(atlas.STATE,sample())
    def tearDown(self):
        for p in self.patches:p.stop()
        self.tmp.cleanup()

    def test_impossible_filter_does_not_destroy_saved_settings(self):
        old=atlas.state()
        with self.assertRaises(core.AtlasError):atlas.dispatch('save_settings',{'settings':{'countries':['US']}})
        self.assertEqual(atlas.state(),old)

    def test_estonia_filter_roundtrip_and_eligible_flags(self):
        atlas.dispatch('save_settings',{'settings':{'countries':['EE']}})
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'engine_version',return_value='test'):
            status=atlas.public_status()
        self.assertEqual(status['eligible_count'],1)
        self.assertEqual([n['country'] for n in status['nodes'] if n['eligible']],['EE'])

    def test_controller_secret_persistent_private_and_not_in_status(self):
        c=atlas.runtime_config(atlas.state());c2=atlas.runtime_config(atlas.state())
        secret=c['experimental']['clash_api']['secret']
        self.assertEqual(c,c2);self.assertEqual((self.path/'controller.json').stat().st_mode & 0o777,0o600)
        with mock.patch.object(atlas,'service_running',return_value=False),mock.patch.object(atlas,'engine_version',return_value='test'):
            self.assertNotIn(secret,json.dumps(atlas.public_status()))

    def test_runtime_http_failure_not_marked_connected(self):
        atlas.atomic(atlas.CONFIG,atlas.runtime_config(atlas.state()))
        connection=mock.Mock();connection.request.side_effect=OSError('refused')
        with mock.patch.object(atlas.http.client,'HTTPConnection',return_value=connection):
            r=atlas.runtime_status(core.all_nodes(atlas.state()),True)
        self.assertFalse(r['available']);self.assertNotIn('selected',r)

    def test_custom_auto_choice_changes_only_loopback_selector(self):
        current=atlas.state();current['settings'].update(auto_strategy='slowest')
        atlas.atomic(atlas.CONFIG,atlas.runtime_config(current))
        nodes=core.all_nodes(current); now=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        proxies={'proxy':{'now':'auto'},'auto':{'now':nodes[0]['key'],'all':[n['key'] for n in nodes]}}
        for n,delay in zip(nodes,[80,180,120]):proxies[n['key']]={'history':[{'delay':delay,'time':now}]}
        with mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'clash_request',side_effect=[{'proxies':proxies},{}]) as api:
            result=atlas.automatic_select(current)
        self.assertTrue(result['changed']);self.assertEqual(result['selected'],nodes[1]['key'])
        self.assertEqual(api.call_args_list[-1].args[:2],('PUT','/proxies/proxy'))
        self.assertEqual(api.call_args_list[-1].args[2],{'name':nodes[1]['key']})

    def test_private_section_reserve_order_is_independent_of_global_order(self):
        current=atlas.state(); keys=[n['key'] for n in core.all_nodes(current)]; sid='c'*16
        current['settings'].update(max_ping_ms=100,urltest_fallbacks=keys[1:],sections=[dict(id=sid,name='private',policy='proxy',domains=['example.com'],cidrs=[],source_ips=[],udp_over_tcp=True,urltest_fallbacks=[keys[0],keys[1]])])
        current['settings']=core.validate_settings(current['settings'])
        stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        prefix='section_'+sid+'_'; group=prefix+'control'
        proxies={'proxy':{'now':'policy-block'},group:{'now':'policy-block'}}
        for key,delay in zip(keys,[80,20,150]):
            proxies[key]={'history':[{'delay':delay,'time':stamp}]}
            proxies[prefix+key]=copy.deepcopy(proxies[key])
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=lambda method='GET',*args,**kwargs: {'proxies':proxies} if method=='GET' else {}):
            result=atlas.automatic_select(current)
        self.assertEqual(result['selected'],keys[0])
        private=next(x for x in result['groups'] if x['group']==group)
        self.assertEqual(private['selected'],prefix+keys[0])

    def test_watchdog_recovers_enabled_service_after_valid_config_check(self):
        current=atlas.state();config=atlas.runtime_config(current)
        atlas.atomic(atlas.CONFIG,config);atlas.atomic(atlas.DATA/'last-good.json',config)
        states=[False]*6+[True]
        def exists(path): return path.as_posix()=='/etc/rc.d/S99atlas'
        with mock.patch.object(atlas.Path,'exists',exists), mock.patch.object(atlas,'check'), \
             mock.patch.object(atlas,'service_running',side_effect=states), mock.patch.object(atlas,'wait_engine_ready',return_value=True), mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)) as run:
            result=atlas.healthcheck()
        self.assertEqual(result,{'ok':True,'reason':'restarted'});run.assert_called_once()

    def test_watchdog_limits_restarts_to_three_per_ten_minutes(self):
        current=atlas.state();config=atlas.runtime_config(current);atlas.atomic(atlas.CONFIG,config)
        now=int(time.time());atlas.atomic(atlas.RUN/'recovery.json',{'attempts':[now-20,now-10,now]})
        def exists(path): return path.as_posix()=='/etc/rc.d/S99atlas'
        with mock.patch.object(atlas.Path,'exists',exists), mock.patch.object(atlas,'check'), \
             mock.patch.object(atlas,'service_running',return_value=False), mock.patch.object(atlas,'run') as run:
            result=atlas.healthcheck()
        self.assertEqual(result['reason'],'restart-limit');run.assert_not_called()

    def test_netifd_events_are_limited_to_configured_logical_interfaces(self):
        current=atlas.state();current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'])
        atlas.atomic(atlas.STATE,current)
        self.assertEqual(atlas.record_interface_event('ifdown','wan')['reason'],'recorded')
        self.assertEqual(atlas.record_interface_event('ifup','lan')['reason'],'ignored')
        self.assertEqual(atlas.read_json(atlas.RUN/'interface-event.json',{})['action'],'ifdown')

    def test_interface_restore_restarts_only_once_for_ifup(self):
        current=atlas.state();current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'])
        atlas.atomic(atlas.RUN/'interface-event.json',{'id':'test-event','action':'ifup','interface':'wan','at':int(time.time())})
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'wait_engine_ready',return_value=True),mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)) as run:
            result=atlas.interface_recover(current)
            again=atlas.interface_recover(current)
        self.assertEqual(result['reason'],'interface-restarted');self.assertEqual(again['reason'],'already-handled')
        run.assert_called_once()

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'),'Set ATLAS_TEST_ENGINE')
    def test_filtered_runtime_config_accepted_by_engine(self):
        current=atlas.state();current['settings'].update(countries=['EE'],auto_interval_seconds=30,interrupt_connections=True)
        config=atlas.runtime_config(current)
        atlas.atomic(atlas.CONFIG,config)
        r=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(atlas.CONFIG)],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
