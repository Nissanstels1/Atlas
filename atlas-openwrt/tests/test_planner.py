import copy,json,sys,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,atlas,planner
import test_extensions_rpc as fixtures
from test_expert_sections import sample,section

class Planner(unittest.TestCase):
    def test_list_capacity_supports_more_than_64_sources(self):
        s=sample()['settings'];s['remote_lists']=[dict(name=str(i),url='https://example.org/'+str(i)+'.txt',policy='proxy',format='domains',enabled=True) for i in range(64)]
        self.assertEqual(len(core.validate_settings(s)['remote_lists']),64)
        s['remote_lists'].append(dict(s['remote_lists'][0],url='https://example.org/65.txt'))
        self.assertEqual(len(core.validate_settings(s)['remote_lists']),65)
    def test_section_exception_allows_later_rule_instead_of_global_direct(self):
        s=sample();s['settings']['sections']=[section('first',domains=['example.org'],exclude_domains=['private.example.org']),section('second',domains=['private.example.org'])]
        cfg=core.make_config(s)
        q=dict(domain='private.example.org',ip='1.1.1.1',source_ip='192.168.1.25',port=443,network='tcp',protocol='tls',inbound='tun')
        r=planner.explain_route(cfg,q)
        sid=core.validate_settings(s['settings'])['sections'][1]['id']
        self.assertTrue(r['certain']);self.assertEqual(r['outbound'],'section_'+sid+'_entry')

    def test_domain_and_ip_match_engine_or_semantics(self):
        rule={'domain_suffix':['example.org'],'ip_cidr':['1.1.1.1/32'],'source_ip_cidr':['192.168.1.0/24']}
        self.assertTrue(planner.match_rule(rule,{'domain':'other.org','ip':'1.1.1.1','source_ip':'192.168.1.2'},{}))
        self.assertFalse(planner.match_rule(rule,{'domain':'example.org','ip':'8.8.8.8','source_ip':'192.168.2.2'},{}))

    def test_missing_ip_or_binary_set_never_claims_certainty(self):
        cfg={'route':{'final':'direct','rules':[{'rule_set':['opaque'],'action':'route','outbound':'proxy'}]}}
        r=planner.explain_route(cfg,{'domain':'example.org','network':'tcp'})
        self.assertFalse(r['certain']);self.assertIsNone(r['outbound'])
        self.assertIsNone(planner.match_rule({'ip_is_private':True},{'ip':'100.64.0.1'},{}))

    def test_scoped_device_and_destination_exceptions(self):
        sec=dict(exclude_domains=[],exclude_cidrs=['1.1.1.1/32'],exclude_source_ips=['192.168.1.25/32'])
        rule=core.section_match(sec,{'source_ip_cidr':['192.168.1.0/24']})
        self.assertFalse(planner.match_rule(rule,{'source_ip':'192.168.1.25','ip':'8.8.8.8'},{}))
        self.assertFalse(planner.match_rule(rule,{'source_ip':'192.168.1.26','ip':'1.1.1.1'},{}))
        self.assertTrue(planner.match_rule(rule,{'source_ip':'192.168.1.26','ip':'8.8.8.8'},{}))

    def test_redaction_hides_unknown_expert_credentials_and_url_query(self):
        cfg={'outbounds':[dict(type='http',tag='x',server='example.org',password='SECRET',odd_field='SECRET',headers={'custom':'SECRET'})], 'inbounds':[{'users':[{'password':'SECRET'}]}],'experimental':{'clash_api':{'secret':'SECRET'}},'url':'https://user:SECRET@example.org/path?token=SECRET'}
        redacted=planner.safe_config(cfg)
        self.assertNotIn('SECRET',json.dumps(redacted));self.assertEqual(cfg['outbounds'][0]['password'],'SECRET')

    def test_conflicts_only_report_proven_simple_shadowing(self):
        settings=core.validate_settings(dict(sample()['settings'],sections=[section('first',domains=['example.org']),section('second',domains=['sub.example.org']),section('scoped',domains=['example.org'],source_ips=['192.168.1.2'])]))
        issues=planner.conflicts(settings)
        self.assertEqual(len(issues),1);self.assertEqual(issues[0]['section'],'second')

    def test_invalid_queries_are_rejected(self):
        for query in [dict(domain=[],network='tcp'),dict(domain='example.org',network='tcp',port=65536),dict(domain='example.org',network='tcp',ip='bad'),dict(domain='example.org',network='tcp',url='https://example.org')]:
            with self.assertRaises(core.AtlasError):planner.validated_query(query)

class PlannerRPC(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown

    def test_preview_never_saves_controller_state_or_active_config(self):
        before=atlas.STATE.read_bytes()
        with mock.patch.object(atlas,'prepare_runtime_paths') as paths,mock.patch.object(atlas,'check') as check:
            r=atlas.dispatch('config_preview',{'validate':True})
        self.assertTrue(r['validated']);check.assert_called_once();paths.assert_not_called()
        self.assertEqual(atlas.STATE.read_bytes(),before);self.assertFalse((self.root/'controller.json').exists());self.assertFalse(atlas.CONFIG.exists())

    def test_clone_is_disabled_new_id_no_listener_no_shared_object(self):
        state=atlas.state();sec=state['settings']['sections'][0]
        result=atlas.dispatch('section_clone',dict(id=sec['id'],name='copy'))
        rows=atlas.state()['settings']['sections'];clone=rows[-1]
        self.assertFalse(clone['enabled']);self.assertFalse(clone['mixed_proxy']['enabled']);self.assertEqual(clone['mixed_proxy']['password'],'')
        self.assertNotEqual(clone['id'],sec['id']);self.assertEqual(clone['outbound_config'],sec['outbound_config']);self.assertEqual(result['id'],clone['id'])

    def test_autostart_does_not_start_stop_or_save_config(self):
        before=atlas.STATE.read_bytes()
        with mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0)) as run:
            atlas.dispatch('set_autostart',{'enabled':True})
        self.assertEqual(run.call_args.args[0],['/etc/init.d/atlas','enable']);self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_logs_are_bounded_and_use_fixed_service_filter(self):
        with mock.patch.object(atlas,'run',return_value=mock.Mock(returncode=0,stdout=('line\n'*300).encode())) as run:
            result=atlas.dispatch('service_logs',{})
        self.assertEqual(len(result['content'].splitlines()),200);self.assertTrue(result['truncated'])
        self.assertEqual(run.call_args.args[0],['/sbin/logread','-e','atlas'])

if __name__=='__main__':unittest.main()
