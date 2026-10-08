import json,os,subprocess,tempfile,threading,time,unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
from types import SimpleNamespace
import atlas,core,sections
from test_independent_sections import sec
from test_expert_sections import sample
import test_extensions_rpc as fixtures

class RecoveryUot(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown

    def test_empty_pool_with_remote_rules_has_useful_error(self):
        current=sample();current['subscriptions'][0]['nodes']=[]
        current['settings']['sections']=[sec(pool='b'*16)]
        current['settings']['remote_lists']=[dict(id='c'*16,name='rules',url='https://example.org/rules',format='domains',policy='direct',enabled=True,domains=['other.example.org'])]
        with self.assertRaises(core.AtlasError):core.make_config(current,tun=False)

    def test_user_control_tag_is_preserved_and_generated_wrapper_is_unique(self):
        current=sample();current['settings']['sections']=[sec(id='a'*16,outbound_config=[dict(type='urltest',tag='entry',outbounds=['control'],url='https://example.org/check'),dict(type='direct',tag='control')])]
        cfg=core.make_config(current,tun=False);tags=[x['tag'] for x in cfg['outbounds']]
        self.assertEqual(len(tags),len(set(tags)))
        self.assertIn('section_'+'a'*16+'_control_1',tags)
        if os.environ.get('ATLAS_RULE_ENGINE'):
            with tempfile.TemporaryDirectory() as directory:
                p=os.path.join(directory,'config.json')
                with open(p,'w') as file:json.dump(cfg,file)
                result=subprocess.run([os.environ['ATLAS_RULE_ENGINE'],'check','-c',p],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_two_recovery_requests_restart_once(self):
        current=sample();current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'])
        atlas.atomic(atlas.RUN/'interface-event.json',dict(id='same',action='ifup',interface='wan',at=1))
        def restart(*args):
            time.sleep(.1);return SimpleNamespace(returncode=0)
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'wait_engine_ready',return_value=True),mock.patch.object(atlas,'run',side_effect=restart) as run:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(lambda _:atlas.interface_recover(current),range(2)))
            self.assertEqual(run.call_count,1)
            self.assertEqual({x['reason'] for x in results},{'interface-restarted','already-handled'})

    def test_burst_updates_queue_without_spawning_while_gate_owned(self):
        current=sample();current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan']);atlas.atomic(atlas.STATE,current)
        with atlas.named_lock('interface-worker.lock',True),mock.patch.object(atlas.subprocess,'Popen') as spawn:
            for _ in range(20):self.assertEqual(atlas.record_interface_event('ifup','wan')['reason'],'coalesced')
            spawn.assert_not_called()
        with mock.patch.object(atlas.subprocess,'Popen') as spawn:
            atlas.record_interface_event('ifup','wan');spawn.assert_called_once()

    def test_section_uot_nodes_are_independent_and_selectable(self):
        current=sample();current['subscriptions'][0]['nodes']=[core.uri_node('socks5://fixture:fixture@127.0.0.1:1080#SOCKS')]
        current['settings'].update(udp_over_tcp=True,sections=[sec('A',id='a'*16,udp_over_tcp=False),sec('B',id='d'*16,udp_over_tcp=True,udp_over_tcp_version=1)])
        current['settings']=core.validate_settings(current['settings']);cfg=core.make_config(current,tun=False)
        originals=[x for x in cfg['outbounds'] if x['type']=='socks' and len(x['tag'])==32]
        self.assertEqual(originals[0]['udp_over_tcp'],dict(enabled=True,version=2))
        for section,enabled,version in zip(current['settings']['sections'],(False,True),(2,1)):
            groups=sections.groups_for_section(section,cfg);control=next(x for x in groups if x['type']=='selector')
            member=next(x for x in control['outbounds'] if len(x)==57)
            outbound=next(x for x in cfg['outbounds'] if x['tag']==member)
            self.assertEqual(outbound['udp_over_tcp'],dict(enabled=enabled,version=version))
            request=mock.Mock(return_value={})
            sections.choose_section(current,cfg,section['id'],control['tag'],member,request)
            self.assertEqual(current['settings']['section_choices'][control['tag']],member)
        if os.environ.get('ATLAS_RULE_ENGINE'):
            with tempfile.TemporaryDirectory() as directory:
                p=os.path.join(directory,'config.json')
                with open(p,'w') as file:json.dump(cfg,file)
                result=subprocess.run([os.environ['ATLAS_RULE_ENGINE'],'check','-c',p],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_uot_validation(self):
        for value in (dict(udp_over_tcp=1),dict(udp_over_tcp_version=True),dict(udp_over_tcp_version=3),dict(policy='direct',udp_over_tcp=True),dict(outbound_config=[dict(type='direct')],udp_over_tcp=True)):
            with self.assertRaises(core.AtlasError):core.validate_settings(dict(sections=[sec(**value)]))

    def test_auto_policy_sees_cloned_member_keys(self):
        current=sample();current['settings']['sections']=[sec(id='a'*16,udp_over_tcp=True)]
        current['settings']=core.validate_settings(current['settings'])
        cfg=core.make_config(current,tun=False)
        proxies={x['tag']:dict(now='old') for x in cfg['outbounds']}
        seen=[]
        def choose(nodes,*args):
            seen.extend(n['key'] for n in nodes);return nodes[0]['key'] if nodes else None
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'custom_auto_policy',return_value=True),mock.patch.object(atlas,'auto_choice',side_effect=choose),mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}):
            result=atlas.automatic_select(current)
        group=next(x for x in result['groups'] if x['group']=='section_'+'a'*16+'_control')
        self.assertTrue(group['selected'].startswith('section_'+'a'*16+'_'))
        self.assertIn(group['selected'],seen)

    def test_old_client_preserves_udp_over_tcp_override(self):
        current=sample();current['settings']['sections']=[sec(id='a'*16,udp_over_tcp=False,udp_over_tcp_version=1)]
        current['settings']=core.validate_settings(current['settings']);atlas.atomic(atlas.STATE,current)
        incoming=json.loads(json.dumps(current['settings']))
        for section in incoming['sections']:
            del section['udp_over_tcp'];del section['udp_over_tcp_version']
        atlas.dispatch('save_settings',{'settings':incoming})
        section=atlas.state()['settings']['sections'][0]
        self.assertEqual((section['udp_over_tcp'],section['udp_over_tcp_version']),(False,1))
