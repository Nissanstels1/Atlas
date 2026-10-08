import time,unittest
from unittest import mock
import atlas,core,sections
from test_expert_sections import sample
from test_independent_sections import sec
import test_extensions_rpc as fixtures

class SelectionRecheck(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown

    def test_freshness_uses_each_section_interval_in_both_directions(self):
        for global_interval,section_interval,blocked in ((60,300,False),(300,30,True)):
            current=sample();current['settings'].update(auto_strategy='stable',auto_interval_seconds=global_interval,sections=[sec(id='a'*16,auto_interval_seconds=section_interval)])
            current['settings']=core.validate_settings(current['settings']);node=core.all_nodes(current)[0]
            stamp=1700000000;tag='section_'+'a'*16+'_control'
            proxies={node['key']:dict(history=[dict(delay=40,time=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(stamp-200)))]),tag:dict(now='old')}
            with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}),mock.patch.object(atlas.time,'time',return_value=stamp):
                result=atlas.automatic_select(current)
            group=next(x for x in result['groups'] if x['group']==tag)
            self.assertEqual(group['blocked'],blocked)
            self.assertEqual(group['selected'],'policy-block' if blocked else node['key'])

    def test_failed_first_group_does_not_skip_next_and_reports_partial_result(self):
        current=sample();current['settings']['sections']=[sec(id='a'*16,auto_interval_seconds=300)]
        current['settings']=core.validate_settings(current['settings']);cfg=core.make_config(current,tun=False)
        proxies={x['tag']:dict(now='old') for x in cfg['outbounds']};calls=[]
        def request(method='GET',path='/proxies',*args,**kwargs):
            if method=='GET':return {'proxies':proxies}
            calls.append(path)
            if path=='/proxies/proxy':raise core.AtlasError('transient failure')
            return {}
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=request):
            result=atlas.automatic_select(current)
        self.assertIn('/proxies/section_'+'a'*16+'_control',calls)
        self.assertEqual(result['reason'],'partial-failure');self.assertTrue(result['changed'])
        failed=next(x for x in result['groups'] if x['group']=='proxy')
        self.assertFalse(failed['ok']);self.assertFalse(failed['changed']);self.assertEqual(failed['selected'],'old')
        saved=atlas.read_json(atlas.RUN/'auto-selection.json',{})
        self.assertEqual(saved,result)

    def test_delay_test_visits_every_node_of_maximum_pool(self):
        current=core.defaults();current['settings'].update(max_active_nodes=1024,sections=[sec(id='a'*16)])
        for sid in ('b'*16,'c'*16):
            current['subscriptions'].append(dict(id=sid,name='fixture',source='local',enabled=True,nodes=[core.uri_node('socks5://127.0.0.1:'+str(10000+i)+'#fixture'+str(i)) for i in range(512)]))
        current['settings']=core.validate_settings(current['settings']);cfg=core.make_config(current,tun=False)
        nodes={n['key'] for n in core.all_nodes(current)}
        result=sections.test_section(current,cfg,'a'*16,lambda *args,**kwargs:{'delay':1})
        self.assertEqual(len(nodes),1024);self.assertTrue(nodes.issubset(result))
