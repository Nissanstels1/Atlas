import copy,json,os,subprocess,tempfile,unittest
import core
from outbounds import outbound_graph
from test_expert_sections import sample,section

class SectionLinks(unittest.TestCase):
    def linked(self,**kwargs):
        state=sample();state['settings']['sections']=[section('A',id='a'*16,outbound_config=[dict(type='http',tag='entry',server='127.0.0.1',server_port=8080,detour='section_'+'b'*16+'_relay')]),section('B',id='b'*16,outbound_config=[dict(type='socks',tag='relay',server='127.0.0.1',server_port=1080)],**kwargs)]
        return state
    def engine_check(self,cfg):
        if os.environ.get('ATLAS_RULE_ENGINE'):
            with tempfile.TemporaryDirectory() as directory:
                path=os.path.join(directory,'config.json')
                with open(path,'w') as f:json.dump(cfg,f)
                result=subprocess.run([os.environ['ATLAS_RULE_ENGINE'],'check','-c',path],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
    def test_forward_link_between_sections_is_preserved(self):
        state=self.linked();before=copy.deepcopy(state);cfg=core.make_config(state,tun=False)
        a=next(x for x in cfg['outbounds'] if x['tag']=='section_'+'a'*16+'_entry')
        self.assertEqual(a['detour'],'section_'+'b'*16+'_relay');self.assertEqual(state,before)
        self.engine_check(cfg)
    def test_missing_disabled_and_cross_section_cycles_fail_closed(self):
        state=self.linked(enabled=False)
        with self.assertRaises(core.AtlasError):core.make_config(state,tun=False)
        state=self.linked();state['settings']['sections'][1]['outbound_config'][0]['detour']='section_'+'a'*16+'_entry'
        with self.assertRaises(core.AtlasError):core.make_config(state,tun=False)
        state=self.linked();state['settings']['sections'][0]['outbound_config'][0]['detour']='section_'+'c'*16+'_missing'
        with self.assertRaises(core.AtlasError):core.make_config(state,tun=False)
    def test_expert_selector_can_reference_existing_profile(self):
        state=sample();key=core.all_nodes(state)[0]['key']
        state['settings']['sections']=[section(outbound_config=[dict(type='selector',tag='entry',outbounds=[key],default=key)])]
        cfg=core.make_config(state,tun=False)
        group=next(x for x in cfg['outbounds'] if x['tag'].startswith('section_'))
        self.assertEqual(group['outbounds'],[key]);self.engine_check(cfg)
    def test_dns_resolver_and_port_transport_scope_are_independent(self):
        state=sample();state['settings']['sections']=[section(resolver='https://1.1.1.1/dns-query',ports=['443'],networks=['tcp'],source_ips=['192.168.1.20/32'])]
        cfg=core.make_config(state,tun=False)
        dns=next(x for x in cfg['dns']['rules'] if x.get('server','').startswith('vpn_dns_'))
        self.assertEqual(dns['source_ip_cidr'],['192.168.1.20/32']);self.assertNotIn('port',dns);self.assertNotIn('network',dns)
        route=next(x for x in cfg['route']['rules'] if x.get('port')==[443])
        self.assertEqual(route['network'],['tcp']);self.engine_check(cfg)
    def test_unlimited_active_pool_accepts_more_than_1024_profiles(self):
        state=sample();base=state['subscriptions'][0]['nodes'][0]
        state['subscriptions'][0]['nodes']=[dict(base,id='%016x'%i) for i in range(1100)]
        state['settings']['max_active_nodes']=0
        cfg=core.make_config(state,tun=False)
        self.assertEqual(len(next(x for x in cfg['outbounds'] if x['tag']=='auto')['outbounds']),1100)
        state['settings']['max_active_nodes']=1024
        with self.assertRaises(core.AtlasError):core.make_config(state,tun=False)
    def test_large_graph_chain_avoids_python_recursion_limit(self):
        graph=[dict(type='http',tag='n%d'%i,server='127.0.0.1',server_port=80,**({'detour':'n%d'%(i+1)} if i<1199 else {})) for i in range(1200)]
        self.assertEqual(len(outbound_graph(graph)),1200)
