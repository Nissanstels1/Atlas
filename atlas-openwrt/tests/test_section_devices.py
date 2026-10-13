import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core
from test_core import state_with_node

class FullDeviceRoutes(unittest.TestCase):
    def sample(self):
        state=state_with_node();state['settings']['sections']=[{'id':'c'*16,'name':'Video','policy':'proxy','domains':['youtube.com'],'cidrs':[],'source_ips':[],'routed_source_ips':['192.168.34.25'],'pools':[]}]
        state['settings']['group_order']=True
        return state

    def test_full_device_route_does_not_require_matching_domain(self):
        config=core.make_config(self.sample(),tun=False)
        rules=config['route']['rules'];full=next(x for x in rules if x.get('source_ip_cidr')==['192.168.34.25/32'] and x.get('action')=='route')
        domain=next(x for x in rules if x.get('domain_suffix')==['youtube.com'] and x.get('action')=='route')
        self.assertNotIn('domain_suffix',full);self.assertEqual(full['outbound'],domain['outbound'])

    def test_devices_only_section_is_valid(self):
        state=self.sample();state['settings']['sections'][0]['domains']=[]
        self.assertTrue(core.make_config(state,tun=False)['route']['rules'])

    def test_rejects_invalid_device_addresses(self):
        state=self.sample();state['settings']['sections'][0]['routed_source_ips']=['not-an-ip']
        with self.assertRaises(core.AtlasError):core.make_config(state,tun=False)

    def test_local_network_and_global_exceptions_still_precede_device_route(self):
        state=self.sample();state['settings']['bypass_domains']=['bank.example']
        rules=core.make_config(state,tun=False)['route']['rules']
        device=next(i for i,x in enumerate(rules) if x.get('source_ip_cidr')==['192.168.34.25/32'])
        self.assertLess(next(i for i,x in enumerate(rules) if x.get('ip_is_private')),device)
        self.assertLess(next(i for i,x in enumerate(rules) if x.get('domain_suffix')==['bank.example']),device)

    def test_block_device_rule_is_independent_of_domains(self):
        state=self.sample();state['settings']['sections'][0].update(policy='block',pools=None)
        rule=next(x for x in core.make_config(state,tun=False)['route']['rules'] if x.get('source_ip_cidr')==['192.168.34.25/32'])
        self.assertEqual(rule['action'],'reject');self.assertNotIn('domain_suffix',rule)
