import copy
import unittest
from unittest.mock import patch
from test_core import state_with_node
import core

class MultiSourceSections(unittest.TestCase):
    def sample(self):
        s=state_with_node()
        second=copy.deepcopy(s['subscriptions'][0]);second['id']='a'*16;second['name']='Second'
        s['subscriptions'].append(second)
        s['settings']['sections']=[{'name':'Sites','policy':'proxy','domains':['example.org'],'cidrs':[],'source_ips':[],'id':'c'*16,'pools':[]}]
        return s

    def test_all_sources_have_independent_section_auto(self):
        c=core.make_config(self.sample())
        g=next(x for x in c['outbounds'] if x['tag']=='section_'+'c'*16+'_auto')
        self.assertEqual(len(g['outbounds']),2)

    def test_subset_does_not_include_other_subscription(self):
        s=self.sample();s['settings']['sections'][0]['pools']=['a'*16]
        c=core.make_config(s)
        g=next(x for x in c['outbounds'] if x['tag']=='section_'+'c'*16+'_auto')
        self.assertEqual(len(g['outbounds']),1)
        self.assertTrue(g['outbounds'][0].startswith('a'*16))

    def test_thirty_sources_forty_profiles_all_active(self):
        s=self.sample();template=s['subscriptions'][0];s['subscriptions']=[]
        for i in range(30):
            sub=copy.deepcopy(template);sub['id']='%016x'%i;sub['name']='Source %d'%i
            sub['nodes']=[dict(copy.deepcopy(template['nodes'][0]),id='%016x'%j) for j in range(40)]
            s['subscriptions'].append(sub)
        c=core.make_config(s)
        g=next(x for x in c['outbounds'] if x['tag']=='section_'+'c'*16+'_auto')
        self.assertEqual(len(g['outbounds']),1200)

    def test_native_fastest_uses_advertised_background_support(self):
        with patch('engine_features.capabilities',return_value={'urltest.background'}):
            c=core.make_config(self.sample())
        self.assertTrue(all(x.get('background') for x in c['outbounds'] if x['type']=='urltest'))

    def test_invalid_source_id_rejected(self):
        s=self.sample();s['settings']['sections'][0]['pools']=['not-an-id']
        with self.assertRaises(core.AtlasError):core.make_config(s)
