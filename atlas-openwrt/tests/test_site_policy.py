import sys,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core
from site_policy import SitePolicy
from test_expert_sections import sample,section

class SiteChecks(unittest.TestCase):
    def policy(self,url='https://youtube.com/'):
        return dict(site_checks=[dict(url=url,statuses=[200],contains='YouTube')],urltest_download_check='default',urltest_download_url='',auto_interval_seconds=60)
    def rank(self,nodes,*args):return nodes[0]['key'] if nodes else None
    def test_failed_site_advances_and_does_not_fall_back_to_direct(self):
        check=mock.Mock(side_effect=[{'ok':False,'tested':0},{'ok':True,'tested':1}])
        p=SitePolicy({},'generation',check,100)
        self.assertEqual(p.choose([dict(key='bad'),dict(key='good')],self.policy(),{},None,self.rank)[0],'good')
        self.assertEqual(check.call_count,2)
    def test_other_site_and_expired_proof_are_rechecked(self):
        check=mock.Mock(return_value={'ok':True,'tested':1});nodes=[dict(key='node')]
        p=SitePolicy({},'g',check,100);p.choose(nodes,self.policy(),{},None,self.rank)
        saved=p.export(1);check.reset_mock()
        SitePolicy(saved,'g',check,110).choose(nodes,self.policy('https://hdrezka.example/'),{},'node',self.rank)
        SitePolicy(saved,'g',check,161).choose(nodes,self.policy(),{},'node',self.rank)
        self.assertEqual(check.call_count,2)
    def test_failed_first_four_do_not_starve_remaining_profiles(self):
        nodes=[dict(key=str(i)) for i in range(6)]
        check=mock.Mock(return_value={'ok':False,'tested':0});p=SitePolicy({},'g',check,100)
        self.assertEqual(p.choose(nodes,self.policy(),{},None,self.rank)[0],'policy-block');self.assertEqual(check.call_count,4)
        check=mock.Mock(return_value={'ok':True,'tested':1});q=SitePolicy(p.export(1),'g',check,160)
        self.assertEqual(q.choose(nodes,self.policy(),{},None,self.rank)[0],'4');self.assertEqual(check.call_count,1)
    def test_partial_success_is_rejected(self):
        p=SitePolicy({},'g',lambda *args:{'ok':True,'tested':0},100)
        self.assertEqual(p.choose([dict(key='n')],self.policy(),{},None,self.rank)[0],'policy-block')
    def test_separate_selectors_and_guarded_selection_for_sites(self):
        s=sample();a=section('a',outbound_config=[]);b=section('b',outbound_config=[]);a['site_checks']=self.policy()['site_checks'];b['site_checks']=self.policy('https://example.org/')['site_checks']
        s['settings']['sections']=[a,b];c=core.make_config(s)
        controls=[o for o in c['outbounds'] if o['tag'].startswith('section_') and o['type']=='selector']
        self.assertEqual(len(controls),2);self.assertTrue(all(o['default']=='policy-block' for o in controls))
    def test_invalid_private_status_and_marker_are_rejected(self):
        for check in [dict(url='https://127.0.0.1/'),dict(url='https://example.org/',statuses=[403]),dict(url='https://example.org/',contains='a'*513)]:
            s=sample();s['settings']['sections']=[dict(section(),site_checks=[check])]
            with self.assertRaises(core.AtlasError):core.validate_settings(s['settings'])
