"""A limited check budget must preserve only a still-qualified verified selection."""
from pathlib import Path
import sys,unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
from download_policy import DownloadPolicy
from site_policy import SitePolicy


class ProofContinuity(unittest.TestCase):
    def settings(self):return {'urltest_download_url':'https://example.org/data'}
    def rank(self,nodes,*args):return nodes[0]['key'] if nodes else None
    def saved(self,kind=DownloadPolicy,settings=None):
        settings=settings or self.settings()
        policy=kind({},'generation',lambda *args:{'ok':True,'received':65536,'tested':1},100)
        policy.choose([{'key':'current'}],settings,{},None,self.rank)
        return policy.export(8)

    def choose(self,saved=None,now=110,settings=None,rank=None,previous='current'):
        check=mock.Mock(return_value={'ok':True,'received':65536})
        policy=DownloadPolicy(saved or self.saved(),'generation',check,now);policy.calls=4
        result=policy.choose([{'key':'faster'},{'key':'current'}],settings or self.settings(),{},previous,rank or self.rank)
        check.assert_not_called()
        return result

    def test_current_verified_profile_survives_budget_exhaustion(self):
        self.assertEqual(self.choose(),('current','verified-budget-reused'))

    def test_expired_proof_or_new_target_or_generation_stays_blocked(self):
        self.assertEqual(self.choose(now=400)[0],'policy-block')
        self.assertEqual(self.choose(settings={'urltest_download_url':'https://example.org/other'})[0],'policy-block')
        saved=self.saved();saved['generation']='other'
        self.assertEqual(self.choose(saved=saved)[0],'policy-block')

    def test_missing_profile_bad_rtt_and_manual_unverified_selection_stay_blocked(self):
        rank=lambda nodes,*args:None if len(nodes)==1 and nodes[0]['key']=='current' else self.rank(nodes)
        self.assertEqual(self.choose(rank=rank)[0],'policy-block')
        self.assertEqual(self.choose(previous='removed')[0],'policy-block')
        self.assertEqual(self.choose(previous='faster')[0],'policy-block')

    def test_proof_invalidated_during_this_round_cannot_be_reused(self):
        policy=DownloadPolicy(self.saved(),'generation',lambda *args:None,110);policy.calls=4
        identity=next(iter(policy.proofs));policy.round[identity]=False
        self.assertEqual(policy.choose([{'key':'faster'},{'key':'current'}],self.settings(),{},'current',self.rank)[0],'policy-block')

    def test_deadline_preserves_current_but_never_expired_proof(self):
        with mock.patch('download_policy.time.monotonic',return_value=0) as clock:
            policy=DownloadPolicy(self.saved(),'generation',lambda *args:None,110)
            clock.return_value=23
            self.assertEqual(policy.choose([{'key':'faster'},{'key':'current'}],self.settings(),{},'current',self.rank)[0],'current')
            clock.return_value=300
            self.assertEqual(policy.choose([{'key':'faster'},{'key':'current'}],self.settings(),{},'current',self.rank)[0],'policy-block')

    def test_site_specific_proof_respects_short_ttl_and_target(self):
        settings={'site_checks':[{'url':'https://example.org/','statuses':[200]}],'urltest_download_check':'default','urltest_download_url':'','auto_interval_seconds':60}
        saved=self.saved(SitePolicy,settings)
        for now,expected in ((110,'current'),(160,'policy-block')):
            policy=SitePolicy(saved,'generation',lambda *args:None,now);policy.calls=4
            self.assertEqual(policy.choose([{'key':'faster'},{'key':'current'}],settings,{},'current',self.rank)[0],expected)
        settings['site_checks']=[{'url':'https://other.example/','statuses':[200]}]
        policy=SitePolicy(saved,'generation',lambda *args:None,110);policy.calls=4
        self.assertEqual(policy.choose([{'key':'faster'},{'key':'current'}],settings,{},'current',self.rank)[0],'policy-block')
