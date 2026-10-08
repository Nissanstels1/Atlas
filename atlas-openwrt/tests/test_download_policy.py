import sys,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
from download_policy import DownloadPolicy,MAX_PROOFS

class DownloadProofs(unittest.TestCase):
    def settings(self):return {'urltest_download_url':'https://example.com/data'}
    def rank(self,nodes,*args):return nodes[0]['key'] if nodes else None
    def test_truncated_and_failed_primary_choose_next_without_direct_fallback(self):
        check=mock.Mock(side_effect=[{'ok':True,'received':16384},{'ok':True,'received':65536}])
        policy=DownloadPolicy({},'launch',check,100)
        self.assertEqual(policy.choose([{'key':'a'},{'key':'b'}],self.settings(),{},None,self.rank),('b','verified'))
        self.assertEqual(check.call_count,2)
    def test_no_response_or_tls_error_blocks(self):
        for result in ({'ok':False,'received':65536},{'ok':True,'received':'65536'},{},None):
            policy=DownloadPolicy({},'launch',lambda *args:result,100)
            self.assertEqual(policy.choose([{'key':'a'}],self.settings(),{},None,self.rank)[0],'policy-block')
    def test_proof_only_reused_for_unchanged_selection_and_expires(self):
        check=mock.Mock(return_value={'ok':True,'received':65536})
        policy=DownloadPolicy({},'launch',check,100);nodes=[{'key':'a'}]
        policy.choose(nodes,self.settings(),{},None,self.rank);saved=policy.export(1)
        check.reset_mock();policy=DownloadPolicy(saved,'launch',check,101)
        self.assertEqual(policy.choose(nodes,self.settings(),{},'a',self.rank),('a','verified-reused'));check.assert_not_called()
        policy=DownloadPolicy(saved,'launch',check,101)
        policy.choose(nodes,self.settings(),{},'policy-block',self.rank);self.assertEqual(check.call_count,1)
        policy=DownloadPolicy(saved,'launch',check,401)
        policy.choose(nodes,self.settings(),{},'a',self.rank);self.assertEqual(check.call_count,2)
    def test_new_launch_or_url_requires_new_proof(self):
        check=mock.Mock(return_value={'ok':True,'received':65536});nodes=[{'key':'a'}]
        policy=DownloadPolicy({},'old',check,100);policy.choose(nodes,self.settings(),{},None,self.rank)
        saved=policy.export(1);check.reset_mock()
        for generation,settings in [('new',self.settings()),('old',{'urltest_download_url':'https://example.com/new'})]:
            DownloadPolicy(saved,generation,check,101).choose(nodes,settings,{},'a',self.rank)
        self.assertEqual(check.call_count,2)
    def test_attempt_budget_is_global_and_round_deduplicates(self):
        check=mock.Mock(return_value={'ok':False,'received':0});policy=DownloadPolicy({},'launch',check,100)
        nodes=[{'key':str(i)} for i in range(10)]
        self.assertEqual(policy.choose(nodes,self.settings(),{},None,self.rank)[1],'check-budget')
        self.assertEqual(check.call_count,4)
        policy.choose(nodes,self.settings(),{},None,self.rank);self.assertEqual(check.call_count,4)
    def test_corruption_and_storage_bound(self):
        policy=DownloadPolicy({'generation':'launch','proofs':{'a'*64:'secret'},'cursor':'invalid'},'launch',None,100)
        self.assertEqual(policy.proofs,{})
        policy.proofs={str(i):100 for i in range(MAX_PROOFS+2)}
        self.assertEqual(len(policy.export(3)['proofs']),MAX_PROOFS)
        self.assertEqual(policy.export(3)['cursor'],1)

    def test_measurement_that_expires_during_transfer_cannot_be_selected(self):
        fresh=[True]
        def check(*args):fresh[0]=False;return {'ok':True,'received':65536}
        def rank(nodes,*args):return nodes[0]['key'] if nodes and fresh[0] else None
        policy=DownloadPolicy({},'launch',check,100)
        self.assertEqual(policy.choose([{'key':'a'}],self.settings(),{},None,rank)[0],'policy-block')
