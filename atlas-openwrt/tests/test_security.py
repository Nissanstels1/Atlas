import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
from security import compare_client,fingerprint,uniform_proxy_expected

class Security(unittest.TestCase):
    def test_explicit_direct_routes_are_not_uniform_proxy(self):
        self.assertTrue(uniform_proxy_expected(dict(mode='global')))
        self.assertFalse(uniform_proxy_expected(dict(mode='global'),dict(route=dict(final='direct'))))
        self.assertFalse(uniform_proxy_expected(dict(mode='global'),dict(route=dict(final='proxy',rules=[dict(outbound='direct',domain_suffix=['api.ipify.org'])]),outbounds=[dict(tag='direct',type='direct')])))
        for changed in [dict(bypass_domains=['api.ipify.org']),dict(routing_excluded_ips=['192.168.1.2/32']),dict(sections=[dict(enabled=True,policy='direct')])]:
            self.assertFalse(uniform_proxy_expected(dict(mode='global',**changed)))
    def baseline(self):return dict(status='done',checked=100,generation='g',direct_ipv4_sha256=fingerprint('8.8.8.8'),proxy_ipv4_sha256=fingerprint('1.1.1.1'))
    def test_direct_browser_and_rtc_confirm_global_leak(self):
        r=compare_client(dict(ipv4='8.8.8.8',webrtc=['8.8.8.8'],stun=True),self.baseline(),'global','g',101)
        self.assertTrue(r['has_confirmed_leak']);self.assertNotIn('8.8.8.8',str(r))
    def test_rules_direct_is_not_reported_as_confirmed_leak(self):
        r=compare_client(dict(ipv4='8.8.8.8'),self.baseline(),'rules','g',101)
        self.assertFalse(r['has_confirmed_leak']);self.assertEqual(r['checks'][0]['state'],'direct')
    def test_missing_family_and_rtc_do_not_pass(self):
        r=compare_client({},self.baseline(),'global','g',101)
        self.assertTrue(all(x['state'] in ('unknown','unchecked') for x in r['checks']))
    def test_failed_proxy_measurement_cannot_confirm_a_leak(self):
        baseline=self.baseline();baseline.pop('proxy_ipv4_sha256')
        result=compare_client(dict(ipv4='8.8.8.8',webrtc=['8.8.8.8']),baseline,'global','g',101)
        self.assertFalse(result['has_confirmed_leak'])
        self.assertEqual(result['checks'][0]['state'],'unknown')
    def test_stale_generation_and_changed_exit_are_unknown(self):
        for generation,now in [('new',101),('g',701)]:
            r=compare_client(dict(ipv4='8.8.8.8'),self.baseline(),'global',generation,now)
            self.assertFalse(r['has_confirmed_leak']);self.assertFalse(r['baseline_fresh'])
    def test_same_direct_and_proxy_is_not_protection_proof(self):
        b=self.baseline();b['proxy_ipv4_sha256']=b['direct_ipv4_sha256']
        self.assertEqual(compare_client(dict(ipv4='8.8.8.8'),b,'global','g',101)['checks'][0]['state'],'unknown')
    def test_invalid_observations_are_rejected(self):
        for value in [dict(ipv4='invalid'),dict(webrtc=['invalid']),dict(webrtc=['1.1.1.1']*17),dict(stun='true')]:
            with self.assertRaises(ValueError):compare_client(value,self.baseline(),'global','g',101)
