import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import json
import struct
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from adaptive_routing import (AdaptivePolicy, AdaptiveWorker, FailureObserver, failed_hostname, tunnel_tls_probe, dns_query,
                              dns_public_addresses, may_probe, public_not_excluded)


def error(host, outbound='direct', port=443):
    return ('ERROR [16 2s] connection: open connection to %s:%s using '
            'outbound/%s[%s]: dial tcp: connection refused' % (host,port,outbound,outbound))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.t = 10
        self.policy = AdaptivePolicy(direct_exclusions=['bank.example.com'], now=lambda: self.t,
                                     ttl=60, cooldown=10, max_probes=2)
        self.probed = []

    def good(self, host):
        self.probed.append(host)
        return True

    def test_only_direct_https_errors_with_host(self):
        self.assertEqual(failed_hostname(error('MEDIA.Example.COM')), 'media.example.com')
        for raw in [error('example.com','proxy'),error('example.com',port=80),error('127.0.0.1'),
                    error('printer.lan'),error('router.local'),error('example.onion'), 'unexpected']:
            self.assertIsNone(failed_hostname(raw),raw)

    def test_sniffed_domain_correlates_with_public_ip_only_for_same_connection(self):
        now=[10];obs=FailureObserver(lambda:{'fakeip':False},now=lambda:now[0])
        sniff=lambda n:'DEBUG [%s 2ms] router: sniffed protocol: tls, domain: media.example.com'%n
        failure=lambda n,ip:'ERROR [%s 4ms] connection: open connection to %s:443 using outbound/direct[direct]: refused'%(n,ip)
        self.assertIsNone(obs.event(sniff(7)))
        self.assertIsNone(obs.event(failure(8,'1.1.1.1')))
        self.assertEqual(obs.event(failure(7,'1.1.1.1')),('media.example.com','1.1.1.1'))
        obs.event(sniff(9));self.assertIsNone(obs.event(failure(9,'127.0.0.1')))
        obs.event(sniff(10));self.assertIsNone(obs.event(failure(10,'198.18.0.1')))
        obs.event(sniff(11));now[0]+=31;self.assertIsNone(obs.event(failure(11,'1.1.1.1')))
        fake=FailureObserver(lambda:{'fakeip':True});fake.event(sniff(12))
        self.assertEqual(fake.event(failure(12,'198.18.0.1')),('media.example.com','198.18.0.1'))

    def test_transient_names_expire_even_when_no_new_events_arrive(self):
        now=[10];obs=FailureObserver(lambda:{'fakeip':False},now=lambda:now[0])
        obs.event('DEBUG [7 2ms] router: sniffed protocol: tls, domain: media.example.com')
        self.assertEqual(len(obs.names),1);now[0]+=31;obs.prune();self.assertEqual(len(obs.names),0)
        p=AdaptivePolicy(now=lambda:now[0]);p.observe(error('example.com'),lambda h:True)
        now[0]+=31;p.expire();self.assertEqual(p.failures,{})

    def test_two_failures_then_verified_exact_domain_and_expiry(self):
        self.assertIsNone(self.policy.observe(error('cdn.example.com'),self.good))
        self.assertEqual(self.policy.observe(error('cdn.example.com'),self.good),'cdn.example.com')
        self.assertEqual(self.policy.rules()['rules'],[{'domain':['cdn.example.com']}])
        self.assertEqual(self.probed,['cdn.example.com'])
        self.t += 61
        self.assertEqual(self.policy.rules()['rules'],[])

    def test_explicit_exclusions_never_probed(self):
        for _ in range(4):self.policy.observe(error('secure.bank.example.com'),self.good)
        self.assertEqual(self.probed,[])
        self.assertEqual(self.policy.rules()['rules'],[])

    def test_tunnel_failure_and_exception_never_add_rule(self):
        self.policy.observe(error('broken.example.com'),lambda h:False)
        self.policy.observe(error('broken.example.com'),lambda h:False)
        self.assertEqual(self.policy.rules()['rules'],[])
        self.t += 11
        def fail(host):raise OSError('failure')
        self.policy.observe(error('broken.example.com'),fail)
        self.assertEqual(self.policy.rules()['rules'],[])

    def test_probe_budget_limits_cost(self):
        for host in ['a.example.com','b.example.com','c.example.com']:
            self.policy.observe(error(host),self.good)
            self.policy.observe(error(host),self.good)
        self.assertEqual(len(self.probed),2)
        self.t += 61
        self.policy.observe(error('c.example.com'),self.good)
        self.policy.observe(error('c.example.com'),self.good)
        self.assertEqual(len(self.probed),3)

    def test_atomic_rules_file_does_not_overwrite_other_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'adaptive.json'
            self.policy.observe(error('a.example.com'),self.good)
            self.policy.observe(error('a.example.com'),self.good)
            self.policy.write_rules(p)
            self.assertEqual(json.loads(p.read_text())['rules'],[{'domain':['a.example.com']}])

    def test_probe_rejects_internal_addresses_before_connecting(self):
        with patch('adaptive_routing.socket.create_connection') as connect:
            for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','198.18.0.1']:
                self.assertFalse(tunnel_tls_probe('example.com',ip,8080,'u','p'))
            connect.assert_not_called()

    def test_probe_requires_certificate_checking(self):
        import ssl
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname=False
        ctx.verify_mode=ssl.CERT_NONE
        with patch('adaptive_routing.socket.create_connection') as connect:
            self.assertFalse(tunnel_tls_probe('example.com','1.1.1.1',8080,'u','p',context=ctx))
            connect.assert_not_called()

    def test_dns_accepts_only_well_formed_public_answers(self):
        q=dns_query('example.com',1234)
        answer=lambda data:struct.pack('!HHHHHH',1234,0x8180,1,1,0,0)+q[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+data
        self.assertEqual(dns_public_addresses(answer(b'\x01\x01\x01\x01'),1234,q),['1.1.1.1'])
        with self.assertRaises(ValueError):dns_public_addresses(answer(b'\x7f\x00\x00\x01'),1234,q)
        with self.assertRaises(ValueError):dns_public_addresses(answer(b'\x01\x01\x01\x01')[:-1],1234,q)
        with self.assertRaises(ValueError):dns_public_addresses(answer(b'\x01\x01\x01\x01'),1235,q)

    def test_uncertain_explicit_rules_fail_closed(self):
        settings={'mode':'rules','bypass_domains':['bank.example.com'],'sections':[], 'remote_lists':[]}
        self.assertFalse(may_probe('pay.bank.example.com',settings))
        self.assertTrue(may_probe('another.example.com',settings))
        self.assertFalse(may_probe('another.example.com',dict(settings,routing_excluded_ips=['192.168.1.2/32'])))
        direct={'enabled':True,'policy':'direct','domains':['shop.example.com'],'connection_rules':[]}
        self.assertFalse(may_probe('cdn.shop.example.com',dict(settings,sections=[direct])))
        unknown=dict(direct,source_ips=['192.168.1.2/32'])
        self.assertFalse(may_probe('another.example.com',dict(settings,sections=[unknown])))
        dynamic={'enabled':True,'policy':'direct'}
        self.assertFalse(may_probe('another.example.com',dict(settings,remote_lists=[dynamic])))
        assigned=dict(dynamic,policy='proxy',section='fixed');direct['id']='fixed'
        self.assertFalse(may_probe('another.example.com',dict(settings,sections=[direct],remote_lists=[assigned])))

    def test_bypass_subnet_is_not_probed(self):
        self.assertFalse(public_not_excluded(['1.1.1.1'],['1.0.0.0/8']))
        self.assertTrue(public_not_excluded(['1.1.1.1'],['8.0.0.0/8']))
        self.assertFalse(public_not_excluded(['10.0.0.1'],[]))
        self.assertFalse(public_not_excluded([],[]))

    def test_worker_rechecks_exclusions_after_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings={'mode':'rules','bypass_domains':[],'sections':[],'remote_lists':[]}
            def verify(host):
                settings['bypass_domains'].append(host)
                return True
            path=Path(tmp)/'adaptive.json';worker=AdaptiveWorker(path,lambda:settings,verify)
            worker.start()
            try:
                worker.offer(error('change.example.com'));worker.offer(error('change.example.com'))
                deadline=time.monotonic()+2
                while not settings['bypass_domains'] and time.monotonic()<deadline:time.sleep(.01)
                self.assertEqual(settings['bypass_domains'],['change.example.com'])
                self.assertEqual(json.loads(path.read_text())['rules'],[])
            finally:worker.close()

    def test_worker_removes_suppressed_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings={'mode':'rules','sections':[],'remote_lists':[]};blocked=set()
            path=Path(tmp)/'adaptive.json';worker=AdaptiveWorker(path,lambda:settings,lambda h:True,suppressed=lambda:blocked)
            worker.start()
            try:
                worker.offer(error('gone.example.com'));worker.offer(error('gone.example.com'))
                deadline=time.monotonic()+2
                while not json.loads(path.read_text())['rules'] and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(json.loads(path.read_text())['rules'])
                blocked.add('gone.example.com');deadline=time.monotonic()+3
                while json.loads(path.read_text())['rules'] and time.monotonic()<deadline:time.sleep(.01)
                self.assertEqual(json.loads(path.read_text())['rules'],[])
            finally:worker.close()

    def test_worker_wont_probe_when_fakeip_could_bypass_ip_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings={'mode':'rules','fakeip':True,'bypass_cidrs':['1.0.0.0/8'],'sections':[],'remote_lists':[]};called=[]
            worker=AdaptiveWorker(Path(tmp)/'adaptive.json',lambda:settings,lambda h:called.append(h) or True)
            worker.start()
            try:
                for identity in (1,2):
                    worker.offer('DEBUG [%s 1ms] router: sniffed protocol: tls, domain: media.example.com'%identity)
                    worker.offer('ERROR [%s 2ms] connection: open connection to 198.18.0.1:443 using outbound/direct[direct]: refused'%identity)
                time.sleep(.5)
                self.assertEqual(called,[])
            finally:worker.close()


if __name__ == '__main__':unittest.main()
