import copy
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import adaptive_routing as a

def connection(**overrides):
    result={'id':'one','metadata':{'host':'media.example.com','network':'tcp','destinationPort':'443','destinationIP':'1.1.1.1'},
            'upload':1200,'download':0,'chains':['direct']}
    for key,value in overrides.items():result[key]=value
    return result

class StalledTests(unittest.TestCase):
    def test_russian_domains_are_never_automatically_probed(self):
        settings={'mode':'rules','sections':[],'remote_lists':[],'bypass_cidrs':[]}
        for host in ('gosuslugi.ru','esia.gosuslugi.ru','nalog.ru','xn--80asehdb.xn--p1ai','SUB.GOSUSLUGI.RU.'):
            with self.subTest(host=host):self.assertFalse(a.may_probe(host,settings))
        for host in ('ru.example.com','notru.example','example.org'):
            with self.subTest(host=host):self.assertTrue(a.may_probe(host,settings))

    def test_first_direct_failure_checks_proxy_without_waiting_for_a_repeat(self):
        settings={'mode':'rules','sections':[],'remote_lists':[],'bypass_cidrs':[]}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'rules.json';called=[]
            worker=a.AdaptiveWorker(path,lambda:settings,lambda h:called.append(h) or True)
            worker.start()
            try:
                worker.queue.put(('rare.example.com','1.1.1.1',False));deadline=time.monotonic()+3
                while time.monotonic()<deadline and not json.loads(path.read_text())['rules']:time.sleep(.05)
                self.assertEqual(called,['rare.example.com'])
                self.assertEqual(json.loads(path.read_text())['rules'],[{'domain':['rare.example.com']}])
            finally:worker.close()

    def test_only_persistent_direct_https_without_received_data_is_considered(self):
        now=[10];observer=a.StalledConnectionObserver(now=lambda:now[0],wait=6)
        snap={'connections':[connection()]}
        self.assertEqual(observer.observe(snap),[])
        now[0]+=5;self.assertEqual(observer.observe(snap),[])
        now[0]+=1;self.assertEqual(observer.observe(snap),[('media.example.com','1.1.1.1')])
        self.assertEqual(observer.observe(snap),[])
        observer.observe({'connections':[]});self.assertEqual(len(observer.pending),0)
        for item in (connection(chains=['proxy']),connection(download=1),connection(upload=0),
                     connection(metadata={'host':'printer.local','network':'tcp','destinationPort':'443'}),
                     connection(metadata={'host':'media.example.com','network':'udp','destinationPort':'443'}),
                     connection(metadata={'host':'media.example.com','network':'tcp','destinationPort':'80'}),
                     connection(metadata={'host':'media.example.com','network':'tcp','destinationPort':'443','destinationIP':'192.168.1.1'}),
                     connection(metadata={'host':'media.example.com','network':'tcp','destinationPort':'443','destinationIP':'2001:4860:4860::8888'})):
            self.assertEqual(observer.observe({'connections':[item]}),[])
        self.assertEqual(observer.pending,{})

    def test_stall_rechecks_direct_and_proxy_and_honours_exclusions(self):
        settings={'mode':'rules','dns_filter':'cloudflare','sections':[],'remote_lists':[],'bypass_cidrs':[]}
        with patch.object(a,'tunnel_dns_a',return_value=['1.1.1.1','8.8.8.8']), \
             patch.object(a,'direct_tls_probe',return_value=False) as direct,patch.object(a,'tunnel_tls_probe',return_value=True) as proxy:
            verify=a.atlas_verifier(lambda:settings,1234,'u','p',require_direct_failure=True)
            self.assertTrue(verify('media.example.com'));self.assertEqual(direct.call_count,2);proxy.assert_called_once()
        with patch.object(a,'tunnel_dns_a',return_value=['1.1.1.1']), \
             patch.object(a,'direct_tls_probe',return_value=True),patch.object(a,'tunnel_tls_probe') as proxy:
            self.assertFalse(a.atlas_verifier(lambda:settings,1234,'u','p',require_direct_failure=True)('media.example.com'))
            proxy.assert_not_called()
        settings['bypass_cidrs']=['1.0.0.0/8']
        with patch.object(a,'tunnel_dns_a',return_value=['1.1.1.1']),patch.object(a,'direct_tls_probe') as direct:
            self.assertFalse(a.atlas_verifier(lambda:settings,1234,'u','p',require_direct_failure=True)('media.example.com'))
            direct.assert_not_called()

    def test_stall_worker_adds_only_a_verified_temporary_rule(self):
        settings={'mode':'rules','sections':[],'remote_lists':[],'bypass_cidrs':[]}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'rules.json';worker=a.AdaptiveWorker(path,lambda:settings,lambda h:False,
                 connection_snapshot=lambda:{'connections':[connection()]},stall_verifier=lambda h:True)
            worker.stalls=a.StalledConnectionObserver(wait=.1);worker.start()
            try:
                deadline=time.monotonic()+7
                while time.monotonic()<deadline and not json.loads(path.read_text())['rules']:time.sleep(.05)
                self.assertEqual(json.loads(path.read_text())['rules'],[{'domain':['media.example.com']}])
            finally:worker.close()

    def test_stall_worker_does_not_probe_explicit_block_or_fakeip_exclusion(self):
        for settings in ({'mode':'rules','sections':[],'remote_lists':[],'blocked_domains':['example.com']},
                         {'mode':'rules','fakeip':True,'sections':[],'remote_lists':[],'bypass_cidrs':['1.0.0.0/8']}):
            with self.subTest(settings=settings),tempfile.TemporaryDirectory() as tmp:
                called=[];worker=a.AdaptiveWorker(Path(tmp)/'rules.json',lambda:settings,lambda h:False,
                    stall_verifier=lambda h:called.append(h) or True)
                worker.start()
                try:
                    worker.queue.put(('media.example.com','198.18.0.1' if settings.get('fakeip') else '1.1.1.1',True));time.sleep(.4)
                    self.assertEqual(called,[]);self.assertEqual(json.loads(worker.path.read_text())['rules'],[])
                finally:worker.close()

    def test_http2_uses_same_resolver_authenticated_proxy_and_no_credentials_in_argv(self):
        query=a.dns_query('example.com',1234)
        answer=struct.pack('!HHHHHH',1234,0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+b'\x01\x01\x01\x01'
        def run(argv,**kwargs):
            cfg=os.read(kwargs['pass_fds'][0],3000).decode();options=dict(line.split(' = ',1) for line in cfg.splitlines() if ' = ' in line)
            self.assertNotIn('private-password',' '.join(argv));self.assertEqual(json.loads(options['proxy']),'http://127.0.0.1:1234')
            self.assertEqual(json.loads(options['connect-to']),'dns.example.com:443:1.1.1.1:443')
            self.assertEqual(json.loads(options['proxy-user']),'user:private-password');self.assertNotIn('insecure',cfg)
            self.assertEqual(json.loads(options['data-binary']),'@-');self.assertEqual(kwargs['input'],query)
            return SimpleNamespace(returncode=0,stdout=answer+b'ATLAS_DOH_META:200:application/dns-message')
        with patch.object(a.os.path,'isfile',return_value=True),patch.object(a.os,'access',return_value=True),patch.object(a.subprocess,'run',side_effect=run):
            body=a.doh_http2(query,1234,'user','private-password','1.1.1.1','dns.example.com','/dns-query',4)
        self.assertEqual(a.dns_public_addresses(body,1234,query),['1.1.1.1'])
        with patch.object(a.subprocess,'run') as run:
            self.assertEqual(a.doh_http2(query,1234,'user','pw','127.0.0.1','dns.example.com','/dns-query',4),b'')
            run.assert_not_called()

if __name__=='__main__':unittest.main()
