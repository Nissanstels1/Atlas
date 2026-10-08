"""Native engine routing and API control, localhost fixtures only."""
import base64
import http.client
import json
import os
from pathlib import Path
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from test_loopback import Fixture, free_port, core


@unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'), 'Set ATLAS_TEST_ENGINE')
class EngineControls(unittest.TestCase):
    def test_scoped_exclusions_with_dns_fakeip_and_assigned_list_schema(self):
        state=core.defaults();state['settings']['fakeip']=True
        state['settings']['sections']=[dict(name='schema',policy='proxy',domains=['example.org'],cidrs=[],source_ips=[],resolver='udp://1.1.1.1',exclude_domains=['skip.example.org'],exclude_cidrs=['8.8.8.8/32'],exclude_source_ips=['192.168.1.25/32'],outbound_config={'type':'direct'})]
        state['settings']=core.validate_settings(state['settings']);sid=state['settings']['sections'][0]['id']
        state['settings']['remote_lists']=[dict(name='assigned',url='https://example.org/list.txt',format='domains',enabled=True,policy='proxy',section=sid,domains=['listed.example.org'])]
        cfg=core.make_config(state,tun=False,api_secret='a'*64)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';path.write_text(json.dumps(cfg),encoding='utf-8')
            check=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(path)],capture_output=True)
            self.assertEqual(check.returncode,0,check.stderr.decode(errors='replace'))

    def test_list_fetch_manual_switch_and_udp_schema(self):
        servers=[];process=None
        with tempfile.TemporaryDirectory() as directory:
            try:
                for marker in (b'A',b'B'):
                    server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Fixture)
                    server.daemon_threads=True;server.marker=marker;server.requests=0
                    threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
                state=core.defaults();state['settings'].update(bootstrap_dns_type='udp',fetch_lists_via_proxy=True)
                state['settings']['sections']=[dict(name='controls',policy='proxy',domains=[],cidrs=[],source_ips=[],
                    outbound_config=[dict(type='selector',tag='select',outbounds=['one','two'],default='one')]+[
                        dict(type='http',tag=tag,server='127.0.0.1',server_port=server.server_address[1]) for tag,server in zip(('one','two'),servers)])]
                state['settings']=core.validate_settings(state['settings']);sid=state['settings']['sections'][0]['id']
                state['settings']['sections'][0].update(domains=['example.invalid'],exclude_domains=['skip.example.invalid'])
                state['settings']['sections'].append(dict(name='fallback',policy='proxy',domains=['skip.example.invalid'],cidrs=[],source_ips=[],outbound_config=[dict(type='http',tag='fallback',server='127.0.0.1',server_port=servers[1].server_address[1])]))
                state['settings']['fetch_lists_section']=sid
                state['settings']['remote_lists']=[dict(name='list',url='https://example.org/list',format='domains',policy='proxy',enabled=True,section=sid,domains=['example.invalid'])]
                cfg=core.make_config(state,api_secret='a'*64)
                inbound=free_port();api=free_port()
                cfg['inbounds'][0]=dict(type='mixed',tag='local',listen='127.0.0.1',listen_port=inbound)
                cfg['experimental']['cache_file']={'enabled':False}
                cfg['experimental']['clash_api']['external_controller']='127.0.0.1:'+str(api)
                cfg['route']['final']='policy-block'
                path=Path(directory)/'config.json';path.write_text(json.dumps(cfg),encoding='utf-8')
                check=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(path)],capture_output=True)
                self.assertEqual(check.returncode,0,check.stderr.decode(errors='replace'))
                with (Path(directory)/'engine.log').open('wb') as log:
                    process=subprocess.Popen([os.environ['ATLAS_TEST_ENGINE'],'run','-c',str(path)],stdout=log,stderr=log)
                    for _ in range(60):
                        try:
                            connection=http.client.HTTPConnection('127.0.0.1',api,timeout=.2)
                            connection.request('GET','/proxies',headers={'Authorization':'Bearer '+'a'*64})
                            response=connection.getresponse();response.read();connection.close()
                            if response.status==200:break
                        except OSError:time.sleep(.1)
                    else:self.fail('API did not start')
                    def fetch(port,auth=None,domain='example.invalid'):
                        c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
                        try:
                            c.request('GET','http://'+domain+'/list',headers={'Proxy-Authorization':auth} if auth else {})
                            r=c.getresponse();self.assertEqual(r.status,200);return r.read()
                        finally:c.close()
                    self.assertEqual(fetch(inbound),b'A')
                    self.assertEqual(fetch(inbound,domain='skip.example.invalid'),b'B')
                    fetch_in=next(x for x in cfg['inbounds'] if x['tag']=='list-fetch');user=fetch_in['users'][0]
                    auth='Basic '+base64.b64encode((user['username']+':'+user['password']).encode()).decode()
                    self.assertEqual(fetch(fetch_in['listen_port'],auth),b'A')
                    c=http.client.HTTPConnection('127.0.0.1',api,timeout=3)
                    c.request('PUT','/proxies/section_'+sid+'_select',body=json.dumps({'name':'section_'+sid+'_two'}),headers={'Authorization':'Bearer '+'a'*64,'Content-Type':'application/json'})
                    r=c.getresponse();self.assertEqual(r.status,204);r.read();c.close()
                    self.assertEqual(fetch(inbound),b'B');self.assertEqual(fetch(fetch_in['listen_port'],auth),b'B')
            finally:
                if process and process.poll() is None:process.terminate();process.wait(timeout=5)
                for server in servers:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
