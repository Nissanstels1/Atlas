"""Actual authenticated API, TLS validation and guarded selector transfer proof."""
import http.server,json,os,select,socket,socketserver,ssl,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,atlas,engine_features

class NativeDownload(unittest.TestCase):
    def test_tls_transfer_failure_skips_primary_before_actual_selector_switch(self):
        binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
        if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine r3')
        self.assertIn('clash.download_test',engine_features.capabilities(binary))
        servers=[];process=None
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cert=root/'cert.pem';keyfile=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture.test','-addext','subjectAltName=DNS:fixture.test','-keyout',str(keyfile),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Target(http.server.BaseHTTPRequestHandler):
                def do_HEAD(self):
                    time.sleep(.02);self.send_response(204);self.end_headers()
                def do_GET(self):
                    body=b'x'*(16384 if self.server.partial or self.path=='/stall' else 65536)
                    self.send_response(200);self.send_header('Content-Length','65536');self.end_headers()
                    self.wfile.write(body);self.wfile.flush()
                    if self.path=='/stall':time.sleep(2)
                    self.close_connection=True
                def log_message(self,*args):pass
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,keyfile)
            for partial in (True,False):
                server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target);server.partial=partial
                server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
            targets=list(servers)
            class Proxy(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(3)
                    first=self.rfile.readline(4096)
                    for _ in range(32):
                        if self.rfile.readline(4096) in (b'\r\n',b'\n',b''):break
                    if not first.startswith(b'CONNECT '):return
                    try:
                        with socket.create_connection(('127.0.0.1',self.server.target.server_port),timeout=3) as peer:
                            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush()
                            end=time.monotonic()+8
                            while time.monotonic()<end:
                                ready,_,_=select.select([peer,self.connection],[],[],.1)
                                for source in ready:
                                    data=source.recv(4096)
                                    if not data:return
                                    (self.connection if source is peer else peer).sendall(data)
                    except OSError:return
            class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
            proxies=[]
            for target in targets:
                server=Server(('127.0.0.1',0),Proxy);server.target=target;servers.append(server);proxies.append(server)
            for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                current=core.defaults()
                current['subscriptions']=[dict(id='a'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('http://127.0.0.1:%d#fixture%d'%(server.server_address[1],i)) for i,server in enumerate(proxies)])]
                keys=[n['key'] for n in core.all_nodes(current)]
                current['settings'].update(max_ping_ms=5000,urltest_fallbacks=[keys[1]],urltest_download_check='custom',urltest_download_url='https://fixture.test/data',urltest_url='https://fixture.test/check')
                with mock.patch.object(engine_features,'capabilities',return_value=engine_features.capabilities(binary)):
                    cfg=core.make_config(current,api_secret='a'*64)
                cfg['inbounds']=[];cfg['route'].update(final='proxy',rules=[])
                cfg['certificate']={'certificate_path':[str(cert)]}
                cfg['experimental']['cache_file']['path']=str(root/'cache.db')
                path=root/'config.json';path.write_text(json.dumps(cfg))
                with (root/'engine.log').open('wb') as log,mock.patch.object(atlas,'CONFIG',path),mock.patch.object(atlas,'RUN',root),mock.patch.object(atlas,'service_running',return_value=True):
                    process=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log)
                    end=time.monotonic()+20
                    while time.monotonic()<end:
                        try:
                            observed=atlas.clash_request()['proxies']
                            if all(observed.get(k,{}).get('history') for k in keys):break
                        except (OSError,core.AtlasError):pass
                        time.sleep(.1)
                    else:self.fail((root/'engine.log').read_text())
                    failed=atlas.clash_request('GET','/proxies/'+keys[0]+'/download?url=https%3A%2F%2Ffixture.test%2Fdata&timeout=5000',timeout=6)
                    self.assertFalse(failed['ok']);self.assertEqual(failed['received'],16384)
                    result=atlas.automatic_select(current)
                    self.assertEqual(result['selected'],keys[1]);self.assertEqual(atlas.clash_request()['proxies']['proxy']['now'],keys[1])
                    wrong=atlas.clash_request('GET','/proxies/'+keys[1]+'/download?url=https%3A%2F%2Fwrong.test%2Fdata&timeout=5000',timeout=6)
                    self.assertFalse(wrong['ok']);self.assertEqual(wrong['received'],0)
                    started=time.monotonic()
                    stalled=atlas.clash_request('GET','/proxies/'+keys[1]+'/download?url=https%3A%2F%2Ffixture.test%2Fstall&timeout=1000',timeout=3)
                    self.assertFalse(stalled['ok']);self.assertLess(time.monotonic()-started,2)
                    for name,url in [('auto','https%3A%2F%2Ffixture.test%2Fdata'),(keys[1],'http%3A%2F%2Ffixture.test%2Fdata')]:
                        with self.assertRaises(core.AtlasError):atlas.clash_request('GET','/proxies/'+name+'/download?url='+url+'&timeout=5000')
                print('NATIVE: HTTPS certificate validated; 16 KiB truncation rejected; 64 KiB reserve passed before real selector switch; wrong hostname, groups and HTTP URLs rejected')
            finally:
                if process is not None:process.terminate();process.wait(timeout=10)
                for server in servers:server.shutdown();server.server_close()
