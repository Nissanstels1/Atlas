"""Controlled engine integration: URI, 64 KiB transfer and ordered reserves."""
import http.server,json,os,select,socket,socketserver,subprocess,sys,tempfile,threading,time,urllib.request
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
os.environ['ATLAS_ENGINE_BINARY']='/tmp/atlas-extended-engine'
import core,engine_features
binary=os.environ['ATLAS_ENGINE_BINARY']
downloads=[];primary_enabled=[True]
class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data=b'x'*65536 if self.path=='/download' else b''
        self.send_response(200 if data else 204);self.send_header('Content-Length',str(len(data)));self.end_headers()
        self.wfile.write(data)
        if data:downloads.append(len(data))
    def log_message(self,*args):pass
class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        first=self.rfile.readline(4096)
        while self.rfile.readline(4096) not in (b'\r\n',b'\n',b''):pass
        if self.server.primary and not primary_enabled[0]:return
        if not first.startswith(b'CONNECT '):return
        with socket.create_connection(('127.0.0.1',target.server_port),timeout=5) as peer:
            self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush()
            while True:
                if self.server.primary and not primary_enabled[0]:return
                ready,_,_=select.select([peer,self.connection],[],[],.2)
                if not ready:continue
                for source in ready:
                    try:data=source.recv(65536)
                    except OSError:return
                    if not data:return
                    (self.connection if source is peer else peer).sendall(data)
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
primary=Server(('127.0.0.1',0),Proxy);primary.primary=True
reserve=Server(('127.0.0.1',0),Proxy);reserve.primary=False
for server in (target,primary,reserve):threading.Thread(target=server.serve_forever,daemon=True).start()
process=None
try:
    features=engine_features.capabilities(binary)
    assert all(x in features for x in ('urltest.fallbacks','urltest.download_url','tools.decode-link'))
    uri='vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=tls&path=%2Ffixture&mode=packet-up&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A8%7D%7D#fixture'
    decoded=core.uri_node(uri);assert decoded['outbound']['transport']['type']=='xhttp'
    trojan=core.uri_node('trojan://fixture@example.com:443?type=splithttp&security=tls&path=%2Ffixture');assert trojan['outbound']['transport']['type']=='xhttp'
    current=core.defaults();current['settings']['mode']='rules'
    nodes=[core.uri_node('http://127.0.0.1:%d#%s'%(port,name)) for port,name in [(primary.server_address[1],'primary'),(9,'dead-reserve'),(reserve.server_address[1],'live-reserve')]]
    current['subscriptions']=[dict(id='a'*16,name='fixture',source='local',enabled=True,nodes=nodes)]
    keys=[x['key'] for x in core.all_nodes(current)]
    current['settings'].update(urltest_fallbacks=keys[1:],urltest_download_check='custom',urltest_download_url='https://example.com/download')
    cfg=core.make_config(current)
    with tempfile.TemporaryDirectory(prefix='atlas-ext-') as tmp:
        root=Path(tmp);path=root/'config.json'
        # Verify full production schema including TUN before isolating traffic.
        path.write_text(json.dumps(cfg));check=subprocess.run([binary,'check','-c',str(path)],capture_output=True,text=True);assert check.returncode==0,check.stderr
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));api_port=sock.getsockname()[1]
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));mixed_port=sock.getsockname()[1]
        cfg['inbounds']=[dict(type='mixed',tag='fixture',listen='127.0.0.1',listen_port=mixed_port)];cfg['experimental']['clash_api']=dict(external_controller='127.0.0.1:%d'%api_port,secret='fixture')
        cfg['route']=dict(cfg['route'],final='proxy',rules=[])
        cfg['experimental']['cache_file'].update(path=str(root/'cache.db'))
        cfg['log']['level']='error'
        group=next(x for x in cfg['outbounds'] if x['tag']=='auto');group.update(url='http://127.0.0.1:%d/check'%target.server_port,download_url='http://127.0.0.1:%d/download'%target.server_port,interval='1s')
        path.write_text(json.dumps(cfg))
        with (root/'engine.log').open('wb') as log:
            process=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log)
            def selected():
                req=urllib.request.Request('http://127.0.0.1:%d/proxies/auto'%api_port,headers={'Authorization':'Bearer fixture'})
                return json.load(urllib.request.urlopen(req,timeout=3))['now']
            def wait(key):
                end=time.monotonic()+60
                while time.monotonic()<end:
                    try:
                        import http.client
                        client=http.client.HTTPConnection('127.0.0.1',mixed_port,timeout=2)
                        client.request('GET','http://127.0.0.1:%d/check'%target.server_port);response=client.getresponse();response.read();client.close()
                    except OSError:pass
                    try:
                        if selected()==key:return
                    except OSError:pass
                    if process.poll() is not None:raise AssertionError((root/'engine.log').read_text())
                    time.sleep(.3)
                raise AssertionError('URLTest selection timeout '+key)
            wait(keys[0]);assert downloads and 65536 in downloads
            primary_enabled[0]=False;wait(keys[2])
            primary_enabled[0]=True;wait(keys[0])
            process.terminate();process.wait(timeout=15);process=None
    report=dict(version='0.27.0',engine_features=features,full_tun_schema_checked=True,xhttp_uri_decoded=True,splithttp_uri_decoded=True,download_65536_bytes_observed=True,ordered_dead_then_live_reserve=True,primary_return_after_recovery=True,scope='local HTTP fixtures and URI/schema checks; no external XHTTP server or physical router')
    Path('/tmp/atlas-extensions-027.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
finally:
    if process is not None and process.poll() is None:process.terminate();process.wait(timeout=15)
    for server in (target,primary,reserve):server.shutdown();server.server_close()
