"""Real-engine regression: fresh guarded measurements without URLTest traffic."""
import http.server,json,os,select,socket,socketserver,subprocess,sys,tempfile,threading,time,unittest,urllib.request
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,atlas,engine_features

class BackgroundMeasurements(unittest.TestCase):
    def test_idle_group_keeps_measuring_and_recovers_primary(self):
        binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
        if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine r2')
        self.assertIn('urltest.background',engine_features.capabilities(binary))
        primary_enabled=[True]
        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(.02)
                self.send_response(204);self.send_header('Content-Length','0');self.end_headers()
            def log_message(self,*args):pass
        target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
        class Proxy(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(3)
                first=self.rfile.readline(4096)
                for _ in range(32):
                    if self.rfile.readline(4096) in (b'\r\n',b'\n',b''):break
                if not first.startswith(b'CONNECT ') or (self.server.primary and not primary_enabled[0]):return
                try:
                    with socket.create_connection(('127.0.0.1',target.server_port),timeout=3) as peer:
                        self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush()
                        end=time.monotonic()+5
                        while time.monotonic()<end:
                            ready,_,_=select.select([peer,self.connection],[],[],.1)
                            for source in ready:
                                data=source.recv(4096)
                                if not data:return
                                (self.connection if source is peer else peer).sendall(data)
                except OSError:return
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=True;daemon_threads=True
        primary=Server(('127.0.0.1',0),Proxy);primary.primary=True
        reserve=Server(('127.0.0.1',0),Proxy);reserve.primary=False
        servers=(target,primary,reserve)
        for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            current=core.defaults()
            current['subscriptions']=[dict(id='a'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('http://127.0.0.1:%d#%s'%(server.server_address[1],name)) for server,name in ((primary,'primary'),(reserve,'reserve'))])]
            keys=[n['key'] for n in core.all_nodes(current)]
            current['settings'].update(max_ping_ms=5000,urltest_fallbacks=[keys[1]],urltest_download_check='off')
            with mock.patch.object(engine_features,'capabilities',return_value=engine_features.capabilities(binary)):
                cfg=core.make_config(current,api_secret='a'*64)
            cfg['inbounds']=[];cfg['route'].update(final='proxy',rules=[])
            group=next(x for x in cfg['outbounds'] if x['tag']=='auto')
            group.update(url='http://127.0.0.1:%d/check'%target.server_port,interval='1s',idle_timeout='1s')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            cfg['experimental']['clash_api']['external_controller']='127.0.0.1:%d'%port
            cfg['experimental']['clash_api']['secret']='fixture'
            def proxies():
                request=urllib.request.Request('http://127.0.0.1:%d/proxies'%port,headers={'Authorization':'Bearer fixture'})
                with urllib.request.urlopen(request,timeout=2) as response:return json.load(response)['proxies']
            def wait(predicate):
                end=time.monotonic()+20
                while time.monotonic()<end:
                    try:
                        value=proxies()
                        if predicate(value):return value
                    except (OSError,ValueError):pass
                    time.sleep(.1)
                self.fail('Fresh idle-group measurement did not arrive')
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'config.json';cfg['experimental']['cache_file']['path']=str(Path(directory)/'cache.db')
                for background in (False,True):
                    group['background']=background;path.write_text(json.dumps(cfg),encoding='utf-8')
                    with (Path(directory)/'engine.log').open('wb') as log:
                        process=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log)
                        try:
                            first=wait(lambda p:bool(p.get(keys[0],{}).get('history')))
                            stamp=first[keys[0]]['history'][-1]['time']
                            # No inbound, no group delay request and no traffic through URLTest.
                            time.sleep(3.2)
                            latest=proxies()[keys[0]]['history'][-1]['time']
                            if not background:
                                self.assertEqual(stamp,latest)
                                continue
                            self.assertNotEqual(stamp,latest)
                            self.assertEqual(atlas.auto_choice(core.all_nodes(current),current['settings'],proxies()),keys[0])
                            primary_enabled[0]=False
                            wait(lambda p:atlas.auto_choice(core.all_nodes(current),current['settings'],p)==keys[1])
                            primary_enabled[0]=True
                            wait(lambda p:atlas.auto_choice(core.all_nodes(current),current['settings'],p)==keys[0])
                        finally:
                            process.terminate();process.wait(timeout=10)
            print('NATIVE: idle URLTest unchanged by default; background measurements renewed past idle_timeout, reserve selected on failure, primary restored without URLTest traffic')
        finally:
            for server in servers:server.shutdown();server.server_close()
