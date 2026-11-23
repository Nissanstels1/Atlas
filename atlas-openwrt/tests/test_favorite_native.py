"""Exercise preferred-server failover and recovery against Atlas Engine."""
import http.server,json,os,select,socket,socketserver,subprocess,sys,tempfile,threading,time,unittest,urllib.request
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,core,engine_features

class FavoriteNative(unittest.TestCase):
 def test_favorite_fails_over_and_recovers(self):
  binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
  if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine')
  enabled=[True]
  class Target(http.server.BaseHTTPRequestHandler):
   def do_GET(self):self.send_response(204);self.send_header('Content-Length','0');self.end_headers()
   def log_message(self,*args):pass
  target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
  class Proxy(socketserver.StreamRequestHandler):
   def handle(self):
    self.connection.settimeout(3);first=self.rfile.readline(4096)
    for _ in range(32):
     if self.rfile.readline(4096) in (b'\r\n',b'\n',b''):break
    if not first.startswith(b'CONNECT ') or (self.server.primary and not enabled[0]):return
    try:
     with socket.create_connection(('127.0.0.1',target.server_port),timeout=3) as peer:
      self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush();end=time.monotonic()+5
      while time.monotonic()<end:
       ready,_,_=select.select([peer,self.connection],[],[],.1)
       for source in ready:
        data=source.recv(4096)
        if not data:return
        (self.connection if source is peer else peer).sendall(data)
    except OSError:return
  class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
  first=Server(('127.0.0.1',0),Proxy);first.primary=True
  second=Server(('127.0.0.1',0),Proxy);second.primary=False
  servers=(target,first,second)
  for srv in servers:threading.Thread(target=srv.serve_forever,daemon=True).start()
  try:
   current=core.defaults();current['subscriptions']=[dict(id='a'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('http://127.0.0.1:%d#%s'%(srv.server_address[1],name)) for srv,name in ((first,'favorite'),(second,'backup'))])]
   keys=[n['key'] for n in core.all_nodes(current)];current['settings'].update(favorite_profile=keys[0],auto_interval_seconds=1,auto_tolerance_ms=350)
   with mock.patch.object(engine_features,'capabilities',return_value=engine_features.capabilities(binary)):cfg=core.make_config(current,api_secret='a'*64)
   cfg['inbounds']=[];cfg['route'].update(final='proxy',rules=[])
   group=next(x for x in cfg['outbounds'] if x['tag']=='auto');group.update(url='http://127.0.0.1:%d/check'%target.server_port,interval='1s',idle_timeout='1s')
   with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
   cfg['experimental']['clash_api'].update(external_controller='127.0.0.1:%d'%port,secret='fixture')
   def request(method='GET',path='/proxies',body=None,timeout=2):
    if '/delay?' in path:
     if not enabled[0]:raise atlas.AtlasError('Локальный API вернул HTTP 503')
     return {'delay':50}
    data=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request('http://127.0.0.1:%d%s'%(port,path),method=method,data=data,headers={'Authorization':'Bearer fixture','Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=timeout) as response:
     raw=response.read();return json.loads(raw) if raw else {}
   with tempfile.TemporaryDirectory() as directory:
    root=Path(directory);p=root/'config.json';cfg['experimental']['cache_file']['path']=str(root/'cache.db');p.write_text(json.dumps(cfg))
    with (root/'engine.log').open('wb') as log:
     process=subprocess.Popen([binary,'run','-c',str(p)],stdout=log,stderr=log)
     try:
      def wait(predicate):
       deadline=time.monotonic()+25
       while time.monotonic()<deadline:
        try:
         proxies=request().get('proxies',{})
         if predicate(proxies):return
        except (OSError,ValueError):pass
        time.sleep(.2)
       self.fail('Engine did not reach the expected state')
      wait(lambda p:all(p.get(k,{}).get('history') for k in keys))
      with mock.patch.object(atlas,'RUN',root),mock.patch.object(atlas,'CONFIG',p),mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=request):
       self.assertEqual(atlas.automatic_select(current)['selected'],keys[0]);enabled[0]=False
       wait(lambda p:not p.get(keys[0],{}).get('history') and bool(p.get(keys[1],{}).get('history')))
       self.assertEqual(atlas.automatic_select(current)['selected'],keys[1]);enabled[0]=True
       wait(lambda p:bool(p.get(keys[0],{}).get('history')))
       self.assertEqual(atlas.automatic_select(current)['selected'],keys[0])
     finally:process.terminate();process.wait(timeout=10)
  finally:
   for srv in servers:srv.shutdown();srv.server_close()

if __name__=='__main__':unittest.main()
