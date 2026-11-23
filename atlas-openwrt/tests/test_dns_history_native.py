"""The DNS fallback must not overwrite an unrelated proxy latency result."""
import http.server,json,os,select,socket,socketserver,subprocess,tempfile,threading,time,unittest,urllib.request
from pathlib import Path

class DnsHistoryNative(unittest.TestCase):
 def test_failed_dns_probe_does_not_erase_selected_profile(self):
  binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
  if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine')
  class Target(http.server.BaseHTTPRequestHandler):
   def do_HEAD(self):self.send_response(204);self.end_headers()
   def log_message(self,*args):pass
  profile=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
  dns=http.server.ThreadingHTTPServer(('127.0.0.1',0),Target)
  dns_via_proxy=[False]
  class Proxy(socketserver.StreamRequestHandler):
   def handle(self):
    self.connection.settimeout(3);line=self.rfile.readline(4096)
    for _ in range(32):
     if self.rfile.readline(4096) in (b'\r\n',b'\n',b''):break
    if not line.startswith(b'CONNECT '):return
    try:port=int(line.split()[1].rsplit(b':',1)[1])
    except (ValueError,IndexError):return
    if port==dns.server_port and not dns_via_proxy[0]:return
    if port not in (profile.server_port,dns.server_port):return
    try:
     with socket.create_connection(('127.0.0.1',port),timeout=3) as peer:
      self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n');self.wfile.flush()
      while True:
       ready,_,_=select.select([peer,self.connection],[],[],3)
       if not ready:return
       for src in ready:
        data=src.recv(4096)
        if not data:return
        (self.connection if src is peer else peer).sendall(data)
    except OSError:return
  class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
  proxy=Server(('127.0.0.1',0),Proxy)
  for server in (profile,dns,proxy):threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
   cfg={'log':{'level':'error'},'outbounds':[
    {'type':'http','tag':'favorite','server':'127.0.0.1','server_port':proxy.server_address[1]},
    {'type':'selector','tag':'proxy','outbounds':['favorite'],'default':'favorite'},
    {'type':'urltest','tag':'auto','outbounds':['favorite'],'url':'http://127.0.0.1:%d/profile'%profile.server_port,'interval':'1800s','idle_timeout':'1800s','background':True},
    {'type':'selector','tag':'atlas-dns-proxy','outbounds':['proxy'],'default':'proxy'},
    {'type':'direct','tag':'atlas-dns-direct'},
    {'type':'urltest','tag':'atlas-dns-fallback','outbounds':['atlas-dns-proxy'],'fallbacks':['atlas-dns-direct'],'url':'http://127.0.0.1:%d/dns'%dns.server_port,'interval':'1s','idle_timeout':'1s','background':True}],
    'route':{'final':'proxy'},'experimental':{'clash_api':{'external_controller':'127.0.0.1:%d'%port,'secret':'fixture'}}}
   with tempfile.TemporaryDirectory() as d:
    config=Path(d)/'config.json';config.write_text(json.dumps(cfg));log=open(Path(d)/'log','w+b');proc=subprocess.Popen([binary,'run','-c',str(config)],stdout=log,stderr=log)
    try:
     def proxies():
      req=urllib.request.Request('http://127.0.0.1:%d/proxies'%port,headers={'Authorization':'Bearer fixture'})
      with urllib.request.urlopen(req,timeout=2) as response:return json.load(response)['proxies']
     end=time.monotonic()+20;sample=None
     while time.monotonic()<end:
      try:
       data=proxies();history=data.get('favorite',{}).get('history',[])
       if history and data.get('atlas-dns-fallback',{}).get('now')=='atlas-dns-direct':sample=history[-1]['time'];break
      except (OSError,ValueError):pass
      time.sleep(.2)
     self.assertIsNotNone(sample,'Profile and DNS fallback did not reach expected state')
     end=time.monotonic()+4
     while time.monotonic()<end:
      data=proxies();history=data['favorite']['history']
      self.assertTrue(history,'A failed DNS test erased the profile result')
      self.assertEqual(history[-1]['time'],sample,'A DNS test overwrote the profile result')
      time.sleep(.25)
     dns_via_proxy[0]=True;end=time.monotonic()+15
     while time.monotonic()<end:
      data=proxies();history=data['favorite']['history']
      self.assertTrue(history);self.assertEqual(history[-1]['time'],sample)
      if data['atlas-dns-fallback']['now']=='atlas-dns-proxy':break
      time.sleep(.25)
     else:self.fail('DNS did not return to the proxy after recovery')
    finally:proc.terminate();proc.wait(timeout=10);log.close()
  finally:
   for server in (profile,dns,proxy):server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
