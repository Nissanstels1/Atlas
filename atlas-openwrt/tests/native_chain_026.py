"""Loopback-only end-to-end cross-section detour on installed OpenWrt."""
import base64,json,select,socket,socketserver,struct,subprocess,sys,tempfile,threading,time
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import core,atlas
hits=[]
def connect(host,port):
    assert host=='127.0.0.1',host
    return socket.create_connection((host,port),timeout=10)
def relay(left,right):
    until=time.monotonic()+30
    while time.monotonic()<until:
        ready,_,_=select.select([left,right],[],[],1)
        for source in ready:
            data=source.recv(65536)
            if not data:return
            (right if source is left else left).sendall(data)
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
class Sink(socketserver.StreamRequestHandler):
    def handle(self):
        assert self.rfile.readline().startswith(b'GET ')
        while self.rfile.readline().strip():pass
        hits.append('target')
        body=b'atlas-chain-fixture'
        self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
class Http(socketserver.StreamRequestHandler):
    def handle(self):
        command,address,_=self.rfile.readline().decode().split()
        assert command=='CONNECT',command
        while self.rfile.readline().strip():pass
        host,port=address.rsplit(':',1)
        with connect(host,int(port)) as upstream:
            hits.append('http');self.connection.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n');relay(self.connection,upstream)
class Socks(socketserver.StreamRequestHandler):
    def handle(self):
        version,count=self.rfile.read(2);assert version==5
        assert 0 in self.rfile.read(count)
        self.connection.sendall(b'\x05\x00')
        version,command,_,kind=self.rfile.read(4);assert version==5 and command==1
        if kind==1:host=socket.inet_ntoa(self.rfile.read(4))
        elif kind==3:host=self.rfile.read(self.rfile.read(1)[0]).decode()
        else:raise AssertionError('Unexpected address family')
        port=struct.unpack('!H',self.rfile.read(2))[0]
        with connect(host,port) as upstream:
            hits.append('socks');self.connection.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00');relay(self.connection,upstream)
servers=[Server(('127.0.0.1',0),kind) for kind in (Sink,Http,Socks)]
for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
with socket.socket() as probe:probe.bind(('127.0.0.1',0));mixed_port=probe.getsockname()[1]
current=core.defaults()
def section(name,sid,outbound):
    return dict(name=name,id=sid,policy='proxy',domains=[name.lower()+'.example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='',outbound_config=[outbound])
first=section('HTTP','c'*16,dict(type='http',tag='entry',server='127.0.0.1',server_port=servers[1].server_address[1],detour='section_'+'d'*16+'_relay'))
first['mixed_proxy']=dict(enabled=True,listen='127.0.0.1',port=mixed_port,username='fixture',password='fixture-only-password')
current['settings']['sections']=[first,section('SOCKS','d'*16,dict(type='socks',tag='relay',server='127.0.0.1',server_port=servers[2].server_address[1]))]
process=None
try:
    with tempfile.TemporaryDirectory() as directory:
        cfg=core.make_config(current)
        # Keep the production section input/rule, but avoid creating a test TUN.
        cfg['inbounds']=[x for x in cfg['inbounds'] if x['type']!='tun']
        cfg['experimental']['cache_file']['enabled']=False
        path=Path(directory)/'config.json';path.write_text(json.dumps(cfg))
        atlas.check(json.loads(path.read_text()))
        with open(Path(directory)/'engine.log','wb') as log:
            process=subprocess.Popen([atlas.BINARY,'run','-c',str(path)],stdout=log,stderr=log)
            for _ in range(180):
                if process.poll() is not None:raise AssertionError('Engine exited: '+(Path(directory)/'engine.log').read_text())
                try:client=socket.create_connection(('127.0.0.1',mixed_port),timeout=2);break
                except OSError:time.sleep(.2)
            else:raise AssertionError('Mixed input not ready: '+(Path(directory)/'engine.log').read_text())
            with client:
                auth=base64.b64encode(b'fixture:fixture-only-password')
                client.sendall(b'GET http://127.0.0.1:'+str(servers[0].server_address[1]).encode()+b'/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic '+auth+b'\r\nConnection: close\r\n\r\n')
                client.settimeout(20);response=b''
                while b'atlas-chain-fixture' not in response:
                    data=client.recv(65536)
                    if not data:break
                    response+=data
            assert b'atlas-chain-fixture' in response,response
            assert hits==['socks','http','target'],hits
            print(json.dumps(dict(version=atlas.VERSION,cross_section_http_over_socks_transfer=True,hops=hits,external_network=False)))
finally:
    if process is not None:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    for server in servers:server.shutdown();server.server_close()
