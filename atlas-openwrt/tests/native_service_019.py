import sys,json,subprocess,time,threading,http.server
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import core,atlas
def rpc(method,args={}):
    value=json.loads(subprocess.check_output(['ubus','call','atlas',method,json.dumps(args)],text=True))
    assert value.get('ok'),value
    return value
def wait():
    for _ in range(100):
        time.sleep(1);value=rpc('status')
        if value.get('job',{}).get('status') in ('done','error'):
            assert value['job']['status']=='done',value['job'];return value
    raise AssertionError('job timeout')
assert rpc('status')['version']=='0.19.0'
rpc('action',{'operation':'stop'});wait()
for iface,peer in [('atesta','atestpa'),('atestb','atestpb')]:
    subprocess.run(['ip','link','del',iface],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['ip','link','add',iface,'type','veth','peer','name',peer],check=True)
    subprocess.run(['ip','addr','add','10.111.1.1/24','dev',iface],check=True)
    subprocess.run(['ip','link','set',iface,'up'],check=True)
    subprocess.run(['ip','link','set',peer,'up'],check=True)
settings=core.defaults()['settings']
settings['sections']=[dict(name=n,policy='proxy',domains=[],cidrs=[],source_ips=[],source_interfaces=[i],outbound_config=[dict(type='selector',tag='pick',outbounds=[n],default=n),dict(type='direct',tag=n)]) for n,i in [('A','atesta'),('B','atestb')]]
try:
    rpc('save_settings',{'settings':settings})
    rpc('config_preview',{'validate':True})
    rpc('action',{'operation':'start'});assert wait()['running']
    diag=rpc('nft_diagnostics'); checks={x['id']:x['ok'] for x in diag['checks']}
    assert checks['fw4'] and checks['atli1'] and checks['atli2'] and checks['atli1-routes'] and checks['atli2-routes'],diag
    print('PASS native procd startup and read-only RPC nft/IPv4/IPv6 diagnostics for exact ingress',flush=True)
    Path('/tmp/arbitrary-atlas-list.txt').write_text('test.example.org\n')
    assert atlas.fetch_rule_list('file:///tmp/arbitrary-atlas-list.txt','domains')[0]==['test.example.org']
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path.startswith('http://example.org/')
            self.send_response(200);self.end_headers();self.wfile.write(b'http.example.org\n')
        def log_message(self,*args):pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=atlas.fetch_rule_list('http://example.org/list.txt','domains','http://127.0.0.1:%d'%server.server_port)
        assert result[0]==['http.example.org'],result
    finally:server.shutdown();server.server_close()
    print('PASS arbitrary local list path and real plaintext HTTP fetch through configured proxy',flush=True)
finally:
    rpc('action',{'operation':'stop'});assert not wait()['running']
    assert subprocess.run(['uci','-q','get','firewall.atlas_ingress'],stdout=subprocess.DEVNULL).returncode!=0
    for iface in ('atesta','atestb'):subprocess.run(['ip','link','del',iface],check=True)
print('PASS native stop removes scoped ingress firewall configuration',flush=True)
