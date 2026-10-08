import sys,json,subprocess,time,socket,struct
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import core
import atlas
subprocess.run(['/etc/init.d/atlas','stop'],check=True)
for iface,peer in [('atesta','atestpa'),('atestb','atestpb')]:
    subprocess.run(['ip','link','del',iface],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['ip','link','add',iface,'type','veth','peer','name',peer],check=True)
    subprocess.run(['ip','addr','add','10.111.1.1/24','dev',iface],check=True)
    subprocess.run(['ip','link','set',iface,'up'],check=True)
    subprocess.run(['ip','link','set',peer,'up'],check=True)
s=core.defaults();s['settings']['log_level']='debug'
s['settings']['sections']=[dict(name=n,policy='proxy',domains=[],cidrs=[],source_ips=[],source_interfaces=[i],outbound_config=[dict(type='selector',tag='pick',outbounds=[n],default=n),dict(type='direct',tag=n)]) for n,i in [('A','atesta'),('B','atestb')]]
cfg=core.make_config(s);cfg['experimental']['cache_file']['path']='/tmp/ingress019.db'
Path('/tmp/ingress019.json').write_text(json.dumps(cfg))
subprocess.run(['sing-box','check','-c','/tmp/ingress019.json'],check=True)
atlas.manage_ingress_firewall(True)
with open('/tmp/ingress019.log','w') as log:
    process=subprocess.Popen(['sing-box','run','-c','/tmp/ingress019.json'],stdout=log,stderr=log)
    try:
        time.sleep(12)
        assert process.poll() is None,Path('/tmp/ingress019.log').read_text()
        print('PASS multiple exact-interface TUNs start',flush=True)
        def checksum(data):
            words=struct.unpack('!%dH'%(len(data)//2),data);total=sum(words)
            while total>>16:total=(total&65535)+(total>>16)
            return (~total)&65535
        for iface,peer in [('atesta','atestpa'),('atestb','atestpb')]:
            mac=lambda dev:bytes.fromhex(Path('/sys/class/net/'+dev+'/address').read_text().strip().replace(':',''))
            udp=struct.pack('!HHHH',40111,40112,12,0)+b'test'
            ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),123,0,64,17,0,socket.inet_aton('10.111.1.2'),socket.inet_aton('203.0.113.7'))
            ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
            with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sender:
                sender.bind((peer,0));sender.send(mac(iface)+mac(peer)+b'\x08\x00'+ip+udp)
        time.sleep(6)
        content=Path('/tmp/ingress019.log').read_text()
        ids=[core.validate_settings(s['settings'])['sections'][i]['id'] for i in (0,1)]
        assert all('section_'+sid+'_'+name in content for sid,name in zip(ids,['A','B'])),content
        assert all(core.interface_inbound(i) in content for i in ('atesta','atestb')),content
        print('PASS identical client IP/subnet and UDP tuple enter distinct interfaces and select A/B independently',flush=True)
        print(subprocess.check_output(['ip','rule','show'],text=True),flush=True)
        print(subprocess.check_output(['nft','list','tables'],text=True),flush=True)
    finally:
        process.terminate();process.wait(timeout=20)
        atlas.manage_ingress_firewall(False)
        for iface in ('atesta','atestb'):subprocess.run(['ip','link','del',iface],check=True)
