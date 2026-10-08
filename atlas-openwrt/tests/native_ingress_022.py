import sys,json,subprocess,time,socket,struct,re
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import core
import atlas
subprocess.run(['/etc/init.d/atlas','stop'],check=True)
for iface,peer in [('atesta','atestpa'),('atestb','atestpb')]:
    subprocess.run(['ip','link','del',iface],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['ip','link','add',iface,'type','veth','peer','name',peer],check=True)
    subprocess.run(['ip','addr','add','10.111.1.1/24','dev',iface],check=True)
    subprocess.run(['ip','-6','addr','add','fd00:111::1/64','dev',iface],check=True)
    subprocess.run(['ip','link','set',iface,'up'],check=True)
    subprocess.run(['ip','link','set',peer,'up'],check=True)
s=core.defaults();s['settings']['log_level']='debug'
s['settings']['sections']=[dict(name=n,policy='proxy',domains=[],cidrs=[],source_ips=[],pool='',interface='',resolver='',source_interfaces=[i],outbound_config=[dict(type='selector',tag='pick',outbounds=[n],default=n),dict(type='direct',tag=n)]) for n,i in [('A','atesta'),('B','atestb')]]
cfg=core.make_config(s);cfg['experimental']['cache_file']['path']='/tmp/ingress022.db'
Path('/tmp/ingress022.json').write_text(json.dumps(cfg))
subprocess.run(['sing-box','check','-c','/tmp/ingress022.json'],check=True)
atlas.manage_ingress_firewall(True)
with open('/tmp/ingress022.log','w') as log:
    process=subprocess.Popen(['sing-box','run','-c','/tmp/ingress022.json'],stdout=log,stderr=log)
    try:
        time.sleep(12)
        assert process.poll() is None,Path('/tmp/ingress022.log').read_text()
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
            # IPv6 UDP requires the checksum over its pseudo-header.
            src=socket.inet_pton(socket.AF_INET6,'fd00:111::2')
            dst=socket.inet_pton(socket.AF_INET6,'2001:db8::7')
            pseudo=src+dst+struct.pack('!I3xB',len(udp),17)
            udp6=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
            ip6=struct.pack('!IHBB16s16s',6<<28,len(udp6),17,64,src,dst)
            with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sender:
                sender.bind((peer,0));sender.send(mac(iface)+mac(peer)+b'\x86\xdd'+ip6+udp6)
        time.sleep(6)
        content=Path('/tmp/ingress022.log').read_text()
        ids=[core.validate_settings(s['settings'])['sections'][i]['id'] for i in (0,1)]
        assert all('section_'+sid+'_'+name in content for sid,name in zip(ids,['A','B'])),content
        plain=re.sub(r'\x1b\[[0-9;]*m','',content)
        for iface,sid,name in zip(('atesta','atestb'),ids,('A','B')):
            for address in ('10.111.1.2','[fd00:111::2]'):
                pattern=r'\[(\d+) \d+ms\] inbound/tun\['+re.escape(core.interface_inbound(iface))+r'\]: inbound packet connection from '+re.escape(address)+r':40111'
                match=re.search(pattern,plain)
                assert match,(iface,address,plain)
                assert any('['+match[1]+' ' in line and 'outbound/direct[section_'+sid+'_'+name+']' in line for line in plain.splitlines()),(iface,address,plain)
        assert all(core.interface_inbound(i) in content for i in ('atesta','atestb')),content
        print('PASS identical IPv4/IPv6 client addresses and UDP tuple enter distinct interfaces and select A/B independently',flush=True)
        print(subprocess.check_output(['ip','rule','show'],text=True),flush=True)
        print(subprocess.check_output(['nft','list','tables'],text=True),flush=True)
    finally:
        process.terminate();process.wait(timeout=20)
        atlas.manage_ingress_firewall(False)
        for iface in ('atesta','atestb'):subprocess.run(['ip','link','del',iface],check=True)
