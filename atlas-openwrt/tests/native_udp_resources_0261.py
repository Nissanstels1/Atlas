"""Diagnose DNS socket churn under lab and production file-descriptor limits."""
import json,resource,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import atlas,core
results=[]
for limit in (1024,65535):
    process=None
    retry_count=0
    with tempfile.TemporaryDirectory(prefix='atlas-udp-audit-') as directory:
        root=Path(directory)
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        state=core.defaults();state['subscriptions']=[dict(id='a'*16,name='fixture',enabled=True,nodes=[core.uri_node('socks5://127.0.0.1:9#fixture')])]
        state['settings'].update(mode='global',fakeip=True)
        cfg=core.make_config(state)
        cfg['inbounds']=[dict(type='direct',tag='dns-fixture',listen='127.0.0.1',listen_port=port)]
        cfg['route']['rules']=[dict(inbound=['dns-fixture'],action='hijack-dns')]
        cfg['experimental']['cache_file']['path']=str(root/'cache.db')
        path=root/'config.json';path.write_text(json.dumps(cfg));atlas.check(cfg)
        def limits():resource.setrlimit(resource.RLIMIT_NOFILE,(limit,limit))
        def query(index):
            global retry_count
            name='client-%d.fixture.invalid'%index
            question=b''.join(bytes([len(part)])+part.encode() for part in name.split('.'))+b'\0'
            packet=struct.pack('!HHHHHH',index,0x100,1,0,0,0)+question+struct.pack('!HH',1,1)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                for attempt in range(3):
                    client.sendto(packet,('127.0.0.1',port))
                    try:reply=client.recv(4096);break
                    except TimeoutError:
                        retry_count+=1
                        if attempt==2:raise
            assert struct.unpack_from('!H',reply,6)[0]>0
        success=0;samples=[]
        try:
            with (root/'engine.log').open('wb') as log:
                process=subprocess.Popen([atlas.BINARY,'run','-c',str(path)],stdout=log,stderr=log,preexec_fn=limits)
                for _ in range(40):
                    try:query(0);break
                    except OSError:time.sleep(.1)
                else:raise AssertionError('DNS fixture did not start')
                for i in range(1,401):
                    try:query(i);success+=1
                    except OSError:break
                    if i%50==0:samples.append(dict(queries=i,open_fds=len(list(Path('/proc/%d/fd'%process.pid).iterdir()))))
                process.terminate();process.wait(timeout=15);process=None
            text=(root/'engine.log').read_text(errors='replace').lower()
            result=dict(nofile=limit,successful_distinct_client_queries=success,timeout_retries=retry_count,samples=samples,descriptor_exhaustion_logged='too many open files' in text)
            results.append(result);print(json.dumps(result),flush=True)
            if limit==65535:assert success==400,result
        finally:
            if process is not None and process.poll() is None:process.terminate();process.wait(timeout=15)
report=dict(version=atlas.VERSION,scope='isolated DNS source socket churn; production procd uses nofile 65535',results=results)
Path('/tmp/atlas-udp-resources-0261.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
