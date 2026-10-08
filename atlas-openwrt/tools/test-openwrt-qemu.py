"""Install and exercise Atlas 0.17.0 on the disposable OpenWrt QEMU snapshot."""
from pathlib import Path
import json
import hashlib
import os
import shlex
import subprocess
import time

LAB = Path(os.environ.get('ATLAS_OPENWRT_LAB', str(Path(__file__).resolve().parents[2] / 'openwrt-lab'))).resolve()
ROOT = Path(__file__).resolve().parents[1]
qemu = LAB / 'qemu/usr/bin/qemu-system-x86_64'
env = dict(os.environ,
           LD_LIBRARY_PATH=str(LAB / 'qemu/usr/lib/x86_64-linux-gnu'),
           QEMU_MODULE_DIR=str(LAB / 'qemu/usr/lib/x86_64-linux-gnu/qemu'))
args = [str(qemu), '-machine', 'pc,accel=tcg', '-snapshot', '-m', '512', '-smp', '2',
        '-display', 'none', '-vga', 'none', '-serial', 'file:' + str(LAB / 'serial-014.log'),
        '-monitor', 'none', '-no-reboot', '-L', str(LAB / 'qemu/usr/share/qemu'),
        '-bios', str(LAB / 'qemu/usr/share/seabios/bios-256k.bin'),
        '-drive', 'file=' + str(LAB / 'openwrt.img') + ',format=raw,if=virtio',
        '-netdev', 'user,id=lan,net=192.168.1.0/24,hostfwd=tcp:127.0.0.1:18080-192.168.1.1:80,hostfwd=tcp:127.0.0.1:12222-192.168.1.1:22',
        '-device', 'virtio-net-pci,netdev=lan,romfile=',
        '-netdev', 'user,id=wan,net=10.0.3.0/24', '-device', 'virtio-net-pci,netdev=wan,romfile=']
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30',
                '-subj', '/CN=Atlas disposable lab', '-addext', 'subjectAltName=IP:10.0.3.2',
                '-keyout', str(LAB / 'lab-key.pem'), '-out', str(LAB / 'www/lab-cert.pem')],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
fixture = subprocess.Popen(['python3', str(ROOT / 'tools/https-lab-fixture.py'), str(LAB / 'www/lab-cert.pem'), str(LAB / 'lab-key.pem')], stdout=subprocess.DEVNULL, stderr=(LAB / 'fixture-014.log').open('w'))
q = subprocess.Popen(args, env=env, stderr=(LAB / 'qemu-014.log').open('w'))
ssh = ['ssh', '-i', str(LAB / 'test-key'), '-o', 'StrictHostKeyChecking=accept-new',
       '-o', 'UserKnownHostsFile=' + str(LAB / 'known-hosts'), '-o', 'BatchMode=yes',
       '-o', 'ConnectTimeout=3', '-p', '12222', 'root@127.0.0.1']


def remote(args, timeout=60):
    return subprocess.run(ssh + args, text=True, capture_output=True, timeout=timeout)


def script(body, timeout=120):
    result = subprocess.run(ssh + ['sh', '-s'], input=body, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('remote command failed (%d):\n%s\n%s' %
                           (result.returncode, result.stdout, result.stderr))
    return result.stdout


def status():
    last = None
    for _ in range(20):
        result = remote(['ubus call atlas status'], timeout=10)
        if result.returncode == 0:
            return json.loads(result.stdout)
        last = result.stderr
        time.sleep(.5)
    raise RuntimeError('Atlas status unavailable: ' + str(last))


def wait_job(job_id, limit=70):
    for _ in range(limit):
        current = status()
        job = current.get('job', {})
        if job.get('id') == job_id and job.get('status') in ('done', 'error'):
            if job['status'] != 'done':
                raise RuntimeError('Atlas job failed: ' + job.get('message', 'unknown'))
            return current
        time.sleep(.6)
    raise RuntimeError('Timed out waiting for Atlas job ' + job_id)


def action(operation):
    result = remote(['ubus call atlas action ' + shlex.quote(json.dumps({'operation': operation}))], timeout=10)
    if result.returncode:
        raise RuntimeError('action failed: ' + result.stderr)
    job_id = json.loads(result.stdout)['job']
    return wait_job(job_id)


try:
    for _ in range(90):
        ready = remote(['ubus call system board'], timeout=4)
        if ready.returncode == 0:
            break
        if q.poll() is not None:
            raise RuntimeError('QEMU exited before OpenWrt became ready')
        time.sleep(1)
    else:
        raise RuntimeError('OpenWrt SSH did not become ready')
    print('OpenWrt 24.10.7 x86/64 ready')

    copy = subprocess.run(['scp', '-O', '-i', str(LAB / 'test-key'),
                           '-o', 'StrictHostKeyChecking=accept-new',
                           '-o', 'UserKnownHostsFile=' + str(LAB / 'known-hosts'),
                           '-P', '12222', str(ROOT / 'dist/luci-app-atlas_0.17.0-1_all.ipk'),
                           'root@127.0.0.1:/tmp/atlas-0.17.0.ipk'],
                          text=True, capture_output=True, timeout=60)
    if copy.returncode:
        raise RuntimeError('Could not copy package: ' + copy.stderr)
    install = script('opkg install /tmp/atlas-0.17.0.ipk\n/etc/init.d/rpcd status\n')
    current = status()
    assert current['version'] == '0.17.0', current.get('version')
    print('Installed 0.17.0; RPC is live after package postinst')

    cert_copy = subprocess.run(['scp', '-O', '-i', str(LAB / 'test-key'), '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'UserKnownHostsFile=' + str(LAB / 'known-hosts'), '-P', '12222', str(LAB / 'www/lab-cert.pem'),
        'root@127.0.0.1:/tmp/atlas-lab-cert.pem'], text=True, capture_output=True, timeout=30)
    assert cert_copy.returncode == 0, 'Lab CA copy failed'
    script('cat /tmp/atlas-lab-cert.pem >> /etc/ssl/certs/ca-certificates.crt\n')

    reset = r"""/etc/init.d/cron stop
python3 - <<'PYRESET'
import os, signal, sys, time
sys.path.insert(0, '/usr/lib/atlas')
import atlas as backend, core
job = backend.read_json(backend.RUN / 'job.json', {})
pid = job.get('pid')
if type(pid) is int and pid > 1 and job.get('status') in ('queued','running'):
    try:
        cmdline = backend.Path('/proc/%d/cmdline' % pid).read_bytes()
        if b'/usr/lib/atlas/atlas.py' in cmdline and b'worker' in cmdline:
            os.kill(pid, signal.SIGTERM)
            time.sleep(.5)
    except OSError:
        pass
job.update(status='error', message='Disposable test setup cancelled the old scheduled job')
backend.atomic(backend.RUN / 'job.json', job)
backend.run(['/etc/init.d/atlas','disable'])
backend.run(['/etc/init.d/atlas','stop'], 20)
current = core.defaults()
current['subscriptions'] = [{'id':'a'*16,'name':'Local lab','enabled':True,'source':'local','url':'','nodes':[
    core.uri_node('vless://11111111-1111-4111-8111-111111111111@127.0.0.1:20001?security=none#EE%20Test%20Fast'),
    core.uri_node('vless://22222222-2222-4222-8222-222222222222@127.0.0.1:20003?security=none#DE%20Test%20Backup')]}]
backend.atomic(backend.STATE, current)
PYRESET
"""
    script(reset, timeout=60)

    native_import = r"""python3 - <<'PYGUEST'
import json, subprocess, sys
sys.path.insert(0, '/usr/lib/atlas')
import core, atlas as backend, yaml

def ub(method, args=None):
    result = subprocess.run(['ubus', 'call', 'atlas', method, json.dumps(args or {}, ensure_ascii=False)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    reply = json.loads(result.stdout)
    assert reply.get('ok'), reply
    return reply

outbound = {'type':'vless','server':'example.com','server_port':443,'uuid':'11111111-1111-4111-8111-111111111111','tls':{'enabled':True,'server_name':'example.com'},'tag':'NL Local fixture'}
inline = ub('import_profiles', {'name':'Local native fixture','content':json.dumps({'outbounds':[outbound]})})
assert inline['count'] == 1, inline
sub = next(x for x in ub('status')['subscriptions'] if x['id'] == inline['id'])
assert sub['source'] == 'local' and sub['host'] == 'Локальный импорт', sub
large = json.dumps({'outbounds':[outbound]}) + '\n' + ' ' * 150000
payload = json.dumps({'name':'Large local fixture','content':large})
large_result = subprocess.run(['/usr/bin/python3','/usr/lib/atlas/atlas.py','call','import_profiles'], input=payload, text=True, capture_output=True, timeout=30)
assert large_result.returncode == 0 and json.loads(large_result.stdout)['count'] == 1, large_result.stdout
print('INLINE_IMPORT_RPC', inline['count'], inline['format'], flush=True)
print('LARGE_IMPORT_BACKEND', len(large.encode()), flush=True)
clash = 'proxies:\n  - name: "DE WS"\n    type: vless\n    server: example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    tls: true\n    servername: example.com\n    network: ws\n    ws-opts:\n      path: /ws\n  - name: "EE AnyTLS"\n    type: anytls\n    server: example.com\n    port: 443\n    password: test-password\n    sni: example.com\n'
parsed = core.parse_subscription(clash.encode())
assert len(parsed['nodes']) == 2, parsed
for node in parsed['nodes'] + [core.uri_node('anytls://test-password@example.com:443?sni=example.com#DE%20AnyTLS')]:
    backend.check(core.make_config(core.defaults(), tun=False, probe_node=node))
assert yaml.__version__ == '6.0.3'
print('YAML_ANYTLS_SCHEMA_CHECK', len(parsed['nodes']), yaml.__version__, flush=True)
batch = ub('import_subscriptions', {'items':[{'name':'Batch fixture','url':'https://example.com/atlas-fixture'}]})
assert batch['added'] == 1, batch
bad = subprocess.run(['ubus','call','atlas','action',json.dumps({'operation':'geo_check','id':'a'*32})], text=True, capture_output=True)
assert json.loads(bad.stdout)['ok'] is False
print('BATCH_AND_GEO_RPC_VALIDATION', flush=True)
PYGUEST
"""
    print(script(native_import, timeout=120).strip())

    provider = {}
    private_link = os.environ.get('ATLAS_PRIVATE_HAPP_FILE')
    cached_body = os.environ.get('ATLAS_CACHED_SUBSCRIPTION_FILE')
    if private_link and cached_body:
        for source, target in ((private_link, '/tmp/atlas-private-happ'), (cached_body, '/tmp/atlas-cached-subscription')):
            copied = subprocess.run(['scp', '-O', '-i', str(LAB / 'test-key'), '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(LAB / 'known-hosts'), '-P', '12222', source, 'root@127.0.0.1:' + target], capture_output=True, text=True, timeout=30)
            assert copied.returncode == 0, 'Private fixture copy failed'
        provider_script = r"""python3 - <<'PYPROVIDER'
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, '/usr/lib/atlas')
import core, atlas as backend
link = Path('/tmp/atlas-private-happ').read_text().strip()
reply = subprocess.run(['ubus','call','atlas','save_subscription',json.dumps({'name':'Private Happ fixture','url':link,'enabled':False})], capture_output=True, text=True, timeout=30)
assert reply.returncode == 0 and json.loads(reply.stdout).get('ok'), 'Happ normalization RPC failed'
raw = Path('/tmp/atlas-cached-subscription').read_text()
reply = subprocess.run(['ubus','call','atlas','import_profiles',json.dumps({'name':'Historical provider cache','content':raw})], capture_output=True, text=True, timeout=30)
assert reply.returncode == 0 and json.loads(reply.stdout).get('ok'), 'Cached provider import failed'
parsed = core.parse_subscription(raw.encode())
for node in parsed['nodes']:
    backend.check(core.make_config(core.defaults(), tun=False, probe_node=node))
print('HAPP_NATIVE_AND_CACHED_IMPORT', json.dumps({'crypt5_native':True,'cached_profiles':len(parsed['nodes']),'schema_checked':len(parsed['nodes']),'live_fetch':False}), flush=True)
Path('/tmp/atlas-private-happ').unlink()
Path('/tmp/atlas-cached-subscription').unlink()
PYPROVIDER
"""
        output = script(provider_script, timeout=120)
        print(output.strip())
        provider = json.loads(output.split('HAPP_NATIVE_AND_CACHED_IMPORT ', 1)[1].strip())

    current = action('start')
    assert current['running'], 'Atlas failed to start'
    engine = remote(['/usr/bin/sing-box check -c /var/run/atlas/config.json'], timeout=20)
    assert engine.returncode == 0, engine.stderr
    print('sing-box 1.12.22 started; atlas0 and config check passed')

    monitor_diag = r'''python3 - <<'PYCODE'
import json, subprocess, sys
sys.path.insert(0, '/usr/lib/atlas')
import atlas
print('SERVICE_RUNNING', atlas.service_running(), flush=True)
cfg = json.loads(atlas.CONFIG.read_text())
api = cfg.get('experimental', {}).get('clash_api', {})
print('API_CONFIG', api.get('external_controller'), len(api.get('secret', '')), flush=True)
for path in ('/connections', '/rules'):
    code = "import sys,json;sys.path.insert(0,'/usr/lib/atlas');import atlas; x=atlas.clash_request('GET',%r,timeout=2); print('SIZE',len(json.dumps(x))); print('KEYS',list(x)); print('COUNT',len(x.get('connections',x.get('rules',[]))))" % path
    try:
        r = subprocess.run(['/usr/bin/python3', '-c', code], text=True, capture_output=True, timeout=8)
        print('ENDPOINT', path, r.returncode, r.stdout[:300], r.stderr[:300], flush=True)
    except subprocess.TimeoutExpired as e:
        print('ENDPOINT_TIMEOUT', path, e.stdout, e.stderr, flush=True)
code = "import sys,json;sys.path.insert(0,'/usr/lib/atlas');import atlas; print(json.dumps(atlas.runtime_monitor()))"
try:
    r = subprocess.run(['/usr/bin/python3', '-c', code], text=True, capture_output=True, timeout=15)
    print('DIRECT_MONITOR', r.returncode, r.stdout[:500], r.stderr[:300], flush=True)
except subprocess.TimeoutExpired as e:
    print('DIRECT_MONITOR_TIMEOUT', e.stdout, e.stderr, flush=True)
try:
    r = subprocess.run(['ubus','call','atlas','monitor'], text=True, capture_output=True, timeout=20)
    print('UBUS_MONITOR', r.returncode, r.stdout[:500], r.stderr[:300], flush=True)
except subprocess.TimeoutExpired as e:
    print('UBUS_MONITOR_TIMEOUT', e.stdout, e.stderr, flush=True)
PYCODE
'''
    diag = script(monitor_diag, timeout=90)
    print(diag.strip())
    assert 'DIRECT_MONITOR 0' in diag and 'UBUS_MONITOR 0' in diag, diag
    print('Loopback connections monitor RPC passed')

    dns_script = r'''python3 - <<'PYCODE'
import json, re, shlex, subprocess, time

def uci(*args):
    return subprocess.run(['uci', '-q', *args], text=True, capture_output=True)

def snapshot():
    raw = uci('show', 'dhcp').stdout
    found = {'server': [], 'noresolv': [], 'cachesize': []}
    for line in raw.splitlines():
        fields = shlex.split(line, comments=False)
        if not fields:
            continue
        key, sep, value = fields[0].partition('=')
        if sep:
            match = re.match(r'^dhcp\.@dnsmasq\[0\]\.(server|noresolv|cachesize)$', key)
            if match:
                found[match.group(1)].append(value)
    return found

def atlas(*args):
    return json.loads(subprocess.check_output(['ubus', 'call', 'atlas', *args]))

before = snapshot()
s = atlas('status')['settings']; s.update(dhcp_dns_enabled=True, fakeip=True, mode='global', countries=[], excluded_countries=[], preferred_countries=[], require_verified_countries=False)
assert atlas('save_settings', json.dumps({'settings': s}, separators=(',', ':')))['ok']
job = atlas('action', json.dumps({'operation': 'apply'}))['job']
for _ in range(70):
    status = atlas('status')
    if status.get('job', {}).get('id') == job and status['job'].get('status') in ('done', 'error'):
        break
    time.sleep(.6)
assert status['job']['status'] == 'done', status['job']
assert status['running']
live = snapshot()
assert live == {'server': ['127.0.0.42'], 'noresolv': ['1'], 'cachesize': ['0']}, live
subprocess.run(['/usr/bin/sing-box', 'check', '-c', '/var/run/atlas/config.json'], check=True, capture_output=True)
print('DNS_ON', json.dumps(live), flush=True)
import sys
sys.path.insert(0, '/usr/lib/atlas')
import atlas as backend
print('DNS_LISTENERS', backend.Path('/proc/net/udp').read_text(), flush=True)
print('DNS_INBOUNDS', json.dumps(backend.read_json(backend.CONFIG, {}).get('inbounds', [])), flush=True)
try:
    addresses = backend.query_local_dns_a('atlas-native-%s.example.com' % int(time.time()))
except Exception:
    print('DNS_LOGS', subprocess.run(['logread','-e','dns'], capture_output=True, text=True).stdout[-6000:], flush=True)
    for resolver in ('127.0.0.42', '127.0.0.1'):
        try:
            print('NSLOOKUP', resolver, subprocess.run(['nslookup','atlas-check.example.com',resolver], capture_output=True, text=True, timeout=8).stdout, flush=True)
        except Exception:
            print('NSLOOKUP_TIMEOUT', resolver, flush=True)
    raise
assert addresses and all(address.startswith('198.18.') or address.startswith('198.19.') for address in addresses), addresses
backend.probe = lambda *args, **kwargs: {'ok':False, 'error':'Skipped: external provider was not tested'}
result = backend.selftest(backend.state())
fakeip = next(x for x in result['checks'] if x['id'] == 'fakeip_dns')
assert fakeip['ok'], fakeip
print('FAKEIP_DNSMASQ', addresses, fakeip['label'], flush=True)


s = atlas('status')['settings']; s.update(dhcp_dns_enabled=False, fakeip=False)
assert atlas('save_settings', json.dumps({'settings': s}, separators=(',', ':')))['ok']
job = atlas('action', json.dumps({'operation': 'apply'}))['job']
for _ in range(70):
    status = atlas('status')
    if status.get('job', {}).get('id') == job and status['job'].get('status') in ('done', 'error'):
        break
    time.sleep(.6)
assert status['job']['status'] == 'done', status['job']
restored = snapshot()
assert restored == before, {'before': before, 'restored': restored}
print('DNS_OFF_RESTORED', json.dumps(restored), flush=True)
PYCODE
'''
    print(script(dns_script, timeout=180).strip())

    policy_script = r"""python3 - <<'PYGUEST'
import json, subprocess, sys, time, urllib.parse, http.client, ssl
sys.path.insert(0, '/usr/lib/atlas')
import atlas as backend, core
# Controlled VLESS and TLS fixtures exercise real URLTest measurements without
# depending on a public provider or representing a country/geolocation test.
def wait_dns(domain):
    for attempt in range(12):
        try:return backend.query_local_dns_a(domain)
        except core.AtlasError:time.sleep(.5)
    raise AssertionError('dnsmasq did not become ready after restart')
def wait_api():
    for attempt in range(60):
        try:return backend.clash_request()['proxies']
        except OSError:time.sleep(.5)
    raise AssertionError('Engine API unavailable: '+subprocess.run(['logread','-e','atlas'],capture_output=True,text=True).stdout)
processes=[]
for port, uid in ((20001,'11111111-1111-4111-8111-111111111111'),(20002,'22222222-2222-4222-8222-222222222222')):
    cfg={'inbounds':[{'type':'vless','listen':'127.0.0.1','listen_port':port,'users':[{'uuid':uid}]}],'outbounds':[{'type':'direct'}]}
    path='/tmp/atlas-fixture-%d.json'%port
    backend.atomic(backend.Path(path),cfg)
    processes.append(subprocess.Popen(['/usr/bin/sing-box','run','-c',path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
relay='''import socket,threading,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',20003));s.listen()
def copy(a,b):
 try:
  while True:
   d=a.recv(65536)
   if not d:break
   time.sleep(.1);b.sendall(d)
 except OSError:pass
 finally:
  try:b.shutdown(socket.SHUT_WR)
  except OSError:pass
while True:
 a,_=s.accept();b=socket.create_connection(('127.0.0.1',20002));threading.Thread(target=copy,args=(a,b),daemon=True).start();threading.Thread(target=copy,args=(b,a),daemon=True).start()
'''
processes.append(subprocess.Popen(['/usr/bin/python3','-c',relay],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
try:
    current=core.defaults();sid='a'*16
    current['subscriptions']=[{'id':sid,'source':'local','name':'Local policy fixtures','url':'','enabled':True,'nodes':[
        core.uri_node('vless://11111111-1111-4111-8111-111111111111@127.0.0.1:20001?security=none#EE%20Fixture'),
        core.uri_node('vless://22222222-2222-4222-8222-222222222222@127.0.0.1:20003?security=none#DE%20Fixture')]}]
    current['settings'].update(mode='rules',fakeip=True,dhcp_dns_enabled=True,auto_strategy='slowest',
        urltest_url='https://10.0.3.2:19443/generate_204',max_ping_ms=60000,
        sections=[{'name':'Pool test','policy':'proxy','domains':['work.example'],'cidrs':[],'source_ips':[],'pool':sid}],
        remote_lists=[{'name':'Proxy list test','url':'https://example.org/list','format':'domains','policy':'proxy','enabled':True,'domains':['remote.example'],'cidrs':[]}])
    current['settings']=core.validate_settings(current['settings'])
    backend.atomic(backend.STATE,current);backend.apply(current)
    cfg=backend.read_json(backend.CONFIG,{})
    assert cfg['experimental']['cache_file']['enabled'] and cfg['experimental']['cache_file']['store_fakeip']
    cfg['inbounds'].extend([{'type':'mixed','tag':'test-main','listen':'127.0.0.1','listen_port':2081},
                            {'type':'mixed','tag':'test-pool','listen':'127.0.0.1','listen_port':2082}])
    cfg['route']['rules'][0:0]=[{'inbound':['test-main'],'action':'route','outbound':'proxy'},
                               {'inbound':['test-pool'],'action':'route','outbound':'pool_'+sid}]
    backend.check(cfg);backend.atomic(backend.CONFIG,cfg)
    subprocess.run(['/etc/init.d/atlas','restart'],check=True,capture_output=True);wait_api()
    proxies=backend.clash_request()['proxies']
    assert proxies['proxy']['now']=='policy-block',proxies['proxy']
    assert proxies['pool_'+sid]['now']=='policy-block',proxies['pool_'+sid]
    # Section and remote-list FakeIP work even with an empty global domain list.
    mapping={}
    for suffix in ('work.example','remote.example'):
        domain='persist.'+suffix
        addresses=wait_dns(domain)
        mapping[domain]=addresses
        assert addresses and all(a.startswith(('198.18.','198.19.')) for a in addresses),addresses
    backend.probe=lambda *a,**k:{'ok':False,'error':'External test omitted'}
    fake=next(x for x in backend.selftest(current)['checks'] if x['id']=='fakeip_dns')
    assert fake['ok'],fake
    url=urllib.parse.quote(current['settings']['urltest_url'],safe='')
    for node in core.all_nodes(current):
        backend.clash_request('GET','/proxies/'+node['key']+'/delay?timeout=5000&url='+url,timeout=8)
    selected=backend.automatic_select(current)
    assert len(selected['groups'])==2 and not any(g['blocked'] for g in selected['groups']),selected
    assert all(g['selected']==core.all_nodes(current)[1]['key'] for g in selected['groups']),selected
    def https(port):
        conn=http.client.HTTPSConnection('127.0.0.1',port,context=ssl.create_default_context(),timeout=8)
        try:
            conn.set_tunnel('10.0.3.2',19443);conn.request('GET','/generate_204');return conn.getresponse().status
        finally:conn.close()
    assert https(2081)==204 and https(2082)==204
    current['settings']['max_ping_ms']=1
    blocked=backend.automatic_select(current)
    assert all(g['blocked'] for g in blocked['groups']),blocked
    for port in (2081,2082):
        try:https(port)
        except (OSError,http.client.HTTPException):pass
        else:raise AssertionError('Blocked pool transferred HTTPS')
    current['settings']['max_ping_ms']=60000
    recovered=backend.automatic_select(current)
    assert not any(g['blocked'] for g in recovered['groups']),recovered
    assert https(2081)==204 and https(2082)==204
    namespace=backend.read_json(backend.CONFIG,{})['experimental']['cache_file']['cache_id']
    subprocess.run(['/etc/init.d/atlas','restart'],check=True,capture_output=True);wait_api()
    assert backend.read_json(backend.CONFIG,{})['experimental']['cache_file']['cache_id'] != namespace
    for domain in reversed(list(mapping)):
        assert wait_dns(domain)==mapping[domain]
    assert backend.clash_request()['proxies']['proxy']['now']=='policy-block'
    current['settings']['browser_diagnostics']=True
    diagnostic=backend.runtime_config(current);backend.check(diagnostic)
    assert any(r.get('override_port')==8443 for r in diagnostic['route']['rules'])
    current['settings']['browser_diagnostics']=False
    # Actual config validation includes resolve actions and avoids bootstrap loop.
    current['settings']['resolve_real_ip']=True
    checked=backend.runtime_config(current);backend.check(checked)
    assert core.real_ip_resolution_active(checked)
    current['settings'].update(auto_strategy='fastest',max_ping_ms=0,sections=[],remote_lists=[],fakeip=False,dhcp_dns_enabled=False)
    backend.atomic(backend.STATE,current);backend.apply(current)
    print('REAL_POOL_SLOWEST_HTTPS_BLOCK_RECOVER_AND_SECTION_LIST_FAKEIP',json.dumps({'groups':2,'https':204,'block_and_recover':True,'section_list_fakeip':True}),flush=True)
finally:
    for process in processes:process.terminate()
PYGUEST
"""
    print(script(policy_script, timeout=180).strip())

    country_script = r"""python3 - <<'PYGUEST'
import json, sys, time
sys.path.insert(0, '/usr/lib/atlas')
import atlas as backend, core
current = backend.state()
for sub in current['subscriptions']:
    for node in sub.get('nodes', []):
        node.update(verified_country='DE', country_verified_at=int(time.time()))
key = core.all_nodes(current)[0]['key']
for sub in current['subscriptions']:
    for node in sub.get('nodes', []):
        if sub['id'] + node['id'] == key:
            node['verified_country'] = 'EE'
current['settings'].update(countries=['EE'], require_verified_countries=True, selected='auto')
backend.atomic(backend.STATE, current)
backend.apply(current)
assert len(core.selection_nodes(current)) == 1
message = backend.save_exit_country(current, key, 'RU')
for _ in range(20):
    if not backend.service_running():
        break
    time.sleep(.25)
assert not backend.service_running(), message
assert backend.kill_switch_active(), 'Fail-closed guard was not installed'
assert backend.state()['settings']['kill_switch']
assert not backend.Path('/etc/rc.d/S99atlas').exists(), 'Watchdog could restart a forbidden exit'
print('COUNTRY_FILTER_EMPTY_POOL_GUARD', message, flush=True)
# Restore temporary firewall policy in the disposable guest.
backend.manage_kill_switch(False)
current = backend.state(); current['settings'].update(countries=[], require_verified_countries=False, kill_switch=False)
backend.atomic(backend.STATE, current)
PYGUEST
"""
    print(script(country_script, timeout=120).strip())

    stopped = action('stop')
    assert not stopped['running']
    print('Service stop completed and DNS settings were restored')
    output = {'ok': True, 'version': '0.17.0', 'engine': 'sing-box 1.12.22',
              'installed': True, 'runtime_start': True, 'monitor': True, 'inline_import_rpc': True,
              'large_import_backend': True, 'yaml_anytls_schema_check': True,
              'fakeip_dnsmasq': True, 'real_pool_slowest_https_block_recover': True, 'section_list_fakeip': True, 'country_empty_pool_guard': True, 'provider_fixture': provider, 'package_sha256': hashlib.sha256((ROOT / 'dist/luci-app-atlas_0.17.0-1_all.ipk').read_bytes()).hexdigest(),
              'dns_enable_apply_restore': True, 'service_stop_restore': True, 'fakeip_persistence_strict_restart': True, 'selector_namespace_rotated': True, 'browser_diagnostics_schema': True}
    (LAB / 'verify-014-result.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output))
finally:
    fixture.terminate()
    if q.poll() is None:
        remote(['poweroff'], timeout=15)
        try:
            q.wait(timeout=20)
        except subprocess.TimeoutExpired:
            q.terminate()
