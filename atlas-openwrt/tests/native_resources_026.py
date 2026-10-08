"""Short native resource audit, isolated cache/HTTP/DNS fixtures; no WAN.

Does not claim LAN/TUN coverage or a long-duration leak-free guarantee.
"""
import http.client
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0, '/usr/lib/atlas')
import atlas, core


class Fixture(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        first = self.rfile.readline(4096)
        while self.rfile.readline(4096) not in (b'\r\n', b'\n', b''): pass
        if not first.startswith(b'CONNECT '): return
        self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n'); self.wfile.flush()
        self.rfile.readline(4096)
        while self.rfile.readline(4096) not in (b'\r\n', b'\n', b''): pass
        body = b'atlas-resource-fixture' * 256
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
        self.wfile.flush()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def rss(pid):
    for line in Path('/proc/%d/status' % pid).read_text().splitlines():
        if line.startswith('VmRSS:'): return int(line.split()[1]) * 1024


def top_buckets(path):
    """Read-only top-level keys from a stopped Bolt DB (not a cache editor)."""
    raw = path.read_bytes()
    page_size = struct.unpack_from('<I', raw, 24)[0]
    metas = [offset for offset in (0, page_size) if struct.unpack_from('<I', raw, offset + 16)[0] == 0xed0cdaed]
    meta = max(metas, key=lambda offset: struct.unpack_from('<Q', raw, offset + 64)[0])
    root = struct.unpack_from('<Q', raw, meta + 32)[0]
    def walk(pgid):
        offset = pgid * page_size
        flags, count = struct.unpack_from('<HH', raw, offset + 8)
        assert flags in (1, 2), flags
        for index in range(count):
            base = offset + 16 + index * 16
            if flags == 1:
                yield from walk(struct.unpack_from('<Q', raw, base + 8)[0])
            else:
                _, pos, size, _ = struct.unpack_from('<IIII', raw, base)
                yield raw[base + pos:base + pos + size]
    return list(walk(root))


started = time.monotonic()
server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Fixture)
server.daemon_threads = True
threading.Thread(target=server.serve_forever, daemon=True).start()
process = None
dns_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_client.settimeout(10)
report = {'version': atlas.VERSION, 'external_network': False, 'scope': 'short-loopback-engine-audit', 'restarts': [], 'memory_samples': []}
try:
    with tempfile.TemporaryDirectory(prefix='atlas-resource-') as directory:
        root = Path(directory)
        mixed, dns = free_port(), free_port()
        current = core.defaults()
        node = core.uri_node('http://127.0.0.1:%d#fixture' % server.server_address[1]); node['id'] = 'e' * 16
        current['subscriptions'] = [{'id': 'a' * 16, 'name': 'fixture', 'enabled': True, 'source': 'local', 'nodes': [node]}]
        current['settings'].update(max_ping_ms=100, fakeip=True, mode='global', urltest_url='https://fixture.invalid/check')
        config = core.make_config(current, api_secret='f' * 64)
        for outbound in config['outbounds']:
            if outbound['type'] == 'urltest': outbound['url'] = 'http://fixture.invalid/check'
        config['inbounds'] = [{'type': 'mixed', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': mixed}, {'type': 'direct', 'tag': 'dns-fixture', 'listen': '127.0.0.1', 'listen_port': dns}]
        config['route']['rules'] = [{'inbound': ['dns-fixture'], 'action': 'hijack-dns'}]
        config['route']['final'] = 'proxy'
        cache = root / 'cache.db'; config['experimental']['cache_file']['path'] = str(cache)
        path = root / 'config.json'
        atlas.CONFIG = path
        def api(method='GET', suffix='/proxies', body=None):
            c = http.client.HTTPConnection('127.0.0.1', 19090, timeout=10)
            try:
                c.request(method, suffix, body=json.dumps(body) if body is not None else None, headers={'Authorization': 'Bearer ' + 'f' * 64, 'Content-Type': 'application/json', 'Connection': 'close'})
                response = c.getresponse(); data = response.readline(65536) if suffix=='/memory' else response.read(); assert response.status in (200, 204), (response.status, data)
                return json.loads(data) if data else {}
            finally: c.close()
        def fetch():
            c = http.client.HTTPConnection('127.0.0.1', mixed, timeout=10)
            try:
                c.request('GET', 'http://fixture.invalid/resource', headers={'Connection': 'close'})
                response = c.getresponse(); body = response.read()
                assert response.status == 200 and body == b'atlas-resource-fixture' * 256
            finally: c.close()
        def query(name):
            question = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\x00'
            request = struct.pack('!HHHHHH', 0x1234, 0x100, 1, 0, 0, 0) + question + struct.pack('!HH', 1, 1)
            dns_client.sendto(request, ('127.0.0.1', dns)); reply = dns_client.recv(4096)
            assert struct.unpack_from('!H', reply, 6)[0] > 0 and reply[-4:-2] == b'\xc6\x12', reply.hex()
            return reply[-4:]
        initial_mapping = None
        for restart in range(12):
            generated = atlas.prepare_engine_start(config); path.write_text(json.dumps(generated))
            atlas.check(generated)
            with (root / 'engine.log').open('wb') as log:
                process = subprocess.Popen([atlas.BINARY, 'run', '-c', str(path)], stdout=log, stderr=log)
                for _ in range(120):
                    if process.poll() is not None: raise AssertionError((root / 'engine.log').read_text())
                    try: proxies = api()['proxies']; break
                    except (OSError, http.client.HTTPException): time.sleep(.2)
                else: raise AssertionError('API startup timeout')
                assert proxies['proxy']['now'] == 'policy-block', proxies['proxy']
                selected = next(x['tag'] for x in generated['outbounds'] if x.get('type')=='http')
                if atlas.VERSION != '0.26.0':
                    atlas.clash_request('PUT','/proxies/proxy',{'name':'a'*16+'e'*16})
                    normalized = atlas.clash_request()['proxies']
                    assert normalized['proxy']['now']=='a'*16+'e'*16
                    assert 'a'*16+'e'*16 in normalized
                    atlas.clash_request('PUT','/proxies/proxy',{'name':'auto'})
                    assert api()['proxies']['proxy']['now']=='policy-block'
                    atlas.clash_request('PUT','/proxies/proxy',{'name':'a'*16+'e'*16})
                else:
                    api('PUT', '/proxies/proxy', {'name': selected})
                fetch()
                mapping = query('persistent.resource.invalid')
                if initial_mapping is None: initial_mapping = mapping
                assert mapping == initial_mapping, 'FakeIP mapping changed across restart'
                if restart == 11:
                    for batch in range(20):
                        for i in range(100):
                            fetch(); query('domain-%d.resource.invalid' % ((batch * 100 + i) % 1000))
                        time.sleep(1)
                        sample = {'batch': batch, 'requests': (batch + 1) * 100, 'rss_bytes': rss(process.pid), 'cache_bytes':cache.stat().st_size, 'active_connections': len(api(suffix='/connections').get('connections', []))}
                        report['memory_samples'].append(sample)
                        print(json.dumps({'progress': sample}), flush=True)
                process.terminate(); process.wait(timeout=15); process = None
            keys = top_buckets(cache)
            sample = {'restart': restart + 1, 'cache_bytes': cache.stat().st_size, 'policy_namespaces': sum(key.startswith(b'\x00atlas-policy-') for key in keys)}
            report['restarts'].append(sample); print(json.dumps({'progress': sample}), flush=True)
        report.update(fakeip_persistence=True, fail_closed_after_restart=True, successful_http_requests=2012, successful_fakeip_queries=2012, unique_domain_count=1001, duration_seconds=round(time.monotonic() - started, 2))
        report['cache_namespace_accumulation_reproduced'] = report['restarts'][-1]['policy_namespaces'] > report['restarts'][0]['policy_namespaces']
        report['memory_leak_free_proven'] = False
        Path('/tmp/atlas-resource-audit.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({'result': report}), flush=True)
finally:
    dns_client.close()
    if process is not None and process.poll() is None:
        process.terminate()
        try: process.wait(timeout=15)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    server.shutdown(); server.server_close()
