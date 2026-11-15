"""Exercise split FakeIP against real engine and local encrypted DNS fixtures."""
import http.server
import ipaddress
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core

ENGINE = os.environ.get('ATLAS_TEST_ENGINE', '')


class FixtureServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


class DNSHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        wire = self.rfile.read(int(self.headers['Content-Length']))
        pos, labels = 12, []
        while wire[pos]:
            size = wire[pos]
            pos += 1
            labels.append(wire[pos:pos + size].decode('ascii'))
            pos += size
        pos += 1
        name = '.'.join(labels)
        qtype = struct.unpack('!H', wire[pos:pos + 2])[0]
        self.server.observations.append((name, qtype))
        answer = b''
        if qtype == 1:
            ip = '1.2.3.4' if name == 'iprule.example' else '127.0.0.1'
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton(ip)
        header = struct.pack('!HHHHHH', struct.unpack('!H', wire[:2])[0], 0x8180, 1, bool(answer), 0, 0)
        response = header + wire[12:pos + 4] + answer
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class SiteHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '9')
        self.end_headers()
        self.wfile.write(b'direct-ok')


def free_port(socktype):
    with socket.socket(socket.AF_INET, socktype) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def fake_query(port, name):
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.'))
    wire = struct.pack('!HHHHHH', 1234, 0x100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(wire, ('127.0.0.1', port))
        response, _ = sock.recvfrom(4096)
    assert struct.unpack('!H', response[6:8])[0] == 1
    address = ipaddress.ip_address(response[-4:])
    assert address in ipaddress.ip_network('198.18.0.0/15')
    return str(address)


@unittest.skipUnless(ENGINE and os.path.isfile(ENGINE) and shutil.which('openssl'),
                     'Set ATLAS_TEST_ENGINE and install openssl for the native DNS test')
class DirectFakeIPNative(unittest.TestCase):
    def test_direct_fakeip_private_ip_rules_and_host_mismatch(self):
        with tempfile.TemporaryDirectory(prefix='atlas-direct-fakeip-test-') as temp:
            cert, key = [str(Path(temp) / x) for x in ('cert.pem', 'key.pem')]
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            direct_dns = FixtureServer(('127.0.0.1', 0), DNSHandler)
            protected_dns = FixtureServer(('127.0.0.1', 0), DNSHandler)
            website = FixtureServer(('127.0.0.1', 0), SiteHandler)
            for server in (direct_dns, protected_dns):
                server.observations = []
                server.socket = context.wrap_socket(server.socket, server_side=True)
            for server in (direct_dns, protected_dns, website):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            dns_port, proxy_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
            current = core.defaults()
            current['subscriptions'] = [{'id':'a'*16, 'name':'test', 'enabled':True,
                'url':'https://example.com/sub', 'nodes':[core.uri_node(
                'vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&sni=example.com#test')]}]
            current['settings'].update(fakeip=True, direct_fakeip_doh=True,
                bypass_domains=['direct.example'], domains=['proxy.example'], cidrs=['1.2.3.0/24'])
            config = core.make_config(current, tun=False, mixed_port=proxy_port)
            config['log']['level'] = 'debug'
            config['inbounds'] = [{'type':'direct', 'tag':'dns-in', 'listen':'127.0.0.1', 'listen_port':dns_port},
                                  {'type':'mixed', 'tag':'client', 'listen':'127.0.0.1', 'listen_port':proxy_port}]
            config['outbounds'] = [{'type':'direct', 'tag':'direct', 'domain_resolver':'direct-doh'},
                                   {'type':'block', 'tag':'proxy'}, {'type':'block', 'tag':'policy-block'}]
            config['route']['rules'].insert(0, {'inbound':['dns-in'], 'action':'hijack-dns'})
            for server in config['dns']['servers']:
                if server.get('tag') in ('secure', 'direct-doh'):
                    server.update(server='127.0.0.1', server_port=direct_dns.server_port, path='/dns-query',
                        tls={'enabled':True, 'server_name':'localhost', 'certificate_path':cert})
            config['experimental']['cache_file']['path'] = str(Path(temp) / 'cache.db')
            config_path, log_path = Path(temp) / 'config.json', Path(temp) / 'engine.log'
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://127.0.0.1:%d' % proxy_port}))
            proc = None
            def start():
                config_path.write_text(json.dumps(config))
                subprocess.run([ENGINE, 'check', '-c', str(config_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
                log = open(log_path, 'wb')
                process = subprocess.Popen([ENGINE, 'run', '-c', str(config_path)], stdout=log, stderr=log)
                log.close()
                for _ in range(40):
                    if process.poll() is not None:
                        self.fail('Engine failed to start: ' + log_path.read_text()[-1500:])
                    try:
                        with socket.create_connection(('127.0.0.1', proxy_port), timeout=.2):
                            return process
                    except OSError:
                        time.sleep(.1)
                process.terminate()
                self.fail('Engine did not start')
            def request(ip, host):
                return opener.open(urllib.request.Request('http://%s:%d/test' % (ip, website.server_port),
                                   headers={'Host':host}), timeout=5)
            try:
                proc = start()
                direct_ip = fake_query(dns_port, 'direct.example')
                proxy_ip = fake_query(dns_port, 'proxy.example')
                ambiguous_ip = fake_query(dns_port, 'iprule.example')
                with request(direct_ip, 'direct.example') as response:
                    self.assertEqual(response.read(), b'direct-ok')
                self.assertIn(('direct.example', 1), direct_dns.observations)
                for ip, host in ((proxy_ip, 'proxy.example'), (ambiguous_ip, 'iprule.example'),
                                 (proxy_ip, 'direct.example')):
                    with self.assertRaises((urllib.error.URLError, OSError)):
                        request(ip, host)
                self.assertFalse(any(name in ('proxy.example', 'iprule.example') for name, _ in direct_dns.observations))
                proc.terminate(); proc.wait(timeout=5); proc = None
                config['outbounds'].extend([{'type':'selector', 'tag':'dns-proxy', 'outbounds':['dns-exit'], 'default':'dns-exit'},
                                            {'type':'direct', 'tag':'dns-exit'}])
                secure = next(x for x in config['dns']['servers'] if x.get('tag') == 'secure')
                secure.update(detour='dns-proxy', server_port=protected_dns.server_port)
                proc = start()
                ambiguous_ip = fake_query(dns_port, 'iprule.example')
                with self.assertRaises((urllib.error.URLError, OSError)):
                    request(ambiguous_ip, 'iprule.example')
                self.assertIn(('iprule.example', 1), protected_dns.observations)
                self.assertFalse(any(name == 'iprule.example' for name, _ in direct_dns.observations))
                proc.terminate(); proc.wait(timeout=5); proc = None
                self.assertIn('ip_cidr=1.2.3.0/24 => route(proxy)', log_path.read_text())
            finally:
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait(timeout=5)
                for server in (direct_dns, protected_dns, website):
                    server.shutdown(); server.server_close()
