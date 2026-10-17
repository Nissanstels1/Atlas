"""A FakeIP policy must answer service discovery promptly without real IP hints."""
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core


def current():
    result = core.defaults()
    result['subscriptions'] = [{'id': 'b' * 16, 'name': 'Test', 'enabled': True,
        'url': 'https://example.com/sub', 'nodes': [core.uri_node(
            'vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#Test')]}]
    result['settings'].update(fakeip=True, sections=[{'name': 'Video', 'policy': 'proxy',
        'domains': ['proxy.example'], 'cidrs': [], 'source_ips': [], 'exclude_domains': ['real.proxy.example']}],
        bypass_domains=['direct.proxy.example'], blocked_domains=['blocked.proxy.example'])
    return result


def question(name, kind):
    encoded = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', secrets.randbits(16), 0x100, 1, 0, 0, 0) + encoded + struct.pack('!HH', kind, 1)


def ask(port, name, kind, tcp=False):
    packet = question(name, kind)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(1.5)
        client.connect(('127.0.0.1', port))
        client.sendall(struct.pack('!H', len(packet)) + packet if tcp else packet)
        if tcp:
            def read_exact(count):
                data = b''
                while len(data) < count:
                    piece = client.recv(count - len(data))
                    if not piece: raise EOFError('DNS TCP closed before response')
                    data += piece
                return data
            reply = read_exact(struct.unpack('!H', read_exact(2))[0])
        else:
            reply = client.recv(4096)
    assert reply[:2] == packet[:2]
    return reply


class FakeIPRecords(unittest.TestCase):
    def test_fakeip_routes_accept_only_addresses_without_changing_route_policies(self):
        cfg = core.make_config(current())
        routes = [r for r in cfg['dns']['rules'] if r.get('server') == 'fakeip']
        self.assertTrue(routes)
        for rule in routes:
            conditions = rule.get('rules', [rule])
            self.assertTrue(any(r.get('query_type') == ['A', 'AAAA'] for r in conditions))
        self.assertTrue(any(r.get('outbound', '').startswith('section_') or r.get('outbound') == 'proxy'
                            for r in cfg['route']['rules']))

    @unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'), 'Set ATLAS_TEST_ENGINE')
    def test_native_udp_and_tcp_service_queries_return_without_fakeip_timeout(self):
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(('127.0.0.1', 0)); upstream.settimeout(.1)
        upstream_port = upstream.getsockname()[1]
        received = []; stop = threading.Event()
        def serve():
            while not stop.is_set():
                try: packet, source = upstream.recvfrom(4096)
                except socket.timeout: continue
                except OSError: return
                offset = 12; labels = []
                while packet[offset]:
                    size = packet[offset]; labels.append(packet[offset + 1:offset + 1 + size].decode()); offset += size + 1
                offset += 1; typ = struct.unpack('!H', packet[offset:offset + 2])[0]
                received.append(('.'.join(labels), typ))
                # TXT, HTTPS and SVCB deliberately have empty successful upstream answers.
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('192.0.2.7') if typ == 1 else b''
                upstream.sendto(packet[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(answer)), 0, 0) + packet[12:offset + 4] + answer, source)
        server = threading.Thread(target=serve, daemon=True); server.start()
        engine = None
        try:
            cfg = core.make_config(current(), tun=False)
            cfg['dns']['servers'] = [{'tag': x, 'type': 'udp', 'server': '127.0.0.1', 'server_port': upstream_port}
                for x in ('bootstrap', 'secure')] + [x for x in cfg['dns']['servers'] if x['tag'] == 'fakeip']
            cfg['dns']['independent_cache'] = True
            with socket.socket() as free: free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
            cfg['inbounds'] = [{'type': 'direct', 'tag': 'dns', 'listen': '127.0.0.1', 'listen_port': port}]
            cfg['outbounds'] = [{'type': 'direct', 'tag': 'proxy'}]
            cfg['route'] = {'default_domain_resolver': 'bootstrap',
                            'rules': [{'inbound': ['dns'], 'action': 'hijack-dns'}], 'final': 'proxy'}
            cfg['experimental'] = {'cache_file': {'enabled': False}}
            cfg['log'] = {'level': 'error'}
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'config.json'; config.write_text(json.dumps(cfg))
                checked = subprocess.run([os.environ['ATLAS_TEST_ENGINE'], 'check', '-c', str(config)], capture_output=True, text=True, timeout=8)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                with (Path(directory) / 'engine.log').open('wb') as log:
                    engine = subprocess.Popen([os.environ['ATLAS_TEST_ENGINE'], 'run', '-c', str(config)], stdout=log, stderr=log)
                    for _ in range(50):
                        try: reply = ask(port, 'video.proxy.example', 1); break
                        except (OSError, EOFError):
                            self.assertIsNone(engine.poll()); time.sleep(.02)
                    else: self.fail('Diagnostic DNS engine did not become ready')
                    self.assertEqual(struct.unpack('!H', reply[2:4])[0] & 15, 0)
                    self.assertIn(ipaddress.ip_address(reply[-4:]), ipaddress.ip_network('198.18.0.0/15'))
                    for tcp in (False, True):
                        for name, typ in [('video.proxy.example', 65), ('video.proxy.example', 64), ('video.proxy.example', 16),
                                          ('real.proxy.example', 65), ('direct.proxy.example', 65), ('ordinary.example', 65)]:
                            with self.subTest(tcp=tcp, name=name, typ=typ):
                                start = time.monotonic(); answer = ask(port, name, typ, tcp)
                                self.assertLess(time.monotonic() - start, 1)
                                header = struct.unpack('!HHHHHH', answer[:12])
                                self.assertEqual(header[1] & 15, 0); self.assertEqual(header[3], 0)
                    self.assertNotIn(('video.proxy.example', 65), received)
                    self.assertNotIn(('video.proxy.example', 64), received)
                    self.assertIn(('video.proxy.example', 16), received)
                    for name in ('real.proxy.example', 'direct.proxy.example', 'ordinary.example'):
                        self.assertIn((name, 65), received)
                    blocked = ask(port, 'blocked.proxy.example', 1)
                    self.assertEqual(struct.unpack('!H', blocked[2:4])[0] & 15, 5)
                    engine.terminate(); engine.wait(timeout=8); engine = None
                self.assertNotIn('only IP queries are supported by fakeip', (Path(directory) / 'engine.log').read_text())
        finally:
            if engine:
                engine.terminate(); engine.wait(timeout=8)
            stop.set(); upstream.close(); server.join(timeout=2)


if __name__ == '__main__': unittest.main(verbosity=2)
