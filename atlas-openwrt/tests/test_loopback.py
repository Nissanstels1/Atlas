"""Real sing-box processes and loopback proxies, without a router or Internet.

The Linux TUN inbound is replaced for this host test. This does not test fw4,
dnsmasq, LAN clients or the WAN. Set ATLAS_TEST_ENGINE to the engine binary.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Fixture(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        first = self.rfile.readline(4096)
        while self.rfile.readline(4096) not in (b'\r\n', b'\n', b''):
            pass
        if not first.startswith(b'CONNECT '):
            return
        self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
        self.wfile.flush()
        self.rfile.readline(4096)
        while self.rfile.readline(4096) not in (b'\r\n', b'\n', b''):
            pass
        self.server.requests += 1
        body = self.server.marker
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
        self.wfile.flush()


@unittest.skipUnless(os.environ.get('ATLAS_TEST_ENGINE'), 'Set ATLAS_TEST_ENGINE for real loopback engine tests')
class Loopback(unittest.TestCase):
    def test_two_section_proxies_authentication_and_route_isolation(self):
        servers, threads = [], []
        process = None
        with tempfile.TemporaryDirectory() as directory:
            try:
                for marker in (b'fixture-A', b'fixture-B'):
                    server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Fixture)
                    server.daemon_threads=True;server.marker=marker;server.requests=0
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    servers.append(server);threads.append(thread)
                ports=[]
                while len(ports)<3:
                    candidate=free_port()
                    if candidate not in ports and candidate not in (19090,):ports.append(candidate)
                state=core.defaults()
                for index,server in enumerate(servers):
                    state['settings']['sections'].append(dict(name='fixture%d'%index,policy='proxy',domains=[],cidrs=[],source_ips=[],
                        outbound_config=[{'type':'http','tag':'entry','server':'127.0.0.1','server_port':server.server_address[1]}],
                        mixed_proxy={'enabled':True,'listen':'127.0.0.1','port':ports[index], 'username':'fixture','password':'fixture-password'}))
                config=core.make_config(state)
                config['inbounds'][0]={'type':'mixed','tag':'local','listen':'127.0.0.1','listen_port':ports[2]}
                config['experimental']={'cache_file':{'enabled':False}}
                config['route']['final']='policy-block'
                path=Path(directory)/'config.json';path.write_text(json.dumps(config),encoding='utf-8')
                check=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(path)],capture_output=True)
                self.assertEqual(check.returncode,0,check.stderr.decode(errors='replace'))
                with (Path(directory)/'engine.log').open('wb') as log:
                    process=subprocess.Popen([os.environ['ATLAS_TEST_ENGINE'],'run','-c',str(path)],stdout=log,stderr=log)
                    for _ in range(50):
                        if process.poll() is not None:
                            self.fail('Loopback engine exited during startup')
                        try:
                            with socket.create_connection(('127.0.0.1',ports[0]),timeout=.1):break
                        except OSError:time.sleep(.1)
                    else:self.fail('Loopback inbound did not become ready')
                    auth='Basic '+base64.b64encode(b'fixture:fixture-password').decode()
                    for index,marker in enumerate((b'fixture-A',b'fixture-B')):
                        connection=http.client.HTTPConnection('127.0.0.1',ports[index],timeout=5)
                        try:
                            connection.request('GET','http://example.invalid/test',headers={'Proxy-Authorization':auth})
                            response=connection.getresponse()
                            self.assertEqual(response.status,200);self.assertEqual(response.read(),marker)
                        finally:connection.close()
                    connection=http.client.HTTPConnection('127.0.0.1',ports[0],timeout=5)
                    try:
                        connection.request('GET','http://example.invalid/test')
                        response=connection.getresponse();self.assertEqual(response.status,407);response.read()
                    finally:connection.close()
                    before=[server.requests for server in servers]
                    connection=http.client.HTTPConnection('127.0.0.1',ports[2],timeout=5)
                    try:
                        connection.request('GET','http://example.invalid/test')
                        try:
                            response=connection.getresponse();self.assertNotEqual(response.status,200);response.read()
                        except (OSError,http.client.HTTPException):pass
                    finally:connection.close()
                    self.assertEqual([server.requests for server in servers],before)
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                for server in servers:server.shutdown();server.server_close()
                for thread in threads:thread.join(timeout=2)


if __name__=='__main__':unittest.main()
