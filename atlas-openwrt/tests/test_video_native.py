"""Real-engine proof that section test destinations retain independent RTTs."""
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
import engine_features
from test_independent_sections import sec


class VideoNative(unittest.TestCase):
    def test_section_targets_keep_distinct_measurements_across_rounds(self):
        binary = os.environ.get('ATLAS_EXTENSION_ENGINE')
        if not binary:
            self.skipTest('Set ATLAS_EXTENSION_ENGINE to run real URLTest isolation')
        features = engine_features.capabilities(binary)
        self.assertIn('urltest.background', features)
        counts = {'/main': 0, '/fast': 0, '/slow': 0}
        lock = threading.Lock()
        class Target(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path not in counts:
                    self.send_error(404)
                    return
                with lock:
                    counts[self.path] += 1
                # Keep a wide gap: QEMU icount may advance the guest's Go
                # monotonic clock differently from Python's sleep/wall clock.
                # The assertion below compares destinations rather than
                # requiring the reported RTT to equal this sleep duration.
                time.sleep(.8 if self.path == '/slow' else .02)
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *args):
                pass
        target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            current = core.defaults()
            current['subscriptions'] = [{'id': 'a' * 16, 'name': 'fixture', 'source': 'local', 'enabled': True,
                'nodes': [core.uri_node('http://127.0.0.1:9#fixture')]}]
            current['settings']['sections'] = [
                sec('Fast', id='b' * 16, urltest_url='https://fast.example.org/check'),
                sec('Slow', id='c' * 16, urltest_url='https://slow.example.org/check')]
            with mock.patch.object(engine_features, 'capabilities', return_value=features):
                config = core.make_config(current, tun=False, api_secret='a' * 64)
            # The production generator establishes member identities. All test
            # traffic then stays on loopback; no real proxy or website is used.
            config['inbounds'] = []
            config['route']['rules'] = []
            groups = {item['tag']: item for item in config['outbounds'] if item['type'] == 'urltest'}
            targets = {'auto': '/main', 'section_' + 'b' * 16 + '_auto': '/fast', 'section_' + 'c' * 16 + '_auto': '/slow'}
            for tag, path in targets.items():
                groups[tag].update(url='http://127.0.0.1:%d%s' % (target.server_port, path), interval='1s', idle_timeout='1s')
            for outbound in config['outbounds']:
                if outbound['type'] == 'http':
                    tag = outbound['tag']
                    outbound.clear()
                    outbound.update(type='direct', tag=tag)
            first = groups['section_' + 'b' * 16 + '_auto']['outbounds'][0]
            second = groups['section_' + 'c' * 16 + '_auto']['outbounds'][0]
            self.assertNotEqual(first, second)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            config['experimental']['cache_file']['enabled'] = False
            config['experimental']['clash_api'].update(external_controller='127.0.0.1:%d' % port, secret='fixture')
            def snapshot():
                request = urllib.request.Request('http://127.0.0.1:%d/proxies' % port, headers={'Authorization': 'Bearer fixture'})
                with urllib.request.urlopen(request, timeout=2) as response:
                    return json.load(response)['proxies']
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps(config), encoding='utf-8')
                log_path = Path(directory) / 'engine.log'
                with log_path.open('wb') as log:
                    process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 15
                        value = {}
                        initial_stamps = None
                        while time.monotonic() < deadline:
                            try:
                                value = snapshot()
                                one = value.get(first, {}).get('history', [])
                                two = value.get(second, {}).get('history', [])
                                with lock:
                                    renewed = counts['/fast'] >= 2 and counts['/slow'] >= 2
                                if one and two:
                                    stamps = (one[-1]['time'], two[-1]['time'])
                                    if initial_stamps is None:
                                        initial_stamps = stamps
                                    elif renewed and all(latest != original for latest, original in zip(stamps, initial_stamps)):
                                        break
                            except (OSError, ValueError):
                                pass
                            if process.poll() is not None:
                                self.fail('Fixture engine stopped: ' + log_path.read_text(encoding='utf-8', errors='replace')[-2000:])
                            time.sleep(.05)
                        else:
                            self.fail('Distinct target measurements not renewed: ' + log_path.read_text(encoding='utf-8', errors='replace')[-2000:])
                        fast = value[first]['history'][-1]['delay']
                        slow = value[second]['history'][-1]['delay']
                        self.assertGreaterEqual(slow - fast, 90, 'Distinct targets must retain a substantial RTT difference: fast=%d slow=%d' % (fast, slow))
                        print('NATIVE: distinct section URLs called repeatedly; both histories renewed; isolated RTTs fast=%dms slow=%dms' % (fast, slow))
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        process.wait(timeout=10)
        finally:
            target.shutdown()
            target.server_close()
