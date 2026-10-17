"""Repeated API calls must stay cheap without stale credentials or false RSS."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas


def config(secret='a' * 64, generation='1' * 32):
    return {'outbounds': [{'tag': 'atlas_run_' + generation + '_' + 'b' * 32, 'type': 'direct'}],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:19090', 'secret': secret}}}


class APIConfigSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root / 'config.json'; self.path.write_text(json.dumps(config()))
        self.patches = [mock.patch.object(atlas, 'CONFIG', self.path), mock.patch.object(atlas, '_api_config_cache', None)]
        for p in self.patches: p.start()
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_many_requests_parse_once_and_do_not_mutate_the_config(self):
        count = []; original = json.loads
        before = self.path.read_bytes()
        def decoded(body, *a, **kw):
            if isinstance(body, bytes) and body == before: count.append(1)
            return original(body, *a, **kw)
        connection = mock.Mock(); response = connection.getresponse.return_value
        response.status = 200; response.read.return_value = b'{"delay":123}'
        with mock.patch.object(atlas.json, 'loads', decoded), mock.patch.object(atlas.http.client, 'HTTPConnection', return_value=connection):
            for _ in range(30):
                self.assertEqual(atlas.clash_request('GET', '/proxies/' + 'b' * 32 + '/delay')['delay'], 123)
        self.assertEqual(len(count), 1)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(all('atlas_run_' + '1' * 32 in x.args[1] for x in connection.request.call_args_list))

    def test_atomic_replacement_with_same_size_and_mtime_changes_credentials(self):
        self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'a' * 64)
        info = self.path.stat(); pending = self.root / 'replacement'
        pending.write_text(json.dumps(config('c' * 64, '2' * 32)))
        self.assertEqual(pending.stat().st_size, info.st_size)
        os.utime(pending, ns=(info.st_atime_ns, info.st_mtime_ns)); os.replace(pending, self.path)
        connection = mock.Mock(); response = connection.getresponse.return_value
        response.status = 204; response.read.return_value = b''
        with mock.patch.object(atlas.http.client, 'HTTPConnection', return_value=connection):
            atlas.clash_request('PUT', '/proxies/' + 'b' * 32, {'name': 'b' * 32})
        request = connection.request.call_args
        self.assertIn('atlas_run_' + '2' * 32, request.args[1])
        self.assertEqual(request.kwargs['headers']['Authorization'], 'Bearer ' + 'c' * 64)
        self.assertIn('atlas_run_' + '2' * 32, request.kwargs['body'].decode())

    def test_in_place_change_deletion_and_invalid_json_never_reuse_old_data(self):
        atlas.active_api_config(); self.path.write_text(json.dumps(config('new-longer-secret')))
        self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'new-longer-secret')
        self.path.unlink(); self.assertEqual(atlas.active_api_config(), {})
        self.assertIsNone(atlas._api_config_cache)
        self.path.write_text('{broken')
        with self.assertRaises(ValueError): atlas.active_api_config()
        self.assertIsNone(atlas._api_config_cache)
        self.path.write_text(json.dumps(config('recovered')))
        self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'recovered')

    def test_change_during_read_does_not_reuse_old_content_on_next_request(self):
        original = Path.read_bytes; replaced = []
        def read(path, *a, **kw):
            body = original(path, *a, **kw)
            if path == self.path and not replaced:
                replaced.append(True); pending = self.root / 'replacement'
                pending.write_text(json.dumps(config('second'))); os.replace(pending, self.path)
            return body
        with mock.patch.object(Path, 'read_bytes', read):
            self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'a' * 64)
            self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'second')

    def test_in_place_same_size_change_with_restored_mtime_uses_ctime(self):
        atlas.active_api_config(); before = self.path.stat()
        self.path.write_text(json.dumps(config('c' * 64)))
        self.assertEqual(self.path.stat().st_size, before.st_size)
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'c' * 64)

    def test_only_latest_path_and_generation_are_retained(self):
        for i in range(12):
            path = self.root / ('config%d.json' % i); path.write_text(json.dumps(config('secret%d' % i)))
            with mock.patch.object(atlas, 'CONFIG', path):
                self.assertEqual(atlas.active_api_config()['experimental']['clash_api']['secret'], 'secret%d' % i)
        self.assertEqual(len(atlas._api_config_cache), 2)
        self.assertEqual(atlas._api_config_cache[0][0], str(path))
        self.assertNotIn('secret0', repr(atlas._api_config_cache))


class EngineRSS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.proc = Path(self.temp.name)
        self.binary = '/fixture/atlas-engine'
        self.result = mock.Mock(returncode=0, stdout=json.dumps({'atlas': {'instances': {'instance1': {'pid': 100}}}}))
        self.patches = [mock.patch.object(atlas, 'BINARY', self.binary), mock.patch.object(atlas, 'run', return_value=self.result)]
        for p in self.patches: p.start()
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()
    def process(self, pid, parent, rss, executable=None, ticks='123'):
        p = self.proc / str(pid); p.mkdir(exist_ok=True)
        (p / 'stat').write_text(str(pid) + ' (process with spaces) S ' + '0 ' * 18 + ticks)
        (p / 'status').write_text('PPid:\t%d\nVmRSS:\t%d kB\n' % (parent, rss))
        (p / 'exe').symlink_to(executable or self.binary)
        return p
    def supervisor(self):
        p = self.process(100, 1, 90000, '/usr/bin/python3')
        folder = p / 'task' / '100'; folder.mkdir(parents=True)
        (folder / 'children').write_text('101 102')

    def test_supervisor_rss_is_excluded_and_real_child_is_measured(self):
        self.supervisor(); self.process(101, 100, 12345)
        self.process(102, 100, 80000, '/usr/bin/python3')
        self.assertEqual(atlas.process_memory(self.proc), {'inuse': 12345 * 1024})

    def test_direct_legacy_engine_and_deleted_running_binary_are_supported(self):
        self.process(100, 1, 12345, self.binary + ' (deleted)')
        self.assertEqual(atlas.process_memory(self.proc), {'inuse': 12345 * 1024})

    def test_missing_or_unrelated_child_stays_unknown_not_supervisor_usage(self):
        self.supervisor(); self.process(101, 999, 12345)
        self.assertEqual(atlas.process_memory(self.proc), {})

    def test_openwrt_without_children_file_still_checks_parent_and_binary(self):
        self.process(100, 1, 90000, '/usr/bin/python3')
        self.process(101, 100, 12345); self.process(102, 999, 80000)
        with mock.patch.object(atlas, 'run', side_effect=[self.result, mock.Mock(returncode=0, stdout=b'101 102')]):
            self.assertEqual(atlas.process_memory(self.proc), {'inuse': 12345 * 1024})

    def test_reused_pid_is_not_reported(self):
        self.supervisor(); p = self.process(101, 100, 12345)
        original = Path.read_text; reads = []
        def read(path, *a, **kw):
            value = original(path, *a, **kw)
            if path == p / 'stat':
                reads.append(1)
                if len(reads) > 1: return value[:-3] + '456'
            return value
        with mock.patch.object(Path, 'read_text', read):
            self.assertEqual(atlas.process_memory(self.proc), {})

    def test_multiple_instances_count_each_owned_engine_once(self):
        self.process(100, 1, 90000, '/usr/bin/python3'); self.process(200, 1, 90000, '/usr/bin/python3')
        self.process(101, 100, 12345); self.process(201, 200, 23456)
        services = mock.Mock(returncode=0, stdout=json.dumps({'atlas': {'instances': {'one': {'pid': 100}, 'two': {'pid': 200}}}}))
        pids = mock.Mock(returncode=0, stdout=b'101 201')
        with mock.patch.object(atlas, 'run', side_effect=[services, pids, pids]):
            self.assertEqual(atlas.process_memory(self.proc), {'inuse': (12345 + 23456) * 1024})


if __name__ == '__main__': unittest.main(verbosity=2)
