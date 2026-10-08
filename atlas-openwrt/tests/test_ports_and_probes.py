import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
from probes import probe_batch, probe_workers


def configuration(**changes):
    state = core.defaults()
    state['settings']['fakeip'] = True
    state['subscriptions'] = [{'id': 'b' * 16, 'enabled': True, 'name': 'test',
                               'nodes': [core.uri_node('trojan://password@example.com:443#test')]}]
    section = dict(name='ports', policy='block', domains=[], cidrs=[], source_ips=[])
    section.update(changes)
    state['settings']['sections'] = [section]
    return core.make_config(state)


class Ports(unittest.TestCase):
    def test_ports_only_match_alternatives_not_intersection(self):
        config = configuration(ports=['443', '10000-20000'])
        rule = next(r for r in config['route']['rules'] if r.get('type') == 'logical')
        self.assertEqual(rule['mode'], 'or')
        self.assertEqual(rule['rules'], [{'port': [443]}, {'port_range': ['10000:20000']}])
        self.assertEqual(rule['action'], 'reject')

    def test_device_transport_and_ports_are_combined(self):
        config = configuration(source_ips=['192.168.1.25'], networks=['udp'], ports=['443', '10000-20000'])
        rule = next(r for r in config['route']['rules'] if r.get('type') == 'logical')
        self.assertEqual(rule['mode'], 'and')
        self.assertEqual(rule['rules'][0], {'source_ip_cidr': ['192.168.1.25/32'], 'network': ['udp']})

    def test_invalid_ports_and_networks_are_rejected(self):
        for ports in [['0'], ['65536'], ['200-100'], ['443:445'], [True], '443']:
            with self.subTest(ports=ports), self.assertRaises(core.AtlasError):
                configuration(ports=ports)
        with self.assertRaises(core.AtlasError):
            configuration(networks=['icmp'])

    def test_port_block_does_not_block_domain_dns(self):
        config = configuration(domains=['example.org'], ports=['443'])
        self.assertFalse(any(r.get('domain_suffix') == ['example.org'] for r in config['dns']['rules']))

    def test_old_section_has_no_new_matchers(self):
        config = configuration(domains=['example.org'])
        rule = next(r for r in config['route']['rules'] if r.get('domain_suffix') == ['example.org'])
        self.assertNotIn('port', rule)
        self.assertNotIn('network', rule)

    def test_diagnostics_do_not_open_service_cache(self):
        node = core.uri_node('trojan://password@example.com:443#test')
        config = core.make_config(core.defaults(), tun=False, probe_node=node)
        self.assertFalse(config['experimental']['cache_file']['enabled'])


class Probes(unittest.TestCase):
    def test_memory_budget_and_unknown_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'meminfo'
            self.assertEqual(probe_workers(path), 1)
            for available, expected in [(0, 1), (262143, 1), (262144, 2)]:
                path.write_text('MemAvailable: %d kB\n' % available)
                self.assertEqual(probe_workers(path), expected)

    def test_bounded_concurrency_and_all_results(self):
        active = peak = 0
        lock = threading.Lock()
        def check(node):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.02)
            with lock:
                active -= 1
            return {'ok': True}
        results = list(probe_batch(list(range(10)), check, workers=100))
        self.assertEqual(sorted(n for n, _ in results), list(range(10)))
        self.assertEqual(peak, 2)

    def test_failed_node_does_not_abort_or_expose_secrets(self):
        def check(node):
            if node == 1:
                raise RuntimeError('secret credential')
            return {'ok': True}
        for workers in (1, 2):
            results = dict(probe_batch([0, 1, 2], check, workers))
            self.assertTrue(results[2]['ok'])
            self.assertFalse(results[1]['ok'])
            self.assertNotIn('secret', str(results))


if __name__ == '__main__':
    unittest.main()
