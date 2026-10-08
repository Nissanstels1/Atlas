import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
from maintenance import prune_artifacts


class Maintenance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / 'data'; self.data.mkdir()
        self.run = self.root / 'run'; self.run.mkdir()
        self.rules = self.data / 'rules'; self.rules.mkdir()
        self.cfg = self.run / 'config.json'
        self.current = core.defaults()

    def tearDown(self):
        self.tmp.cleanup()

    def rule(self, sid):
        path = self.rules / (sid * 16 + '.srs'); path.write_bytes(b'fixture')
        return path

    def test_keeps_saved_running_boot_and_rollback_rules(self):
        paths = [self.rule(x) for x in 'abcde']
        self.current['settings']['remote_lists'] = [{'id': 'a' * 16}]
        for path, rule in zip((self.cfg, self.data / 'active.json', self.data / 'last-good.json'), paths[1:4]):
            path.write_text(json.dumps({'route': {'rule_set': [{'path': str(rule)}]}}))
        self.assertEqual(prune_artifacts(self.current, self.data, self.run, self.cfg)['removed'], 1)
        self.assertTrue(all(x.exists() for x in paths[:4])); self.assertFalse(paths[4].exists())

    def test_repeated_churn_does_not_accumulate_orphan_files(self):
        for _ in range(100):
            self.rule('f')
            (self.run / ('section-check-' + 'f' * 16 + '.json')).write_text('{}')
            prune_artifacts(self.current, self.data, self.run, self.cfg)
        self.assertEqual(list(self.rules.iterdir()), [])
        self.assertEqual(list(self.run.glob('section-check-*')), [])

    def test_unknown_files_and_unreadable_deployed_config_are_preserved(self):
        owned = self.rule('f'); other = self.rules / 'user.srs'; other.write_bytes(b'owned-by-user')
        self.cfg.write_text('broken')
        self.assertIn('skipped', prune_artifacts(self.current, self.data, self.run, self.cfg))
        self.assertTrue(owned.exists()); self.assertTrue(other.exists())

    def test_external_rollback_rules_are_preserved(self):
        external = self.root / 'external'; external.mkdir()
        self.current['settings'].update(config_storage='external', config_custom_dir=str(external))
        rule = self.rule('a')
        (external / 'last-good.json').write_text(json.dumps({'route': {'rule_set': [{'path': str(rule)}]}}))
        prune_artifacts(self.current, self.data, self.run, self.cfg)
        self.assertTrue(rule.exists())

    def test_probe_records_for_removed_nodes_are_trimmed_and_persisted(self):
        node = core.uri_node('socks5://127.0.0.1:1080#fixture')
        self.current['subscriptions'] = [{'id': 'a' * 16, 'nodes': [node], 'enabled': False}]
        key = 'a' * 16 + node['id']
        checks = self.run / 'checks.json'; checks.write_text(json.dumps({key: {'ok': True}, 'old': {'ok': False}}))
        with mock.patch.object(atlas, 'DATA', self.data), mock.patch.object(atlas, 'RUN', self.run), mock.patch.object(atlas, 'CONFIG', self.cfg):
            atlas.maintain_artifacts(self.current)
        self.assertEqual(json.loads(checks.read_text()), {key: {'ok': True}})

    def test_filesystem_failure_does_not_mask_successful_commit(self):
        with mock.patch.object(atlas, 'prune_artifacts', side_effect=PermissionError()):
            self.assertEqual(atlas.maintain_artifacts(self.current), {'skipped': 'filesystem-error'})
