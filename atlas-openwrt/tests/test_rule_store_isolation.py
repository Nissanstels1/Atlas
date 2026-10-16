"""A downloaded list must not depend on other lists awaiting their first fetch."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core


class RuleStoreIsolation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [mock.patch.object(atlas, 'DATA', self.root),
                        mock.patch.object(atlas, 'RUN', self.root)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def current(self):
        value = core.defaults()
        value['settings']['remote_lists'] = [
            dict(id=character * 16, name=character,
                 url='https://example.org/' + character + '.srs',
                 format='srs', policy='direct', enabled=True)
            for character in ('a', 'b')]
        value['settings'] = core.validate_settings(value['settings'])
        return value

    def check_files(self, config):
        """The engine refuses a config whose local rule-set file is missing."""
        definitions = config.get('route', {}).get('rule_set', [])
        self.assertTrue(definitions)
        for item in definitions:
            if item.get('type') == 'local':
                body = Path(item['path']).read_bytes()
                if body.startswith(b'invalid'):
                    raise core.AtlasError('Invalid rule-set fixture')

    def test_two_new_binary_lists_can_be_fetched_in_one_update(self):
        current = self.current()
        with mock.patch.object(atlas, 'check', side_effect=self.check_files):
            for item in current['settings']['remote_lists']:
                self.assertTrue(atlas.store_rule_set(current, item, b'valid binary fixture'))
        for item in current['settings']['remote_lists']:
            self.assertTrue(item['srs_cached'])
            self.assertEqual((self.root / 'rules' / (item['id'] + '.srs')).read_bytes(),
                             b'valid binary fixture')

    def test_invalid_new_list_does_not_prevent_another_list_from_loading(self):
        current = self.current()
        first, second = current['settings']['remote_lists']
        before = copy.deepcopy(first)
        with mock.patch.object(atlas, 'check', side_effect=self.check_files):
            with self.assertRaises(core.AtlasError):
                atlas.store_rule_set(current, first, b'invalid binary fixture')
            self.assertTrue(atlas.store_rule_set(current, second, b'valid binary fixture'))
        self.assertEqual(first, before)
        self.assertFalse((self.root / 'rules' / (first['id'] + '.srs')).exists())
        self.assertTrue(second['srs_cached'])

    def test_failed_replacement_preserves_existing_binary_and_metadata(self):
        current = self.current()
        item = current['settings']['remote_lists'][0]
        item.update(srs_cached=True, updated=123, count=19)
        path = self.root / 'rules' / (item['id'] + '.srs')
        atlas.atomic_bytes(path, b'old working fixture')
        before = copy.deepcopy(item)
        with mock.patch.object(atlas, 'check', side_effect=self.check_files):
            with self.assertRaises(core.AtlasError):
                atlas.store_rule_set(current, item, b'invalid replacement')
        self.assertEqual(item, before)
        self.assertEqual(path.read_bytes(), b'old working fixture')

    def test_json_is_validated_even_when_other_binary_list_is_unavailable(self):
        current = self.current()
        item = current['settings']['remote_lists'][0]
        item.update(format='json', url='https://example.org/a.json')
        payload = {'version': 3, 'rules': [{'domain_suffix': ['example.org']}]}
        body = json.dumps(payload).encode()
        with mock.patch.object(atlas, 'validate_source_rules') as validate, \
                mock.patch.object(atlas, 'check', side_effect=self.check_files):
            self.assertTrue(atlas.store_rule_set(current, item, body, source=True))
        validate.assert_called_once_with(body)
        self.assertEqual(item['source_rules'], payload)
        self.assertTrue(item['source_cached'])
        self.assertFalse(item['srs_cached'])

    @unittest.skipUnless(os.environ.get('ATLAS_RULE_ENGINE'), 'Set ATLAS_RULE_ENGINE')
    def test_actual_engine_checks_two_new_srs_without_loading_other_sources(self):
        engine = os.environ['ATLAS_RULE_ENGINE']
        source = self.root / 'source.json'
        compiled = self.root / 'source.srs'
        source.write_text(json.dumps({'version': 3, 'rules': [
            {'domain_suffix': ['example.org']}]}))
        result = subprocess.run([engine, 'rule-set', 'compile', str(source), '-o', str(compiled)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        current = self.current()
        with mock.patch.object(atlas, 'BINARY', engine):
            for item in current['settings']['remote_lists']:
                self.assertTrue(atlas.store_rule_set(current, item, compiled.read_bytes()))
        self.assertTrue(all(item['srs_cached'] for item in current['settings']['remote_lists']))


if __name__ == '__main__':
    unittest.main()
