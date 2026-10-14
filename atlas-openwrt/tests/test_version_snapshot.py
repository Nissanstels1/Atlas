"""Bounded request-local engine metadata, including upgrades and transient errors."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,engine_features


class VersionSnapshot(unittest.TestCase):
    def setUp(self):
        engine_features._version_cache.clear()
        self.temp=tempfile.TemporaryDirectory();self.binary=Path(self.temp.name)/'engine'
        self.binary.write_bytes(b'fixture')
        self.reply=subprocess.CompletedProcess([],0,'sing-box version fixture\nFeatures: clash.download_test,urltest.background\n')
    def tearDown(self):
        engine_features._version_cache.clear();self.temp.cleanup()

    def test_version_and_many_feature_reads_launch_engine_once(self):
        with mock.patch.object(atlas,'BINARY',str(self.binary)),mock.patch.object(engine_features.subprocess,'run',return_value=self.reply) as run:
            self.assertEqual(atlas.engine_version(),'sing-box version fixture')
            for _ in range(30):self.assertIn('urltest.background',engine_features.capabilities(self.binary))
        self.assertEqual(run.call_count,1)

    def test_replacement_and_in_place_modification_invalidate(self):
        with mock.patch.object(engine_features.subprocess,'run',return_value=self.reply) as run:
            engine_features.capabilities(self.binary)
            replacement=self.binary.with_name('replacement');replacement.write_bytes(b'new');os.replace(replacement,self.binary)
            engine_features.capabilities(self.binary)
            self.binary.write_bytes(b'new-longer')
            engine_features.capabilities(self.binary)
        self.assertEqual(run.call_count,3)

    def test_expiry_and_clock_reset_recheck(self):
        with mock.patch.object(engine_features.subprocess,'run',return_value=self.reply) as run,mock.patch.object(engine_features.time,'monotonic',return_value=10) as clock:
            engine_features.capabilities(self.binary)
            clock.return_value=41;engine_features.capabilities(self.binary)
            clock.return_value=1;engine_features.capabilities(self.binary)
        self.assertEqual(run.call_count,3)

    def test_missing_binary_does_not_return_old_features(self):
        with mock.patch.object(engine_features.subprocess,'run',return_value=self.reply) as run:
            engine_features.capabilities(self.binary);self.binary.unlink()
            run.side_effect=FileNotFoundError
            self.assertEqual(engine_features.capabilities(self.binary),[])
        self.assertEqual(len(engine_features._version_cache),0)

    def test_failure_is_not_cached_and_success_can_recover_immediately(self):
        for failed in (subprocess.CompletedProcess([],1,'invalid'),subprocess.TimeoutExpired('version',3),UnicodeError('invalid')):
            engine_features._version_cache.clear()
            with mock.patch.object(engine_features.subprocess,'run',side_effect=[failed,self.reply]) as run:
                self.assertEqual(engine_features.capabilities(self.binary),[])
                self.assertIn('urltest.background',engine_features.capabilities(self.binary))
                self.assertEqual(run.call_count,2)

    def test_cache_is_bounded_and_results_are_independent(self):
        with mock.patch.object(engine_features.subprocess,'run',return_value=self.reply):
            for i in range(12):
                path=self.binary.with_name('engine'+str(i));path.write_bytes(b'fixture')
                engine_features.capabilities(path)
            self.assertEqual(len(engine_features._version_cache),4)
            features=engine_features.capabilities(path);features.clear()
            self.assertIn('urltest.background',engine_features.capabilities(path))
