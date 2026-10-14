"""Refresh without needless restarts, retry storms or recycled-worker confusion."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
from test_core import state_with_node, REALITY


class RefreshReliability(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [mock.patch.object(atlas, 'RUN', self.root),
                        mock.patch.object(atlas, 'DATA', self.root),
                        mock.patch.object(atlas, 'STATE', self.root / 'state.json'),
                        mock.patch.object(atlas, 'CONFIG', self.root / 'config.json'),
                        mock.patch.object(atlas, 'maintain_artifacts')]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temp.cleanup()

    def test_304_does_not_restart_running_engine(self):
        current = state_with_node()
        with mock.patch.object(atlas, 'fetch', return_value=(b'', {}, 'etag', '', True)), mock.patch.object(atlas, 'apply') as apply:
            message = atlas.refresh(current)
        apply.assert_not_called()
        self.assertIn('перезапуск не нужен', message)
        self.assertGreater(current['subscriptions'][0]['updated'], 0)

    def test_same_profiles_with_new_metadata_do_not_restart(self):
        current = state_with_node()
        with mock.patch.object(atlas, 'fetch', return_value=(REALITY.encode(), {'upload':123}, '', '', False)), mock.patch.object(atlas, 'check'), mock.patch.object(atlas, 'apply') as apply:
            atlas.refresh(current)
        apply.assert_not_called()
        self.assertEqual(current['subscriptions'][0]['metadata'], {'upload':123})

    def test_changed_profile_restarts_once_and_preserves_previous_on_fetch_error(self):
        current = state_with_node()
        with mock.patch.object(atlas, 'fetch', return_value=(REALITY.replace('example.com', 'new.example').encode(), {})), mock.patch.object(atlas, 'check'), mock.patch.object(atlas, 'service_running', return_value=True), mock.patch.object(atlas, 'apply') as apply:
            atlas.refresh(current)
        apply.assert_called_once()
        before = copy.deepcopy(current['subscriptions'][0]['nodes'])
        with mock.patch.object(atlas, 'fetch', side_effect=core.AtlasError('offline')), mock.patch.object(atlas, 'apply') as apply, self.assertRaises(core.AtlasError):
            atlas.refresh(current)
        apply.assert_not_called()
        self.assertEqual(current['subscriptions'][0]['nodes'], before)

    def test_automatic_retry_backoff_and_manual_retry(self):
        current = state_with_node()
        with mock.patch.object(atlas, 'time') as clock, mock.patch.object(atlas, 'fetch', side_effect=core.AtlasError('offline')) as fetch:
            clock.time.return_value=10000; clock.monotonic.return_value=100
            with self.assertRaises(core.AtlasError): atlas.refresh(current, due_only=True)
            clock.monotonic.return_value=120
            atlas.refresh(current, due_only=True)
            self.assertEqual(fetch.call_count, 1)
            with self.assertRaises(core.AtlasError): atlas.refresh(current)  # User retries immediately.
            retry = json.loads((self.root/'refresh-retries.json').read_text())
            self.assertEqual(next(iter(retry.values()))['delay'], 120)
            clock.monotonic.return_value=240
            with self.assertRaises(core.AtlasError): atlas.refresh(current, due_only=True)
            self.assertEqual(fetch.call_count, 3)

    def test_scheduler_skips_current_sources_when_one_fails(self):
        current = state_with_node()
        second=copy.deepcopy(current['subscriptions'][0]); second.update(id='c'*16, updated=10000)
        current['subscriptions'].append(second)
        with mock.patch.object(atlas.time, 'time', return_value=10000), mock.patch.object(atlas, 'fetch', side_effect=core.AtlasError('offline')) as fetch, self.assertRaises(core.AtlasError):
            atlas.refresh(current, due_only=True)
        self.assertEqual(fetch.call_count, 1)

    def test_retry_recovers_clock_reset_and_url_edit(self):
        source=state_with_node()['subscriptions'][0];source['updated']=20000
        self.assertTrue(atlas.source_due(source, 3600, {'attempted':500,'delay':900}, now=10000, monotonic=10))
        old=atlas.refresh_source_key('subscription', source)
        source['url']='https://other.example/list'
        self.assertNotEqual(atlas.refresh_source_key('subscription', source), old)

    def test_changed_local_file_bypasses_retry_pause(self):
        source={'url':'file:///tmp/owned.txt','file_version':'old','updated':10000}
        with mock.patch.object(atlas, 'local_rule_version', return_value='new'):
            self.assertTrue(atlas.source_due(source, 3600, {'attempted':100,'delay':900}, now=10000, monotonic=120))

    def test_success_clears_retry_and_deleted_sources_are_pruned(self):
        current=state_with_node();key=atlas.refresh_source_key('subscription',current['subscriptions'][0])
        atlas.atomic(self.root/'refresh-retries.json',{key:{'attempted':0,'delay':0,'failures':5},'deleted':{}})
        with mock.patch.object(atlas,'fetch',return_value=(b'',{},'', '',True)):
            atlas.refresh(current)
        self.assertEqual(json.loads((self.root/'refresh-retries.json').read_text()),{})

    def test_same_failed_local_version_respects_pause_and_retries_after_it(self):
        source={'url':'file:///tmp/owned.txt','file_version':'old','updated':10000}
        for version in ('missing','new-invalid'):
            retry={'attempted':100,'delay':900,'file_version':version}
            with mock.patch.object(atlas,'local_rule_version',return_value=version):
                self.assertFalse(atlas.source_due(source,86400,retry,now=10000,monotonic=120))
                self.assertTrue(atlas.source_due(source,86400,retry,now=10000,monotonic=1000))

    def test_identical_binary_rules_do_not_rewrite_or_revalidate(self):
        (self.root/'rules').mkdir();item={'id':'a'*16,'srs_cached':True,'source_cached':False}
        target=self.root/'rules'/('a'*16+'.srs');target.write_bytes(b'validatedfixture')
        before=target.stat().st_mtime_ns
        with mock.patch.object(atlas,'check') as check:
            self.assertFalse(atlas.store_rule_set({'settings':{}},item,b'validatedfixture'))
        check.assert_not_called();self.assertEqual(target.stat().st_mtime_ns,before)

    def test_reused_worker_pid_and_missing_pid_are_not_busy(self):
        for pid in (None,-1,0,True,123):
            atlas.atomic(self.root/'job.json',{'id':'a'*16,'pid':pid,'process_identity':'old','status':'running'})
            with mock.patch.object(atlas.os,'kill'),mock.patch.object(atlas,'process_identity',return_value='new'):
                self.assertEqual(atlas.active_job()['status'],'error')

    def test_matching_worker_identity_remains_running(self):
        atlas.atomic(self.root/'job.json',{'id':'a'*16,'pid':123,'process_identity':'valid','status':'queued'})
        with mock.patch.object(atlas.os,'kill'),mock.patch.object(atlas,'process_identity',return_value='valid'):
            self.assertEqual(atlas.active_job()['status'],'queued')

    def test_old_job_requires_exact_worker_command(self):
        atlas.atomic(self.root/'job.json',{'id':'a'*16,'pid':123,'status':'running'})
        with mock.patch.object(atlas.os,'kill'),mock.patch.object(atlas,'process_identity',return_value='valid'),mock.patch.object(Path,'read_bytes',return_value=b'python3\0other.py\0worker\0'+b'a'*16+b'\0'):
            self.assertEqual(atlas.active_job()['status'],'error')
