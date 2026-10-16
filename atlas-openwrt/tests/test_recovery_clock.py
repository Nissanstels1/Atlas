"""Interface and watchdog recovery share a rate limit unaffected by NTP jumps."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas


class RecoveryClock(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patch = mock.patch.object(atlas, 'RUN', self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def write(self, payload):
        atlas.atomic(self.root / 'recovery.json', payload)

    def read(self):
        return json.loads((self.root / 'recovery.json').read_text())

    def test_first_claim_records_both_clocks_and_fourth_is_rejected(self):
        with mock.patch.object(atlas.time, 'time', return_value=10000), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertEqual([atlas.claim_recovery_attempt() for _ in range(4)],
                             [True, True, True, False])
        stored = self.read()
        self.assertEqual(stored['attempts'], [10000] * 3)
        self.assertEqual(stored['monotonic_attempts'], [1000] * 3)

    def test_clock_rollback_does_not_extend_expired_monotonic_attempts(self):
        self.write({'attempts': [9999999999] * 3, 'monotonic_attempts': [0, 1, 2]})
        with mock.patch.object(atlas.time, 'time', return_value=100), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertTrue(atlas.claim_recovery_attempt())
        self.assertEqual(self.read()['monotonic_attempts'], [1000])

    def test_clock_jump_does_not_discard_recent_monotonic_attempts(self):
        previous = {'attempts': [10000, 10001, 10002],
                    'monotonic_attempts': [980, 990, 995]}
        self.write(previous)
        with mock.patch.object(atlas.time, 'time', return_value=9999999999), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertFalse(atlas.claim_recovery_attempt())
        self.assertEqual(self.read(), previous)

    def test_legacy_recent_wall_clock_attempts_still_limit_recovery(self):
        self.write({'attempts': [9980, 9990, 9995]})
        with mock.patch.object(atlas.time, 'time', return_value=10000), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertFalse(atlas.claim_recovery_attempt())

    def test_legacy_future_attempts_do_not_lock_recovery_after_clock_reset(self):
        self.write({'attempts': [9999999999] * 3})
        with mock.patch.object(atlas.time, 'time', return_value=100), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertTrue(atlas.claim_recovery_attempt())
        self.assertEqual(self.read()['attempts'], [100])
        self.assertEqual(self.read()['monotonic_attempts'], [1000])

    def test_exact_ten_minute_boundary_allows_new_attempt(self):
        self.write({'attempts': [9400] * 3, 'monotonic_attempts': [400] * 3})
        with mock.patch.object(atlas.time, 'time', return_value=10000), \
                mock.patch.object(atlas.time, 'monotonic', return_value=1000):
            self.assertTrue(atlas.claim_recovery_attempt())
        self.assertEqual(self.read()['monotonic_attempts'], [1000])


if __name__ == '__main__':
    unittest.main()
