import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas

class BootGrace(unittest.TestCase):
    def test_two_minute_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'uptime'
            for value,expected in [('0.0 0',True),('119.9 0',True),('120.0 0',False),('600.0 0',False),('bad',False)]:
                path.write_text(value)
                self.assertEqual(atlas.boot_grace_active(path),expected)

    def test_scheduler_does_not_recover_or_refresh_during_boot(self):
        with patch.object(atlas,'setup'),patch.object(atlas,'boot_grace_active',return_value=True),patch.object(atlas,'state',side_effect=AssertionError('Startup accessed state')),patch.object(sys,'argv',['atlas.py','scheduled']):
            atlas.main()
