import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_core import state_with_node
import atlas

class BootRebuild(unittest.TestCase):
    def test_boot_rebuilds_after_upgrade_instead_of_reusing_old_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'config.json'
            (root/'active.json').write_text('{"old_config":true}')
            state=state_with_node()
            with patch.object(atlas,'setup'),patch.object(atlas,'state',return_value=state),patch.object(atlas,'DATA',root),patch.object(atlas,'CONFIG',config),patch.object(atlas,'stored_config_dir',return_value=root),patch.object(atlas,'prepare_runtime_paths'),patch.object(sys,'argv',['atlas.py','boot-config']):
                atlas.main()
            generated=json.loads(config.read_text())
            self.assertNotIn('old_config',generated)
            self.assertTrue(generated.get('outbounds'))
