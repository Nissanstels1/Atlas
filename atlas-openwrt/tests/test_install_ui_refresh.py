import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('atlas_ui_refresh', ROOT / 'tools/install-ui-refresh.py')
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
REF = 'a' * 40


class UIRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payloads = {}
        self.before = {}
        for i, (relative, _) in enumerate(ui.FILES):
            target = self.root / relative[len('root/'):]
            target.parent.mkdir(parents=True, exist_ok=True)
            if i != 1:
                target.write_bytes(('old' + str(i)).encode())
            self.before[target] = target.read_bytes() if target.exists() else None
            self.payloads[relative] = (ROOT / relative).read_bytes()

    def fetch(self, url):
        return self.payloads[url.split('/atlas-openwrt/', 1)[1]]

    def assert_unchanged(self):
        for target, before in self.before.items():
            self.assertEqual(target.read_bytes() if target.exists() else None, before)

    def test_success_switches_only_interface_files(self):
        ui.install(REF, self.root, self.fetch)
        for relative, _ in ui.FILES:
            self.assertEqual((self.root / relative[len('root/'):]).read_bytes(), self.payloads[relative])

    def test_corrupt_download_makes_no_changes(self):
        def corrupt(url):
            return b'bad' if url.endswith('overview_cf0d9175.js') else self.fetch(url)
        with self.assertRaises(ValueError):
            ui.install(REF, self.root, corrupt)
        self.assert_unchanged()

    def test_failed_menu_switch_restores_previous_files(self):
        original_write = ui.atomic_write
        def fail_menu(path, content, mode):
            if path.name == 'luci-app-atlas.json':
                raise OSError('simulated')
            return original_write(path, content, mode)
        with patch.object(ui, 'atomic_write', side_effect=fail_menu):
            with self.assertRaises(OSError):
                ui.install(REF, self.root, self.fetch)
        self.assert_unchanged()

    def test_invalid_ref_makes_no_changes(self):
        with self.assertRaises(ValueError):
            ui.install('main', self.root, self.fetch)
        self.assert_unchanged()


if __name__ == '__main__':
    unittest.main()
