import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / 'Makefile').read_text()
VERSION = re.search(r'^PKG_VERSION:=(.+)$', MAKEFILE, re.M).group(1)
RELEASE = re.search(r'^PKG_RELEASE:=(.+)$', MAKEFILE, re.M).group(1)


class ReleaseBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT / 'tools/build_release.py')], check=True, capture_output=True)
        cls.archive = ROOT / ('dist/atlas-openwrt-%s-beta.zip' % VERSION)
        cls.package = ROOT / ('dist/luci-app-atlas_%s-%s_all.ipk' % (VERSION, RELEASE))

    def test_source_bundle_contains_parser_license_tests_and_package(self):
        with zipfile.ZipFile(self.archive) as bundle:
            names = set(bundle.namelist())
        for name in ('atlas-openwrt/root/usr/lib/atlas/core.py',
                     'atlas-openwrt/root/usr/lib/atlas/PYYAML-LICENSE',
                     'atlas-openwrt/root/usr/lib/atlas/yaml/__init__.py',
                     'atlas-openwrt/tests/test_core.py',
                     ('atlas-openwrt/dist/luci-app-atlas_%s-%s_all.ipk' % (VERSION, RELEASE))):
            self.assertIn(name, names)
        self.assertNotIn('atlas-openwrt/dist/SHA256SUMS', names)

    def test_release_checksums_match_both_deliverables(self):
        rows = dict(line.split('  ', 1)[::-1] for line in (ROOT / 'dist/SHA256SUMS').read_text().splitlines())
        for path in (self.package, self.archive):
            self.assertEqual(rows[path.name], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_other_revision_apk_is_not_shipped(self):
        other = ROOT / ('dist/luci-app-atlas-%s-r999.apk' % VERSION)
        if other.exists(): self.skipTest('Sentinel path already exists')
        other.write_bytes(b'not a package')
        try:
            subprocess.run([sys.executable,str(ROOT/'tools/build_release.py')],check=True,capture_output=True)
            with zipfile.ZipFile(self.archive) as bundle:
                self.assertNotIn('atlas-openwrt/dist/'+other.name,bundle.namelist())
        finally:
            other.unlink()
