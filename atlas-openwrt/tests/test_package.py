"""Regressions for failures observed during native opkg installation."""
import gzip
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
import re
import os
import tempfile
ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / 'Makefile').read_text()
VERSION = re.search(r'^PKG_VERSION:=(.+)$', MAKEFILE, re.M).group(1)
RELEASE = re.search(r'^PKG_RELEASE:=(.+)$', MAKEFILE, re.M).group(1)

class PackageLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT / 'tools/build_ipk.py')], check=True, capture_output=True)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress((ROOT / ('dist/luci-app-atlas_%s-%s_all.ipk' % (VERSION, RELEASE))).read_bytes()))) as package:
            cls.members = {Path(item.name).name: package.extractfile(item).read() for item in package if item.isfile()}
        cls.data = cls.members['data.tar.gz']
        cls.control = cls.members['control.tar.gz']
    def test_standard_ipk_container(self):
        self.assertEqual(set(self.members), {'debian-binary', 'control.tar.gz', 'data.tar.gz'})
        self.assertEqual(self.members['debian-binary'], b'2.0\n')
    def test_parent_directories_precede_every_file(self):
        dirs = {'.'}
        with tarfile.open(fileobj=io.BytesIO(self.data)) as tar:
            for item in tar:
                path = Path(item.name)
                self.assertIn(str(path.parent), dirs, item.name)
                if item.isdir(): dirs.add(str(path))
    def test_conffiles_exist_and_state_is_private(self):
        with tarfile.open(fileobj=io.BytesIO(self.control)) as tar:
            conffiles = tar.extractfile('./conffiles').read().decode().splitlines()
            control = tar.extractfile('./control').read().decode()
            self.assertIn('python3-logging', control)
        self.assertIn('+python3-logging', MAKEFILE)
        self.assertIn('python3-logging', (ROOT / 'tools/install.sh').read_text())
        with tarfile.open(fileobj=io.BytesIO(self.data)) as tar:
            for name in conffiles: self.assertTrue(tar.getmember('.' + name).isfile())
            self.assertEqual(tar.getmember('./etc/atlas/state.json').mode, 0o600)
            self.assertEqual(tar.getmember('./etc/atlas').mode, 0o700)
            self.assertEqual(tar.extractfile('./lib/upgrade/keep.d/atlas').read(), b'/etc/atlas/\n')
            self.assertEqual(tar.getmember('./etc/hotplug.d/iface/95-atlas').mode, 0o755)
    def test_yaml_parser_and_license_are_bundled_without_runtime_dependency(self):
        with tarfile.open(fileobj=io.BytesIO(self.data)) as tar:
            self.assertTrue(tar.getmember('./usr/lib/atlas/yaml/__init__.py').isfile())
            self.assertTrue(tar.getmember('./usr/lib/atlas/PYYAML-LICENSE').isfile())
    def test_prerm_uses_busybox_compatible_cron_filter(self):
        with tarfile.open(fileobj=io.BytesIO(self.control)) as tar:
            script=tar.extractfile('./prerm').read()
        self.assertIn(b"sed -i '/atlas[.]py scheduled/d'",script)

    @unittest.skipUnless(os.name=='posix','Package shell hooks require Linux')
    def test_upgrade_preserves_service_and_remove_cleans_it(self):
        with tarfile.open(fileobj=io.BytesIO(self.control)) as tar:
            text=tar.extractfile('./prerm').read().decode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); calls=root/'calls'; cron=root/'cron'; script=root/'prerm'; service=root/'service'
            service.write_text('#!/bin/sh\necho "$1" >> '+str(calls)+'\n');service.chmod(0o755)
            cron.write_text('* * * * * python3 /usr/lib/atlas/atlas.py scheduled\nother-job\n')
            script.write_text(text.replace('/etc/init.d/atlas',str(service)).replace('/etc/crontabs/root',str(cron)))
            env=dict(os.environ,IPKG_INSTROOT='',PKG_UPGRADE='0')
            subprocess.run(['/bin/sh',str(script),'upgrade'],env=env,check=True)
            self.assertFalse(calls.exists());self.assertIn('atlas.py scheduled',cron.read_text())
            subprocess.run(['/bin/sh',str(script),'remove'],env=env,check=True)
            self.assertEqual(calls.read_text().splitlines(),['stop','disable'])
            self.assertEqual(cron.read_text(),'other-job\n')

    def test_postinst_starts_rpcd_after_acl_refresh(self):
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(self.control))) as tar:
            script=tar.extractfile('./postinst').read()
        self.assertIn(b'/etc/init.d/rpcd restart',script)
        self.assertIn(b'/etc/init.d/rpcd start',script)
