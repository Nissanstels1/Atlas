"""Run the public bootstrap against isolated package-manager/RPC fixtures."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which('sh') or ('C:/Program Files/Git/bin/sh.exe' if os.name == 'nt' else None)


def shell_path(path):
    value = Path(path).resolve().as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value


@unittest.skipUnless(SHELL, 'POSIX shell is required')
class BootstrapTests(unittest.TestCase):
    def run_fixture(self, manager, failure=''):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binaries = base / 'bin'
            binaries.mkdir()
            log = base / 'operations'
            release = base / 'openwrt_release'
            release.write_text("DISTRIB_RELEASE='24.10.1'\n")
            installer = base / 'installer.sh'
            installer.write_text('#!/bin/sh\necho release >> "' + shell_path(log) + '"\n')
            backend = base / 'atlas'
            backend.write_text('#!/bin/sh\n' + ('exit 1' if failure == 'backend' else "echo '[]'" if failure == 'methods' else "echo '{\"status\":{}}'") + '\n')
            backend.chmod(0o755)
            python = base / 'python3'
            if failure != 'python':
                python.write_text('#!/bin/sh\nexec "' + shell_path(sys.executable) + '" "$@"\n')
                python.chmod(0o755)
            bodies = {
                'id': 'echo 0', 'uname': 'echo aarch64',
                'wget': 'cp "' + shell_path(installer) + '" "$3"',
                manager: 'echo "$*" >> "' + shell_path(log) + '"\n' + ('exit 1' if failure == 'manager' else 'exit 0'),
                'ubus': 'exit 1' if failure == 'rpc' else 'echo atlas',
                'sleep': 'exit 0',
            }
            for name, body in bodies.items():
                target = binaries / name
                target.write_text('#!/bin/sh\n' + body + '\n')
                target.chmod(0o755)
            source = (ROOT / 'install.sh').read_text()
            source = source.replace('63bc588105e12aff89e9dff8713cc112a7130a7bb02517b593e90cde58e63497', hashlib.sha256(installer.read_bytes()).hexdigest())
            for original, target in [('/etc/openwrt_release', release), ('/usr/bin/python3', python), ('/usr/libexec/rpcd/atlas', backend)]:
                source = source.replace(original, shell_path(target))
            source = source.replace('/tmp/atlas-bootstrap.', shell_path(base) + '/atlas-bootstrap.')
            script = base / 'bootstrap.sh'
            script.write_text(source)
            env = dict(os.environ, ATLAS_FIXTURE_BIN=shell_path(binaries))
            args = [SHELL, '-c', 'PATH="$ATLAS_FIXTURE_BIN:/usr/bin:/bin"; export PATH; exec sh "$1"', 'fixture', shell_path(script)]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
            return result, log.read_text() if log.exists() else ''

    def test_complete_install_opkg_and_apk(self):
        for manager in ('opkg', 'apk'):
            with self.subTest(manager=manager):
                result, operations = self.run_fixture(manager)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('python3-light', operations)
                self.assertIn('python3-cryptography', operations)
                self.assertIn('release', operations)
                self.assertIn('backend verified', result.stdout)

    def test_incomplete_install_is_never_successful(self):
        for manager in ('opkg', 'apk'):
            for failure in ('python', 'manager', 'backend', 'methods', 'rpc'):
                with self.subTest(manager=manager, failure=failure):
                    result, operations = self.run_fixture(manager, failure)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('backend verified', result.stdout)
                    if failure in ('python', 'manager'):
                        self.assertNotIn('release', operations)


if __name__ == '__main__':
    unittest.main()
