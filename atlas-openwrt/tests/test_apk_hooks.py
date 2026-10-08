"""Exercise the real APK builder with a capture tool, inspect generated hooks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name=='posix','APK build hooks require Linux')
class APKHooks(unittest.TestCase):
    def test_explicit_hooks_preserve_service_choice_and_guard_offline_root(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk=Path(directory); apk=sdk/'staging_dir/host/bin/apk'; apk.parent.mkdir(parents=True)
            report=sdk/'hooks.json'
            apk.write_text('#!'+sys.executable+'\nimport json,sys\nfrom pathlib import Path\nargs=sys.argv[1:]\nhooks={}\nfor index,value in enumerate(args):\n if value=="--script":\n  kind,path=args[index+1].split(":",1);hooks[kind]=Path(path).read_text()\nPath('+repr(str(report))+').write_text(json.dumps(hooks))\n')
            apk.chmod(0o755)
            result=subprocess.run([sys.executable,str(ROOT/'tools/build-apk.py'),str(sdk)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            hooks=json.loads(report.read_text())
            for kind in ('post-install','post-upgrade'):
                self.assertNotIn('default_postinst',hooks[kind])
                self.assertNotIn('/etc/init.d/atlas start',hooks[kind])
                self.assertNotIn('/etc/init.d/atlas enable',hooks[kind])
                self.assertIn('[ -n "${IPKG_INSTROOT}" ] && exit 0',hooks[kind])
                self.assertIn('/etc/init.d/rpcd',hooks[kind])
            self.assertIn('export PKG_UPGRADE=1',hooks['post-upgrade'])
            self.assertIn('/etc/init.d/atlas stop',hooks['pre-deinstall'])
