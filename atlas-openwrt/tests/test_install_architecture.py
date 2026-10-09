import os,re,subprocess,unittest,shutil
from pathlib import Path

AWK=shutil.which('awk') or ('C:/Program Files/Git/usr/bin/awk.exe' if Path('C:/Program Files/Git/usr/bin/awk.exe').exists() else None)
class InstallerArchitecture(unittest.TestCase):
    @unittest.skipUnless(AWK,'Installer needs awk')
    def test_engine_matches_architecture_and_package_format(self):
        source=(Path(__file__).resolve().parents[1]/'tools/install-release.sh').read_text()
        program=re.search(r'awk -v suffix="\$suffix" -v machine="\$machine" \'(.*?)\' "\$directory/SHA256SUMS"',source,re.S)[1]
        names=['luci-app-atlas_0.28.0-1_all.ipk','atlas-engine_1.13.21-3_x86_64.ipk','atlas-engine_1.13.21-3_aarch64_generic.ipk','atlas-engine_1.13.21-3_mips.ipk','luci-app-atlas-0.28.0-r1.apk','atlas-engine-1.13.21-r3.apk','atlas-engine-1.13.21-r3_aarch64_generic.apk','atlas-engine-1.13.21-r3_mips.apk']
        manifest=''.join('a'*64+'  '+name+'\n' for name in names)
        for machine in ('x86_64','aarch64','mips','armv7l'):
            for suffix in ('ipk','apk'):
                result=subprocess.run([AWK,'-v','suffix='+suffix,'-v','machine='+machine,program],input=manifest,text=True,capture_output=True,check=True)
                selected=[line.split()[1] for line in result.stdout.splitlines()]
                expected=[name for name in names if name.endswith('.'+suffix) and (name.startswith('luci-app-atlas') or (machine=='x86_64' and (name.endswith('_x86_64.ipk') or name=='atlas-engine-1.13.21-r3.apk')) or (machine=='aarch64' and name.endswith('_aarch64_generic.'+suffix)))]
                self.assertEqual(selected,expected)
