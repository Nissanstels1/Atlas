import os,re,subprocess,unittest
from pathlib import Path

class InstallerArchitecture(unittest.TestCase):
    @unittest.skipIf(os.name=='nt','Installer uses OpenWrt awk')
    def test_optional_x86_engine_is_excluded_on_other_architectures(self):
        source=(Path(__file__).resolve().parents[1]/'tools/install-release.sh').read_text()
        program=re.search(r'awk -v suffix="\$suffix" -v machine="\$machine" \'(.*?)\' "\$directory/SHA256SUMS"',source,re.S)[1]
        names=['luci-app-atlas_0.28.0-1_all.ipk','atlas-engine_1.13.21-3_x86_64.ipk','luci-app-atlas-0.28.0-r1.apk','atlas-engine-1.13.21-r3.apk']
        manifest=''.join('a'*64+'  '+name+'\n' for name in names)
        for machine in ('x86_64','aarch64','mips'):
            for suffix in ('ipk','apk'):
                result=subprocess.run(['awk','-v','suffix='+suffix,'-v','machine='+machine,program],input=manifest,text=True,capture_output=True,check=True)
                selected=[line.split()[1] for line in result.stdout.splitlines()]
                expected=[name for name in names if name.endswith('.'+suffix) and (machine=='x86_64' or name.startswith('luci-app-atlas'))]
                self.assertEqual(selected,expected)
