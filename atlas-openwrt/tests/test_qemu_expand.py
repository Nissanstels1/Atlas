import shutil
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from expand_openwrt_ext4 import expand


@unittest.skipUnless(all(shutil.which(tool) for tool in ('mkfs.ext4','e2fsck','resize2fs')),
                     'e2fsprogs is required for the disk image test')
class ExpandOpenWrtImage(unittest.TestCase):
    def test_expands_copy_of_ext4_root_partition_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / 'source.img'
            root = directory / 'root.ext4'
            root.write_bytes(b'')
            with root.open('wb') as image:
                image.truncate(16 * 1024 * 1024)
            subprocess.run(['mkfs.ext4','-q','-F',str(root)], check=True)
            sectors = root.stat().st_size // 512
            mbr = bytearray(1024 * 1024)
            mbr[510:512] = b'\x55\xaa'
            # The active type byte is entry offset + 4, not a multi-byte word.
            mbr[450] = 0x83
            struct.pack_into('<II',mbr,454,2048,sectors)
            with source.open('wb') as image:
                image.write(mbr)
                image.write(root.read_bytes())
            original_size = source.stat().st_size
            output = expand(source, directory / 'expanded.img', 32)
            self.assertEqual(source.stat().st_size, original_size)
            raw = output.read_bytes()
            start, count = struct.unpack_from('<II',raw,454)
            self.assertEqual(start,2048)
            self.assertEqual(count * 512,32 * 1024 * 1024)
            self.assertEqual(raw[510:512],b'\x55\xaa')
            self.assertGreater(output.stat().st_size, source.stat().st_size)


if __name__ == '__main__':
    unittest.main()
