import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fetch_sdk',ROOT/'tools/fetch-sdk.py')
fetch_sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(fetch_sdk)


class SDKManifest(unittest.TestCase):
    def test_sdk_name_matches_verified_official_24101_index(self):
        name='openwrt-sdk-24.10.1-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst'
        self.assertEqual(fetch_sdk.sdk_filename('<a href="'+name+'">'+name+'</a>','24.10.1','x86/64'),name)

    def test_ambiguous_sdk_is_rejected(self):
        with self.assertRaises(ValueError):fetch_sdk.sdk_filename('', '24.10.1','x86/64')

    def test_manifest_hash_is_for_exact_filename(self):
        self.assertEqual(fetch_sdk.expected_hash('a'*64+' *sdk.tar.zst\n','sdk.tar.zst'),'a'*64)
        with self.assertRaises(ValueError):fetch_sdk.expected_hash('a'*64+' sdk.tar.zst.bak\n','sdk.tar.zst')


if __name__=='__main__':unittest.main()
