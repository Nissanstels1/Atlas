import os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
from resources import snapshot,MIB

class ResourceSnapshot(unittest.TestCase):
    def test_monitor_preserves_resources_when_engine_or_api_unavailable(self):
        import atlas
        config={'experimental':{'cache_file':{'enabled':False}}}
        with patch.object(atlas,'read_json',return_value=config),patch.object(atlas,'service_running',return_value=False),patch.object(atlas,'clash_request') as api:
            result=atlas.runtime_monitor()
            self.assertFalse(result['available'])
            self.assertIn('resources',result)
            api.assert_not_called()
        with patch.object(atlas,'read_json',return_value=config),patch.object(atlas,'service_running',return_value=True),patch.object(atlas,'clash_request',side_effect=atlas.AtlasError('fixture')):
            result=atlas.runtime_monitor()
            self.assertFalse(result['available'])
            self.assertIn('resources',result)

    def test_large_sparse_cache_is_not_read_or_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            cache=Path(directory)/'cache.db';memory=Path(directory)/'meminfo'
            with cache.open('wb') as handle:handle.truncate(65*MIB)
            memory.write_text('MemTotal: 4194304 kB\nMemAvailable: 32000 kB\n')
            config={'experimental':{'cache_file':{'enabled':True,'path':cache.as_posix()}}}
            original=Path.open
            def guarded(path,*args,**kwargs):
                if path==cache:raise AssertionError('Database must not be opened')
                return original(path,*args,**kwargs)
            # Windows paths lack a leading slash; use lstat mock to test Linux path semantics.
            config['experimental']['cache_file']['path']='/atlas-test/cache.db'
            with patch.object(Path,'lstat',return_value=cache.stat()),patch.object(Path,'open',guarded),patch('resources.os.statvfs',create=True) as vfs:
                vfs.return_value=type('Disk',(),{'f_bavail':1024,'f_frsize':4096})()
                data=snapshot(config,memory)
            self.assertEqual(data['cache']['size_bytes'],65*MIB)
            self.assertEqual(data['cache']['free_bytes'],4*MIB)
            self.assertEqual(len(data['warnings']),3)
            self.assertEqual(cache.stat().st_size,65*MIB)
            self.assertNotIn('path',data['cache'])

    def test_unknown_and_bad_configuration_remain_unknown(self):
        missing=Path('not-present-resource-meminfo')
        for config in (None,[],{}, {'experimental':[]},{'experimental':{'cache_file':[]}}, {'experimental':{'cache_file':{'enabled':True,'path':'relative'}}}):
            self.assertEqual(snapshot(config,missing),{'cache':{},'system':{},'warnings':[]})

    def test_missing_cache_is_zero_and_symlink_not_followed(self):
        config={'experimental':{'cache_file':{'enabled':True,'path':'/atlas-test/cache.db'}}}
        with patch.object(Path,'lstat',side_effect=FileNotFoundError),patch('resources.os.statvfs',side_effect=OSError,create=True):
            self.assertEqual(snapshot(config,Path('missing'))['cache']['size_bytes'],0)
        import stat
        with patch.object(Path,'lstat',return_value=type('Info',(),{'st_mode':stat.S_IFLNK})()),patch('resources.os.statvfs',side_effect=OSError,create=True):
            result=snapshot(config,Path('missing'))
            self.assertNotIn('size_bytes',result['cache'])
            self.assertEqual(len(result['warnings']),1)
