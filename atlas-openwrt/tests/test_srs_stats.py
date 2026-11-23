import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas

class SrsStats(unittest.TestCase):
 def test_real_engine_counts_srs(self):
  binary=os.environ.get('ATLAS_EXTENSION_ENGINE')
  if not binary:self.skipTest('Set ATLAS_EXTENSION_ENGINE to Atlas Engine')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=root/'data';run=root/'run';(data/'rules').mkdir(parents=True);run.mkdir();ident='c'*16
   source=root/'rules.json';source.write_text(json.dumps({'version':3,'rules':[{'domain':['a.example'],'domain_suffix':['b.example','c.example'],'domain_regex':['^ads\\.']}]}))
   result=subprocess.run([binary,'rule-set','compile','--output',str(data/'rules'/(ident+'.srs')),str(source)],capture_output=True,timeout=10)
   self.assertEqual(result.returncode,0,result.stderr)
   item={'id':ident,'format':'srs','srs_cached':True,'policy':'dnsblock'}
   with patch.object(atlas,'DATA',data),patch.object(atlas,'RUN',run),patch.object(atlas,'BINARY',binary),patch.object(atlas,'state',return_value={'settings':{'remote_lists':[item]}}):
    atlas.count_srs_list(ident)
    self.assertEqual(atlas.public_srs_stats([item]),{ident:{'domains':3,'patterns':1}})
 def test_count_cached_version_without_recording_queries(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);data=root/'data';run=root/'run';(data/'rules').mkdir(parents=True);run.mkdir()
   ident='a'*16;file=data/'rules'/(ident+'.srs');file.write_bytes(b'first-version')
   item={'id':ident,'format':'srs','srs_cached':True,'policy':'dnsblock'}
   def decompile(args,**kwargs):
    Path(args[-2]).write_text(json.dumps({'rules':[{'domain':['a.example'],'domain_suffix':['b.example','c.example'],'domain_regex':['.*'] }]}))
    return SimpleNamespace(returncode=0)
   with patch.object(atlas,'DATA',data),patch.object(atlas,'RUN',run),patch.object(atlas,'state',return_value={'settings':{'remote_lists':[item]}}),patch.object(atlas.subprocess,'run',side_effect=decompile) as calls,patch.object(atlas.subprocess,'Popen') as spawn:
    atlas.count_srs_list(ident)
    self.assertEqual(atlas.public_srs_stats([item]),{ident:{'domains':3,'patterns':1}})
    self.assertEqual(atlas.public_srs_stats([item]),{ident:{'domains':3,'patterns':1}})
    self.assertEqual(calls.call_count,1);spawn.assert_not_called()
    file.write_bytes(b'second-version-is-different')
    self.assertEqual(atlas.public_srs_stats([item]),{});spawn.assert_called_once()
    cached=json.loads((run/('srs-stat-'+ident+'.json')).read_text())
    self.assertNotIn('a.example',json.dumps(cached))
 def test_rejects_symlinks_and_non_blocking_sources(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'rules').mkdir();target=root/'elsewhere';target.write_bytes(b'x')
   ident='b'*16;(root/'rules'/(ident+'.srs')).symlink_to(target)
   with patch.object(atlas,'DATA',root):
    self.assertIsNone(atlas.srs_list_fingerprint({'id':ident,'format':'srs','srs_cached':True,'policy':'dnsblock'}))
    self.assertIsNone(atlas.srs_list_fingerprint({'id':ident,'format':'srs','srs_cached':True,'policy':'proxy'}))

if __name__=='__main__':unittest.main()
