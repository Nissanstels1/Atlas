"""Automatic bypass must never probe names in a global binary DNS block list."""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import adaptive_routing as adaptive

ENGINE=shutil.which('sing-box')

@unittest.skipUnless(ENGINE and os.name!='nt','requires sing-box on Linux')
class BinaryBlockListTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name)
  self.path=self.directory/('a'*16+'.srs');self.patch=mock.patch.object(adaptive,'RULE_SET_DIRECTORY',self.directory);self.patch.start()
  self.env=mock.patch.dict(os.environ,{'ATLAS_ENGINE_BINARY':ENGINE});self.env.start()
  adaptive._block_list_cache.clear();adaptive._block_match_cache.clear()
  self.item={'id':'a'*16,'enabled':True,'policy':'dnsblock','format':'srs','srs_cached':True,'section':''}
  self.settings={'mode':'rules','fakeip':True,'sections':[],'remote_lists':[self.item]}
  self.compile({'domain_suffix':['ads.example'],'domain_regex':['^tracker[0-9]+\\.example$']})
 def tearDown(self):self.env.stop();self.patch.stop();self.temp.cleanup()
 def compile(self,rule):
  source=self.directory/'source.json';source.write_text(json.dumps({'version':3,'rules':[rule]}))
  subprocess.run([ENGINE,'rule-set','compile','-o',str(self.path),str(source)],check=True,capture_output=True)
 def test_blocked_names_are_never_probed(self):
  self.assertEqual(adaptive.suspension_reason(self.settings),'')
  for host in ('ads.example','cdn.ads.example','tracker42.example'):
   with self.subTest(host=host):self.assertFalse(adaptive.may_probe(host,self.settings))
  self.assertTrue(adaptive.may_probe('regular.example',self.settings))
 def test_replacement_and_unknown_rules_suspend(self):
  self.assertTrue(adaptive.may_probe('regular.example',self.settings))
  self.compile({'ip_cidr':['8.8.8.8/32']})
  self.assertEqual(adaptive.suspension_reason(self.settings),'lists')
  self.assertFalse(adaptive.may_probe('regular.example',self.settings))
 def test_engine_failure_denies_probe(self):
  self.assertEqual(adaptive.suspension_reason(self.settings),'')
  with mock.patch.object(adaptive.subprocess,'run',side_effect=OSError('missing engine')):
   self.assertFalse(adaptive.may_probe('regular.example',self.settings))

if __name__=='__main__':unittest.main()
