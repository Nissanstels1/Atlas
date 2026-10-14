"""Recognize exact public filter presets without exposing saved source URLs."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas
import test_extensions_rpc as fixtures


class AdblockPresets(unittest.TestCase):
    def setUp(self):
        fixtures.ExtensionsRPC.setUp(self)
        self.initial['settings']=atlas.validate_settings(self.initial['settings'])
    tearDown=fixtures.ExtensionsRPC.tearDown
    def sources(self):
        return [dict(id=char*16,name=key,url=url,policy='dnsblock',format='domains',enabled=True)
                for char,(key,url) in zip(('c','d'),atlas.ADBLOCK_PRESETS.items())]

    def test_exact_preset_is_identified_after_url_is_masked(self):
        self.initial['settings']['remote_lists']=self.sources();atlas.atomic(atlas.STATE,self.initial)
        sources=atlas.public_status()['settings']['remote_lists']
        self.assertEqual([x['adblock_preset'] for x in sources],['peter','hagezi'])
        self.assertTrue(all(x['url'].endswith('/[saved]') for x in sources))

    def test_other_host_path_policy_and_section_are_not_global_presets(self):
        base=self.sources()[0]
        sources=[]
        for i,change in enumerate(({'url':base['url']+'&other=1'},{'policy':'proxy'},{'policy':'proxy','section':self.initial['settings']['sections'][0]['id']},{'policy':'interface','interface':'wan'},{'url':'https://pgl.yoyo.org/private?secret=SOURCE_SECRET'})):
            sources.append(dict(base,id=('%x'%i)*16,**change))
        self.initial['settings']['remote_lists']=sources;atlas.atomic(atlas.STATE,self.initial)
        result=atlas.public_status()
        self.assertTrue(all('adblock_preset' not in x for x in result['settings']['remote_lists']))
        self.assertNotIn('SOURCE_SECRET',json.dumps(result))

    def test_derived_marker_is_not_saved_and_cannot_spoof_a_preset(self):
        self.initial['settings']['remote_lists']=self.sources();atlas.atomic(atlas.STATE,self.initial)
        submitted=atlas.public_status()['settings']
        submitted['remote_lists'][0]['adblock_preset']='hagezi'
        atlas.dispatch('save_settings',{'settings':submitted})
        stored=atlas.state()['settings']['remote_lists']
        self.assertTrue(all('adblock_preset' not in x for x in stored))
        self.assertEqual(stored[0]['url'],atlas.ADBLOCK_PRESETS['peter'])
        self.assertEqual(atlas.public_status()['settings']['remote_lists'][0]['adblock_preset'],'peter')

    def test_save_disable_and_reopen_preserve_source_and_cache(self):
        sources=self.sources();sources[0].update(domains=['ads.example'],updated=123)
        self.initial['settings']['remote_lists']=sources;atlas.atomic(atlas.STATE,self.initial)
        submitted=atlas.public_status()['settings'];submitted['remote_lists'][0]['enabled']=False
        atlas.dispatch('save_settings',{'settings':submitted})
        saved=atlas.state()['settings']['remote_lists'][0]
        self.assertEqual(saved['url'],atlas.ADBLOCK_PRESETS['peter'])
        self.assertEqual(saved['domains'],['ads.example']);self.assertEqual(saved['updated'],123)
        public=atlas.public_status()['settings']['remote_lists'][0]
        self.assertFalse(public['enabled']);self.assertEqual(public['adblock_preset'],'peter')
