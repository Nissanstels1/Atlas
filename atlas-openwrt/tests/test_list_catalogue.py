import copy,json,sys,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,core
import test_extensions_rpc as fixtures

class ListCatalogue(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown

    def source(self,**changes):
        item=dict(id='d'*16,name='My video',url='https://example.org/list?token=LIBRARY_SECRET',format='domains')
        item.update(changes);return item

    def save_library(self,items):
        return atlas.dispatch('save_settings',{'settings':{'list_catalogue':items}})

    def test_library_save_does_not_apply_or_change_routes(self):
        before=atlas.state()
        with mock.patch.object(atlas,'check') as check,mock.patch.object(atlas,'manage_kill_switch') as guard:
            self.save_library([self.source()]);check.assert_not_called();guard.assert_not_called()
        after=atlas.state();after['settings']['list_catalogue']=[]
        self.assertEqual(before,after)

    def test_status_masks_url_and_preserves_it_on_metadata_save(self):
        self.save_library([self.source()]);settings=atlas.public_status()['settings']
        self.assertNotIn('LIBRARY_SECRET',json.dumps(settings))
        self.save_library(settings['list_catalogue'])
        self.assertIn('LIBRARY_SECRET',atlas.state()['settings']['list_catalogue'][0]['url'])

    def test_older_routing_form_cannot_erase_the_library(self):
        old=atlas.public_status()['settings'];self.save_library([self.source()])
        atlas.dispatch('save_settings',{'settings':old})
        self.assertEqual(len(atlas.state()['settings']['list_catalogue']),1)

    def test_source_can_be_reused_without_disclosing_secret(self):
        self.save_library([self.source()]);settings=atlas.public_status()['settings']
        settings['remote_lists']=[dict(id='e'*16,name='Video copy',url='https://example.org/[saved]',format='domains',policy='proxy',enabled=True,source_catalogue_id='d'*16)]
        atlas.dispatch('save_settings',{'settings':settings})
        item=atlas.state()['settings']['remote_lists'][0]
        self.assertEqual(item['url'],self.source()['url']);self.assertEqual(item['catalogue_origin'],'d'*16)
        self.assertNotIn('source_catalogue_id',item)

    def test_invalid_reference_does_not_modify_settings(self):
        before=atlas.STATE.read_bytes();settings=atlas.public_status()['settings']
        settings['remote_lists']=[dict(id='e'*16,name='Copy',url='',format='domains',policy='proxy',enabled=True,source_catalogue_id='d'*16)]
        with self.assertRaises(core.AtlasError):atlas.dispatch('save_settings',{'settings':settings})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_inline_text_is_metadata_only_until_used(self):
        self.save_library([self.source(url='',content='example.org\nexample.net',format='domains')])
        self.assertFalse((self.root/'catalogue-files').exists())
        public=atlas.public_status()['settings']['list_catalogue'][0]
        self.assertTrue(public['content_set']);self.assertEqual(public['content_lines'],2);self.assertNotIn('content',public)
        before=atlas.STATE.read_bytes()
        read=atlas.dispatch('save_settings',{'settings':{'catalogue_read':'d'*16}})
        self.assertIn('example.net',read['source']['content']);self.assertEqual(before,atlas.STATE.read_bytes())
        self.save_library([public]);self.assertIn('example.net',atlas.state()['settings']['list_catalogue'][0]['content'])

    def test_inline_copy_has_owned_source_and_is_retained_while_used(self):
        self.save_library([self.source(url='',content='example.org',format='domains')])
        settings=atlas.public_status()['settings'];settings['remote_lists']=[dict(id='e'*16,name='Copy',url='',format='domains',policy='proxy',enabled=True,source_catalogue_id='d'*16)]
        atlas.dispatch('save_settings',{'settings':settings})
        path=self.root/'catalogue-files'/('e'*16+'.txt')
        self.assertEqual(path.read_text(),'example.org')
        self.save_library([]);self.assertTrue(path.is_file())
        settings=atlas.public_status()['settings'];settings['remote_lists']=[]
        atlas.dispatch('save_settings',{'settings':settings});self.assertFalse(path.exists())

    def test_library_edit_keeps_existing_copies_independent(self):
        self.save_library([self.source()]);settings=atlas.public_status()['settings']
        settings['remote_lists']=[dict(id='e'*16,name='Copy',url='',format='domains',policy='proxy',enabled=True,source_catalogue_id='d'*16)]
        atlas.dispatch('save_settings',{'settings':settings})
        self.save_library([self.source(url='https://example.org/other')])
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['url'],self.source()['url'])

    def test_library_rejects_invalid_text_and_duplicates(self):
        before=atlas.STATE.read_bytes()
        for items in [[self.source(url='',content='https://bad.example/path',format='cidrs')],[self.source(),self.source(id='e'*16)]]:
            with self.assertRaises(core.AtlasError):self.save_library(items)
            self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_content_size_and_format_are_bounded(self):
        for item in [self.source(url='',content='x'*1048577),self.source(url='',content='example.org',format='srs')]:
            settings=core.defaults()['settings'];settings['list_catalogue']=[item]
            with self.assertRaises(core.AtlasError):core.validate_settings(settings)

    def test_backup_restores_independent_text_copies(self):
        self.save_library([self.source(url='',content='example.org',format='domains')])
        settings=atlas.public_status()['settings'];settings['remote_lists']=[dict(id='e'*16,name='Copy',url='',format='domains',policy='proxy',enabled=True,source_catalogue_id='d'*16)]
        atlas.dispatch('save_settings',{'settings':settings})
        self.save_library([self.source(url='',content='example.net',format='domains')])
        backup=atlas.dispatch('export_backup',{})['backup']
        path=self.root/'catalogue-files'/('e'*16+'.txt');path.unlink()
        atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        self.assertEqual(path.read_text(),'example.org')
        self.assertEqual(atlas.state()['settings']['list_catalogue'][0]['content'],'example.net')

    def test_corrupt_catalogue_backup_is_rejected_before_state_changes(self):
        backup=atlas.dispatch('export_backup',{})['backup'];before=atlas.STATE.read_bytes()
        backup['catalogue_files']={'entries':{},'texts':{'bad':'example.org'}}
        with self.assertRaises(core.AtlasError):atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_global_exclusions_precede_multiple_sections(self):
        state=atlas.state();sec=state['settings']['sections'][0]
        sec.update(domains=['bank.example'],outbound_config=[],mixed_proxy={})
        state['settings'].update(group_order=True,bypass_domains=['bank.example'],bypass_cidrs=['203.0.113.0/24'],routing_excluded_ips=['192.168.34.25'])
        state['settings']['sections'].append(dict(sec,id='f'*16,name='Other'))
        rules=core.make_config(state)['route']['rules']
        direct=next(i for i,x in enumerate(rules) if x.get('domain_suffix')==['bank.example'] and x.get('outbound')=='direct')
        section_indexes=[i for i,x in enumerate(rules) if x.get('domain_suffix')==['bank.example'] and x.get('outbound')!='direct']
        self.assertTrue(section_indexes);self.assertTrue(all(direct<i for i in section_indexes))
        self.assertEqual(next(x for x in rules if x.get('source_ip_cidr')==['192.168.34.25/32'])['outbound'],'direct')

if __name__=='__main__':unittest.main()
