import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas
import core
from backups import make_backup
from test_expert_sections import sample, section, listener


class ExtensionsRPC(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.patches = [mock.patch.object(atlas, name, value) for name, value in
                       [('DATA',self.root),('RUN',self.root),('STATE',self.root/'state.json'),('CONFIG',self.root/'config.json')]]
        self.patches += [mock.patch.object(atlas,'service_running',return_value=False),
                         mock.patch.object(atlas,'check'),mock.patch.object(atlas,'system_interfaces',return_value=set()),
                         mock.patch.object(atlas,'engine_version',return_value='sing-box 1.12.17'),
                         mock.patch.object(atlas,'kill_switch_active',return_value=False),
                         mock.patch.object(atlas,'dhcp_dns_active',return_value=False),
                         mock.patch.object(atlas,'manage_kill_switch'),mock.patch.object(atlas,'process_memory',return_value={})]
        for patch in self.patches:patch.start()
        self.initial = sample()
        self.initial['settings']['sections'] = [section(mixed_proxy=listener())]
        atlas.atomic(atlas.STATE,self.initial)

    def tearDown(self):
        for patch in reversed(self.patches):patch.stop()
        self.directory.cleanup()

    def test_status_hides_section_passwords_and_graph(self):
        status=atlas.public_status()
        self.assertNotIn('graph-secret',json.dumps(status))
        self.assertNotIn('listener-secret',json.dumps(status))
        public=status['settings']['sections'][0]
        self.assertTrue(public['outbound_config_set'])
        self.assertNotIn('outbound_config',public)

    def test_private_source_permissions_legacy_save_and_backup_roundtrip(self):
        self.initial['settings']['remote_lists']=[dict(id='c'*16,name='NAS',url='http://nas.lan/list?token=SOURCE_SECRET',policy='proxy',format='auto',enabled=True,allow_private=True,allow_symlinks=True)]
        atlas.atomic(atlas.STATE,self.initial)
        submitted=atlas.public_status()['settings']
        self.assertNotIn('SOURCE_SECRET',json.dumps(submitted))
        self.assertEqual(submitted['remote_lists'][0]['url'],'http://nas.lan/[saved]')
        for flag in ('allow_private','allow_symlinks'):submitted['remote_lists'][0].pop(flag)
        atlas.dispatch('save_settings',{'settings':submitted})
        saved=atlas.state()['settings']['remote_lists'][0]
        self.assertTrue(saved['allow_private']);self.assertTrue(saved['allow_symlinks'])
        backup=atlas.dispatch('export_backup',{})['backup']
        atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['url'],self.initial['settings']['remote_lists'][0]['url'])
        submitted=atlas.public_status()['settings'];submitted['remote_lists'][0]['allow_symlinks']=False
        atlas.dispatch('save_settings',{'settings':submitted})
        self.assertFalse(atlas.state()['settings']['remote_lists'][0]['allow_symlinks'])

    def test_settings_roundtrip_and_rename_preserve_secrets(self):
        submitted=atlas.public_status()['settings']
        submitted['sections'][0]['name']='renamed'
        atlas.dispatch('save_settings',{'settings':submitted})
        saved=atlas.state()['settings']['sections'][0]
        self.assertEqual(saved['mixed_proxy']['password'],'listener-secret')
        self.assertEqual(saved['outbound_config'][0]['password'],'graph-secret')
        self.assertEqual(saved['name'],'renamed')

    def test_explicit_empty_graph_clears_it(self):
        submitted=atlas.public_status()['settings']
        submitted['sections'][0]['outbound_config']=[]
        atlas.dispatch('save_settings',{'settings':submitted})
        self.assertEqual(atlas.state()['settings']['sections'][0]['outbound_config'],[])

    def test_engine_rejection_keeps_saved_state_unchanged(self):
        before=atlas.STATE.read_bytes()
        with mock.patch.object(atlas,'check',side_effect=core.AtlasError('Invalid engine configuration')):
            with self.assertRaises(core.AtlasError):atlas.dispatch('save_settings',{'settings':atlas.public_status()['settings']})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_administrator_reads_section_config_explicitly(self):
        identity=atlas.state()['settings']['sections'][0]['id']
        result=atlas.dispatch('section_details',{'id':identity})
        self.assertEqual(result['outbound_config'][0]['password'],'graph-secret')
        with self.assertRaises(core.AtlasError):atlas.dispatch('section_details',{'id':'missing'})

    def test_local_edit_preserves_source_id_and_does_not_duplicate_source(self):
        source_id=self.initial['subscriptions'][0]['id']
        result=atlas.dispatch('import_profiles',{'id':source_id,'name':'changed',
                              'content':'trojan://new-password@example.net:443#changed'})
        self.assertEqual(result['id'],source_id)
        self.assertEqual(len(atlas.state()['subscriptions']),1)
        content=atlas.dispatch('get_profiles',{'id':source_id})['content']
        self.assertIn('new-password',content)

    def test_bad_local_edit_preserves_source(self):
        before=atlas.STATE.read_bytes()
        with self.assertRaises(core.AtlasError):atlas.dispatch('import_profiles',{'id':'b'*16,'name':'changed','content':'invalid'})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_partial_local_edit_does_not_delete_invalid_rows(self):
        before=atlas.STATE.read_bytes()
        with self.assertRaises(core.AtlasError):
            atlas.dispatch('import_profiles',{'id':'b'*16,'name':'changed',
                'content':'trojan://new-password@example.net:443#changed\ninvalid'})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_legacy_client_section_without_new_fields_preserves_advanced_data(self):
        submitted=atlas.public_status()['settings']
        for field in ('id','enabled','mixed_proxy','outbound_config_set'):
            submitted['sections'][0].pop(field,None)
        atlas.dispatch('save_settings',{'settings':submitted})
        saved=atlas.state()['settings']['sections'][0]
        self.assertEqual(saved['outbound_config'][0]['password'],'graph-secret')
        self.assertEqual(saved['mixed_proxy']['password'],'listener-secret')

    def test_backup_export_restore_and_previous_state_copy(self):
        backup=atlas.dispatch('export_backup',{})['backup']
        backup['state']['settings']['sections'][0]['name']='restored'
        result=atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        self.assertTrue(result['ok'])
        self.assertEqual(atlas.state()['settings']['sections'][0]['name'],'restored')
        self.assertEqual(json.loads((self.root/'backup-before-restore.json').read_text())['settings']['sections'][0]['name'],'expert')

    def test_restore_refuses_running_service_and_engine_failure(self):
        content=json.dumps(make_backup(self.initial));before=atlas.STATE.read_bytes()
        with mock.patch.object(atlas,'service_running',return_value=True),self.assertRaises(core.AtlasError):
            atlas.dispatch('restore_backup',{'content':content})
        with mock.patch.object(atlas,'check',side_effect=core.AtlasError('bad')),self.assertRaises(core.AtlasError):
            atlas.dispatch('restore_backup',{'content':content})
        self.assertEqual(atlas.STATE.read_bytes(),before)

    def test_diagnostic_report_omits_secrets_graphs_and_source_addresses(self):
        result=atlas.dispatch('diagnostic_report',{})['report']
        encoded=json.dumps(result)
        for secret in ('graph-secret','listener-secret','private-password','example.com','example.org','127.0.0.1'):
            self.assertNotIn(secret,encoded)
        self.assertEqual(result['node_count'],1)

    def test_extension_methods_are_administrator_only(self):
        acl=json.loads((Path(__file__).resolve().parents[1]/'root/usr/share/rpcd/acl.d/atlas.json').read_text())['luci-app-atlas']
        for method in ('section_details','get_profiles','export_backup','restore_backup','diagnostic_report'):
            self.assertIn(method,acl['write']['ubus']['atlas'])
            self.assertNotIn(method,acl['read']['ubus']['atlas'])

    def test_large_expert_settings_and_backup_have_method_specific_rpc_limits(self):
        self.assertGreaterEqual(atlas.rpc_request_limit('save_settings'),16*1024*1024)
        self.assertGreater(atlas.rpc_request_limit('restore_backup'),16*1024*1024)
        self.assertEqual(atlas.rpc_request_limit('status'),131072)

    def test_strict_country_backup_can_be_restored_without_widening_saved_policy(self):
        backup=make_backup(self.initial)
        backup['state']['settings'].update(countries=['EE'],require_verified_countries=True)
        atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        settings=atlas.state()['settings']
        self.assertTrue(settings['require_verified_countries'])
        self.assertEqual(settings['countries'],['EE'])
        self.assertFalse(core.filter_nodes(core.all_nodes(atlas.state()),settings))


if __name__=='__main__':unittest.main()
