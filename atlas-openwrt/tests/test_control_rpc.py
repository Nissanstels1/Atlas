import copy
from pathlib import Path
import unittest
from unittest import mock
import test_extensions_rpc as fixtures
import atlas
import core


class ControlRPC(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown

    def configured(self):
        state=atlas.state();sec=state['settings']['sections'][0]
        sec['outbound_config']=[dict(type='selector',tag='select',outbounds=['one','two'],default='one'),dict(type='direct',tag='one'),dict(type='direct',tag='two')]
        atlas.atomic(atlas.STATE,state)
        cfg=core.make_config(state)
        atlas.atomic(atlas.CONFIG,cfg)
        return state,sec['id'],cfg

    def test_manual_choice_persists_state_and_active_config(self):
        state,sid,cfg=self.configured();group='section_'+sid+'_select';member='section_'+sid+'_two'
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',return_value={}):
            atlas.dispatch('section_select',dict(id=sid,group=group,member=member))
        self.assertEqual(atlas.state()['settings']['section_choices'][group],member)
        for path in [atlas.CONFIG,self.root/'active.json',self.root/'last-good.json']:
            stored=atlas.read_json(path,{})
            self.assertEqual(next(x for x in stored['outbounds'] if x['tag']==group)['default'],member)

    def test_engine_api_failure_does_not_save_manual_choice(self):
        state,sid,cfg=self.configured();previous=atlas.STATE.read_bytes()
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=core.AtlasError('API failed')):
            with self.assertRaises(core.AtlasError):atlas.dispatch('section_select',dict(id=sid,group='section_'+sid+'_select',member='section_'+sid+'_two'))
        self.assertEqual(atlas.STATE.read_bytes(),previous)

    def test_private_panel_key_is_not_in_public_status(self):
        state,sid,cfg=self.configured();state['settings'].update(yacd_enabled=True,yacd_listen='192.168.1.1')
        atlas.atomic(atlas.STATE,state);cfg['experimental']['clash_api']={'external_controller':'192.168.1.1:19090','secret':'a'*64};atlas.atomic(atlas.CONFIG,cfg)
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'runtime_status',return_value={}):
            self.assertNotIn('a'*64,str(atlas.public_status()))
            self.assertEqual(atlas.dispatch('dashboard_access',{})['secret'],'a'*64)

    def test_local_file_read_is_bounded_and_symlink_rejected(self):
        path=mock.Mock();path.is_symlink.return_value=True
        with mock.patch.object(atlas,'Path',return_value=path):
            with self.assertRaises(core.AtlasError):atlas.local_rule_bytes('file:///mnt/usb/list.txt')
        path.is_symlink.return_value=False;path.parents=[];path.is_file.return_value=True
        stream=mock.MagicMock();stream.__enter__.return_value.read.return_value=b'x'*(core.MAX_BYTES+1)
        path.open.return_value=stream
        with mock.patch.object(atlas,'Path',return_value=path):
            with self.assertRaises(core.AtlasError):atlas.local_rule_bytes('file:///mnt/usb/list.txt')

    def test_manual_pool_choice_is_not_overwritten_by_scheduler(self):
        state=atlas.state();sid=state['subscriptions'][0]['id'];key=sid+state['subscriptions'][0]['nodes'][0]['id'];group='pool_'+sid
        state['settings']['section_choices'][group]=key
        request=mock.Mock(return_value={'proxies':{group:{'now':key},'proxy':{'now':'auto'}}})
        with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',request):atlas.automatic_select(state)
        self.assertFalse(any(c.args[0]=='PUT' and c.args[1]=='/proxies/'+group for c in request.call_args_list if c.args))

if __name__=='__main__':unittest.main()
