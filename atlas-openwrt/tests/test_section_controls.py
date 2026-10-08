import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core
from sections import choose_section, section_dashboard, test_section
from test_expert_sections import sample, section


class Controls(unittest.TestCase):
    def fixture(self):
        state=sample()
        state['settings']['sections']=[section()]
        state['settings']=core.validate_settings(state['settings'])
        return state

    def test_lists_and_fetch_use_exact_independent_target(self):
        state=self.fixture();sid=state['settings']['sections'][0]['id']
        state['settings'].update(fetch_lists_via_proxy=True,fetch_lists_section=sid)
        state['settings']['remote_lists']=[dict(name='list',url='https://example.org/list.txt',policy='proxy',format='domains',enabled=True,section=sid,domains=['listed.example'],cidrs=[])]
        cfg=core.make_config(state)
        target='section_'+sid+'_entry'
        rules=cfg['route']['rules']
        self.assertTrue(any(x.get('domain_suffix')==['listed.example'] and x.get('outbound')==target for x in rules))
        self.assertTrue(any(x.get('inbound')==['list-fetch'] and x.get('outbound')==target for x in rules))

    def test_missing_disabled_and_block_section_for_list_are_rejected(self):
        for mutation in ('missing','disabled','block'):
            state=self.fixture();sec=state['settings']['sections'][0];sid=sec['id']
            if mutation=='missing':sid='0'*16
            if mutation=='disabled':sec['enabled']=False
            if mutation=='block':sec.update(policy='block',outbound_config=[])
            state['settings']['remote_lists']=[dict(name='list',url='https://example.org/list.txt',policy='proxy',format='domains',enabled=True,section=sid)]
            with self.assertRaises(core.AtlasError):core.validate_settings(state['settings'])

    def test_udp_bootstrap_has_no_tls(self):
        state=self.fixture();state['settings']['bootstrap_dns_type']='udp'
        cfg=core.make_config(state)
        dns=next(x for x in cfg['dns']['servers'] if x['tag']=='bootstrap')
        self.assertEqual(dns['type'],'udp');self.assertNotIn('tls',dns)

    def graph(self):
        state=self.fixture();sec=state['settings']['sections'][0]
        sec['outbound_config']=[{'type':'urltest','tag':'auto','outbounds':['one','two']}, {'type':'direct','tag':'one'},{'type':'direct','tag':'two'}]
        return state,sec['id'],core.make_config(state)

    def test_root_urltest_has_manual_control_and_persistent_choice(self):
        state,sid,cfg=self.graph();group='section_'+sid+'_control';member='section_'+sid+'_one'
        request=Mock(return_value={})
        choose_section(state,cfg,sid,group,member,request)
        self.assertEqual(state['settings']['section_choices'][group],member)
        self.assertEqual(next(x for x in core.make_config(state)['outbounds'] if x['tag']==group)['default'],member)
        choose_section(state,cfg,sid,group,'section_'+sid+'_auto',request)
        self.assertNotIn(group,state['settings']['section_choices'])

    def test_cross_section_or_unknown_member_is_rejected(self):
        state,sid,cfg=self.graph();request=Mock()
        for group,member in [('proxy','direct'),('section_'+sid+'_control','unknown')]:
            with self.assertRaises(core.AtlasError):choose_section(state,cfg,sid,group,member,request)
        request.assert_not_called()

    def test_dashboard_and_delay_do_not_return_credentials(self):
        state,sid,cfg=self.graph();request=Mock(return_value={'proxies':{}})
        rows=section_dashboard(state,cfg,request)
        self.assertEqual(len(rows[0]['groups']),2)
        self.assertNotIn('outbound_config',str(rows));self.assertNotIn('password',str(rows))
        request=Mock(return_value={'delay':12})
        results=test_section(state,cfg,sid,request)
        self.assertTrue(results);self.assertTrue(all('/delay?' in c.args[1] for c in request.call_args_list))

    def test_file_list_paths_reject_traversal_and_remote_authority(self):
        self.assertEqual(core.rule_list_url('file:///mnt/usb/list.txt'),'file:///mnt/usb/list.txt')
        self.assertEqual(core.rule_list_url('file:///mnt/usb/../list.txt'),'file:///mnt/usb/../list.txt')
        for path in ['file://host/mnt/list.txt','file:///mnt/list.txt?secret']:
            with self.assertRaises(core.AtlasError):core.rule_list_url(path)

    def test_wan_api_requires_explicit_permission_and_secret(self):
        state=self.fixture();state['settings'].update(yacd_enabled=True,yacd_listen='0.0.0.0')
        with self.assertRaises(core.AtlasError):core.make_config(state,api_secret='a'*64)
        state['settings']['yacd_wan']=True
        api=core.make_config(state,api_secret='a'*64)['experimental']['clash_api']
        self.assertEqual(api['external_controller'],'0.0.0.0:19090');self.assertEqual(api['secret'],'a'*64)

if __name__=='__main__':unittest.main()
