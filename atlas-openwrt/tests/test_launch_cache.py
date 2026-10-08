import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import atlas, core
from launch_cache import prepare, normalized_config, normalized_proxies, wire_request
from test_selection import sample


class LaunchCache(unittest.TestCase):
    def config(self):
        current = sample(); current['settings'].update(max_ping_ms=100)
        current['settings']['sections'] = [dict(id='c'*16, name='private', policy='proxy', domains=['fixture.invalid'], cidrs=[], source_ips=[], pool=current['subscriptions'][0]['id'], udp_over_tcp=True)]
        return core.make_config(current)

    def test_rotation_preserves_normalized_config_and_credentials(self):
        config = self.config()
        first = prepare(config, 'a'*32); second = prepare(first, 'b'*32)
        expected = json.loads(json.dumps(config)); expected['experimental']['cache_file']['cache_id'] = 'atlas-policy-v2'
        self.assertEqual(normalized_config(first), expected)
        self.assertEqual(normalized_config(second), expected)
        self.assertEqual(first['experimental']['cache_file'], second['experimental']['cache_file'])
        for group in [x for x in first['outbounds'] if x['type']=='selector']:
            fresh = next(x for x in second['outbounds'] if x['tag']==group['tag'])
            self.assertEqual(set(group['outbounds']) & set(fresh['outbounds']), {'policy-block'})
            self.assertEqual(fresh['default'], 'policy-block')

    def test_native_mode_is_unchanged(self):
        config = core.make_config(sample())
        self.assertEqual(prepare(config, 'a'*32), config)

    def test_automatic_groups_stay_stable_but_cannot_restore_unfiltered_auto(self):
        launched = prepare(self.config(), 'a'*32)
        self.assertEqual(next(x['tag'] for x in launched['outbounds'] if x['type']=='urltest'),'auto')
        self.assertNotIn('auto',launched['outbounds'][0]['outbounds'])
        path, body = wire_request(launched, '/proxies/proxy', {'name':'auto'})
        self.assertEqual(body, {'name':'policy-block'})
        self.assertIn('auto',normalized_config(launched)['outbounds'][0]['outbounds'])

    def test_expert_group_with_managed_looking_names_keeps_its_auto_member(self):
        current=sample();current['settings'].update(max_ping_ms=100)
        sid='c'*16;prefix='section_'+sid+'_'
        current['settings']['sections']=[dict(id=sid,name='expert',policy='proxy',domains=['fixture.invalid'],cidrs=[],source_ips=[],outbound_config=[dict(type='selector',tag='control',outbounds=['auto','policy-block','d'*32],default='policy-block'),dict(type='urltest',tag='auto',outbounds=['d'*32]),dict(type='http',tag='d'*32,server='127.0.0.1',server_port=9)])]
        config=prepare(core.make_config(current),'a'*32)
        group=next(x for x in config['outbounds'] if x['tag']==prefix+'control')
        self.assertIn(prefix+'auto',group['outbounds'])
        self.assertNotIn('atlas_guard_'+prefix+'control',[x['tag'] for x in config['outbounds']])
        _,body=wire_request(config,'/proxies/'+prefix+'control',{'name':prefix+'auto'})
        self.assertEqual(body,{'name':prefix+'auto'})

    def test_api_identifiers_and_delay_query_are_round_tripped(self):
        config = self.config(); key = next(x['tag'] for x in config['outbounds'] if len(x['tag'])==32)
        launched = prepare(config, 'a'*32)
        tag = next(x['tag'] for x in launched['outbounds'] if x.get('tag','').endswith(key))
        path, body = wire_request(launched, '/proxies/'+key+'/delay?timeout=5000&url=https%3A%2F%2Fexample.org', {'name':key})
        self.assertEqual(path, '/proxies/'+tag+'/delay?timeout=5000&url=https%3A%2F%2Fexample.org')
        self.assertEqual(body, {'name':tag})
        proxies = normalized_proxies({'proxy':{'now':tag,'all':[tag,'policy-block']},tag:{'name':tag,'history':[{'delay':50}]}})
        self.assertEqual(proxies['proxy']['now'],key)
        self.assertEqual(proxies[key]['history'],[{'delay':50}])

    def test_actual_engine_accepts_rotated_references(self):
        engine = os.environ.get('ATLAS_RULE_ENGINE') or os.environ.get('ATLAS_TEST_ENGINE')
        if not engine: self.skipTest('Actual engine not configured')
        with tempfile.TemporaryDirectory() as directory:
            config = prepare(self.config(), 'a'*32)
            config['experimental']['cache_file']['path'] = str(Path(directory)/'cache.db')
            if os.name=='nt': config['inbounds']=[{'type':'mixed','tag':'local','listen':'127.0.0.1','listen_port':19999}]
            path = Path(directory)/'config.json'; path.write_text(json.dumps(config),encoding='utf-8')
            result = subprocess.run([engine,'check','-c',str(path)],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))

    def test_tag_like_password_is_not_modified(self):
        config = self.config(); key = next(x['tag'] for x in config['outbounds'] if len(x['tag'])==32)
        headers={'default':key,'tag':key,'outbound':key}
        config['outbounds'].extend([dict(type='http',tag='expert-secret',server='127.0.0.1',server_port=9,username='fixture',password=key),dict(type='vless',tag='expert-headers',server='127.0.0.1',server_port=9,uuid='11111111-1111-4111-8111-111111111111',transport=dict(type='ws',path='/',headers=headers))])
        launched=prepare(config,'a'*32)
        self.assertEqual(launched['outbounds'][-2]['password'],key)
        self.assertEqual(launched['outbounds'][-1]['transport']['headers'],headers)

    def test_section_save_preserves_live_aliases_and_auto_guard(self):
        current = sample(); current['settings'].update(max_ping_ms=100)
        current['settings']['sections'] = [dict(id='c'*16,name='private',policy='proxy',domains=['fixture.invalid'],cidrs=[],source_ips=[],pool=current['subscriptions'][0]['id'],udp_over_tcp=True)]
        current['settings'] = core.validate_settings(current['settings'])
        config = prepare(core.make_config(current), 'a'*32)
        group = 'section_'+'c'*16+'_control'
        member = next(x for x in normalized_config(config)['outbounds'] if x['tag']==group)['outbounds'][-1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(atlas,'DATA',root), mock.patch.object(atlas,'RUN',root), mock.patch.object(atlas,'STATE',root/'state.json'), mock.patch.object(atlas,'CONFIG',root/'config.json'), mock.patch.object(atlas,'service_running',return_value=True), mock.patch.object(atlas,'clash_request',return_value={}):
                atlas.atomic(atlas.STATE,current); atlas.atomic(atlas.CONFIG,config)
                atlas.dispatch('section_select',dict(id='c'*16,group=group,member=member))
                wire = json.loads(atlas.CONFIG.read_text()); live = next(x for x in wire['outbounds'] if x['tag']==group)
                self.assertTrue(live['default'].startswith('atlas_run_'))
                self.assertNotIn('section_'+'c'*16+'_auto',live['outbounds'])
                self.assertEqual(atlas.state()['settings']['section_choices'][group],member)
                atlas.dispatch('section_select',dict(id='c'*16,group=group,member='section_'+'c'*16+'_auto'))
                live = next(x for x in json.loads(atlas.CONFIG.read_text())['outbounds'] if x['tag']==group)
                self.assertEqual(live['default'],'policy-block')
                self.assertNotIn(group,atlas.state()['settings']['section_choices'])
