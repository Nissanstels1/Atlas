"""Routing and safety of the opt-in adaptive fallback."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas, core
import adaptive_routing, start_guard
from test_core import state_with_node


class AdaptiveConfigTests(unittest.TestCase):
    def test_explicit_proxy_and_block_rules_remain_in_force_for_russian_domains(self):
        state=state_with_node();state['settings'].update(adaptive_proxy_enabled=True,
            domains=['user-selected.ru'],blocked_domains=['ads.example.ru'])
        cfg=core.make_config(state);rules=cfg['route']['rules']
        self.assertTrue(any(r.get('domain_suffix')==['user-selected.ru'] and r.get('outbound')=='proxy' for r in rules))
        self.assertTrue(any('ads.example.ru' in r.get('domain_suffix',[]) and r.get('action')=='reject' for r in cfg['dns']['rules']))

    def test_disabled_configuration_unchanged(self):
        state=state_with_node();cfg=core.make_config(state)
        self.assertFalse(any(x.get('tag')=='adaptive-probe' for x in cfg['inbounds']))
        self.assertFalse(any(x.get('tag')=='atlas-adaptive' for x in cfg['route']['rule_set']))

    def test_route_and_dns_priorities_are_preserved(self):
        state=state_with_node();settings=state['settings']
        settings.update(adaptive_proxy_enabled=True,fakeip=True,bypass_domains=['bank.example.com'],
                        domains=['proxy.example.com'])
        cfg=core.make_config(state);rules=cfg['route']['rules']
        inbound=next(x for x in cfg['inbounds'] if x.get('tag')=='adaptive-probe')
        self.assertEqual(inbound['listen'],'127.0.0.1')
        self.assertTrue(inbound['users'][0]['password'])
        self.assertTrue(any(x.get('inbound')==['adaptive-probe'] and x.get('outbound')=='proxy' for x in rules))
        dynamic=next(i for i,x in enumerate(rules) if x.get('rule_set')==['atlas-adaptive'])
        direct=next(i for i,x in enumerate(rules) if x.get('domain_suffix')==['bank.example.com'])
        explicit=next(i for i,x in enumerate(rules) if x.get('domain_suffix')==['proxy.example.com'])
        self.assertLess(direct,dynamic);self.assertLess(explicit,dynamic)
        self.assertTrue(any(x.get('tag')=='atlas-adaptive' for x in cfg['route']['rule_set']))
        self.assertTrue(any(x.get('rule_set')==['atlas-adaptive'] and x.get('server')=='fakeip' for x in cfg['dns']['rules']))

    def test_incompatible_modes_or_dns_are_rejected(self):
        with self.assertRaises(core.AtlasError):core.validate_settings({'adaptive_proxy_enabled':True,'mode':'global'})
        with self.assertRaises(core.AtlasError):core.validate_settings({'adaptive_proxy_enabled':True,'dns_filter':'custom',
            'custom_dns_type':'udp','custom_dns_server':'1.1.1.1','custom_dns_sni':'cloudflare-dns.com'})
        with self.assertRaises(core.AtlasError):core.validate_settings({'adaptive_proxy_enabled':True,'adaptive_proxy_section':'missing'})
        self.assertEqual(core.validate_settings({'adaptive_proxy_enabled':False,'adaptive_proxy_section':'missing'})['adaptive_proxy_section'],'')

    def test_ambiguous_direct_exclusions_do_not_enable_debug_logging(self):
        state=state_with_node();state['settings'].update(adaptive_proxy_enabled=True,routing_excluded_ips=['192.168.1.10/32'])
        cfg=core.make_config(state)
        self.assertEqual(cfg['log']['level'],'warn')
        self.assertTrue(any(x.get('tag')=='atlas_adaptive_log_warn' for x in cfg['outbounds']))

    def test_selected_section_is_used_for_probe_and_dynamic_traffic(self):
        state=state_with_node();settings=state['settings'];sid='a'*16
        settings['sections']=[{'id':sid,'name':'Video','policy':'proxy','domains':['video.example.com'],'cidrs':[],'source_ips':[],'pools':[]}]
        settings.update(adaptive_proxy_enabled=True,adaptive_proxy_section=sid)
        cfg=core.make_config(state);rules=cfg['route']['rules']
        actual=next(x['outbound'] for x in rules if x.get('rule_set')==['atlas-adaptive'])
        self.assertEqual(actual,'section_'+sid+'_control')
        self.assertTrue(any(x.get('inbound')==['adaptive-probe'] and x.get('outbound')==actual for x in rules))

    def test_adaptive_settings_save_does_not_replace_other_settings(self):
        state=state_with_node();state['settings']['bypass_domains']=['bank.example.com']
        writes=[]
        with patch.object(atlas,'locked',return_value=contextlib.nullcontext()),patch.object(atlas,'active_job',return_value={}), \
             patch.object(atlas,'state',return_value=copy.deepcopy(state)),patch.object(atlas,'atomic',side_effect=lambda p,v:writes.append(copy.deepcopy(v))):
            self.assertTrue(atlas.dispatch('adaptive_settings',{'enabled':True,'section':''})['ok'])
        self.assertEqual(writes[0]['settings']['bypass_domains'],['bank.example.com'])
        self.assertTrue(writes[0]['settings']['adaptive_proxy_enabled'])

    def test_unapplied_direct_exception_removal_suspends_probes(self):
        original=state_with_node();original['settings'].update(adaptive_proxy_enabled=True,bypass_domains=['bank.example.com'])
        applied=core.make_config(original)
        self.assertTrue(atlas.adaptive_config_matches(original,applied))
        changed=copy.deepcopy(original);changed['settings']['bypass_domains']=[]
        self.assertFalse(atlas.adaptive_config_matches(changed,applied))

    def test_applied_comparison_survives_real_launch_namespace(self):
        state=state_with_node();state['settings'].update(adaptive_proxy_enabled=True,fakeip=True,
            direct_fakeip_doh=True,max_ping_ms=500,
            sections=[{'id':'a'*16,'name':'Video','policy':'proxy','domains':['video.example.com'],'cidrs':[],'source_ips':[],'pools':[]}])
        generated=core.make_config(state);launched=atlas.prepare_engine_start(generated)
        self.assertTrue(atlas.adaptive_config_matches(state,launched))

    def test_created_file_starts_empty_and_keeps_existing(self):
        state=state_with_node();state['settings']['adaptive_proxy_enabled']=True
        cfg=core.make_config(state)
        with tempfile.TemporaryDirectory() as temp,patch.object(atlas,'RUN',Path(temp)):
            cfg['experimental']['cache_file']['path']=str(Path(temp)/'cache.db')
            atlas.prepare_runtime_paths(cfg,state['settings'])
            path=Path(temp)/'adaptive-rules.json';self.assertEqual(json.loads(path.read_text()),{'version':3,'rules':[]})
            path.write_text('{"version":3,"rules":[{"domain":["keep.example.com"]}]}')
            atlas.prepare_runtime_paths(cfg,state['settings'])
            self.assertEqual(json.loads(path.read_text())['rules'][0]['domain'],['keep.example.com'])

    @unittest.skipUnless(os.path.exists('/usr/lib/atlas-engine/bin/atlas-engine'),'native engine not present')
    def test_native_engine_accepts_opt_in_configuration(self):
        state=state_with_node();state['settings'].update(adaptive_proxy_enabled=True,fakeip=True)
        cfg=core.make_config(state)
        with tempfile.TemporaryDirectory() as temp:
            rulefile=Path(temp)/'rules.json';rulefile.write_text('{"version":3,"rules":[]}')
            next(x for x in cfg['route']['rule_set'] if x['tag']=='atlas-adaptive')['path']=str(rulefile)
            cfg['experimental']['cache_file']['path']=str(Path(temp)/'cache.db')
            config=Path(temp)/'config.json';config.write_text(json.dumps(cfg))
            result=subprocess.run(['/usr/lib/atlas-engine/bin/atlas-engine','check','-c',str(config)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_remove_suppresses_only_an_existing_automatic_host(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);config=root/'config.json'
            config.write_text(json.dumps({'inbounds':[{'tag':'adaptive-probe'}]}))
            (root/'adaptive-rules.json').write_text(json.dumps({'version':3,'rules':[{'domain':['a.example.com','b.example.com']}]}))
            with patch.object(atlas,'RUN',root),patch.object(atlas,'DATA',root),patch.object(atlas,'CONFIG',config),patch.object(atlas,'service_running',return_value=True),patch.object(atlas,'state',return_value=core.defaults()):
                self.assertTrue(atlas.adaptive_remove('a.example.com')['ok'])
                self.assertEqual(atlas.adaptive_suppressed(),{'a.example.com'})
                with self.assertRaises(core.AtlasError):atlas.adaptive_remove('other.example.com')
                self.assertEqual(atlas.adaptive_suppressed(),{'a.example.com'})

    def test_hostname_list_is_restricted_to_write_acl(self):
        acl=json.loads((Path(__file__).resolve().parents[1]/'root/usr/share/rpcd/acl.d/atlas.json').read_text())['luci-app-atlas']
        self.assertNotIn('adaptive_list',acl['read']['ubus']['atlas'])
        self.assertIn('adaptive_list',acl['write']['ubus']['atlas'])

    def test_supervisor_feeds_failed_direct_events_to_bounded_worker(self):
        current=state_with_node();current['settings']['adaptive_proxy_enabled']=True
        config=core.make_config(current)
        sample=b'ERROR connection: open connection to media.example.com:443 using outbound/direct[direct]: connect: connection refused\n'
        class Child:
            stderr=io.BytesIO(sample+sample)
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp);statepath=run/'state.json';configpath=run/'config.json'
            config['experimental']['cache_file']['path']=str(run/'cache'/'cache.db')
            statepath.write_text(json.dumps(current));configpath.write_text(json.dumps(config))
            observed=[]
            def supervise(*args,**kwargs):
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    try:rules=json.loads((run/'adaptive-rules.json').read_text())['rules']
                    except (OSError,ValueError):rules=[]
                    if rules:
                        observed.extend(rules[0]['domain']);return 0
                    time.sleep(.02)
                self.fail('worker did not apply a verified temporary rule')
            with patch.object(atlas,'RUN',run),patch.object(atlas,'DATA',run),patch.object(atlas,'STATE',statepath),patch.object(atlas,'CONFIG',configpath), \
                 patch.object(atlas,'restore_start_network',return_value=True),patch.object(atlas,'startup_report'), \
                 patch.object(atlas,'prepare_engine_start',side_effect=lambda c:c),patch.object(atlas,'check'), \
                 patch.object(atlas.subprocess,'Popen',return_value=Child()),patch.object(start_guard,'supervise',side_effect=supervise), \
                 patch.object(adaptive_routing,'atlas_verifier',return_value=lambda host:True):
                self.assertEqual(atlas.supervise_engine(),0)
            self.assertEqual(observed,['media.example.com'])
            self.assertEqual(json.loads((run/'adaptive-rules.json').read_text())['rules'],[])

    def test_supervisor_correlates_device_sni_without_exposing_debug_log(self):
        current=state_with_node();current['settings']['adaptive_proxy_enabled']=True
        config=core.make_config(current)
        sample=(b'2026-11-21 \x1b[36mDEBUG\x1b[0m [42 10ms] router: sniffed protocol: tls, domain: media.example.com\n'
                b'2026-11-21 \x1b[31mERROR\x1b[0m [42 12ms] connection: open connection to 1.1.1.1:443 using outbound/direct[direct]: refused\n'
                b'2026-11-21 \x1b[36mDEBUG\x1b[0m [43 10ms] router: sniffed protocol: tls, domain: media.example.com\n'
                b'2026-11-21 \x1b[31mERROR\x1b[0m [43 12ms] connection: open connection to 1.1.1.1:443 using outbound/direct[direct]: refused\n')
        class Child:stderr=io.BytesIO(sample)
        class Log:
            def __init__(self):self.buffer=io.BytesIO()
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp);statepath=run/'state.json';configpath=run/'config.json'
            config['experimental']['cache_file']['path']=str(run/'cache'/'cache.db')
            statepath.write_text(json.dumps(current));configpath.write_text(json.dumps(config));observed=[];log=Log()
            def supervise(*args,**kwargs):
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    rules=json.loads((run/'adaptive-rules.json').read_text())['rules']
                    if rules:observed.extend(rules[0]['domain']);return 0
                    time.sleep(.02)
                self.fail('worker missed a device destination')
            with patch.object(atlas,'RUN',run),patch.object(atlas,'DATA',run),patch.object(atlas,'STATE',statepath),patch.object(atlas,'CONFIG',configpath), \
                 patch.object(atlas,'restore_start_network',return_value=True),patch.object(atlas,'startup_report'), \
                 patch.object(atlas,'prepare_engine_start',side_effect=lambda c:c),patch.object(atlas,'check'), \
                 patch.object(atlas.subprocess,'Popen',return_value=Child()),patch.object(start_guard,'supervise',side_effect=supervise), \
                 patch.object(adaptive_routing,'atlas_verifier',return_value=lambda host:True),patch.object(atlas.sys,'stderr',log):
                self.assertEqual(atlas.supervise_engine(),0)
            self.assertEqual(observed,['media.example.com'])
            self.assertNotIn(b'DEBUG',log.buffer.getvalue())
            self.assertIn(b'ERROR',log.buffer.getvalue())

    def test_saved_but_unapplied_enable_does_not_break_old_engine(self):
        applied=state_with_node();config=core.make_config(applied)
        saved=copy.deepcopy(applied);saved['settings']['adaptive_proxy_enabled']=True
        class Child:pass
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp);statepath=run/'state.json';configpath=run/'config.json'
            config['experimental']['cache_file']['path']=str(run/'missing'/'cache.db')
            statepath.write_text(json.dumps(saved));configpath.write_text(json.dumps(config))
            with patch.object(atlas,'RUN',run),patch.object(atlas,'DATA',run),patch.object(atlas,'STATE',statepath),patch.object(atlas,'CONFIG',configpath), \
                 patch.object(atlas,'restore_start_network',return_value=True),patch.object(atlas,'startup_report'), \
                 patch.object(atlas,'prepare_engine_start',side_effect=lambda c:c),patch.object(atlas,'check'), \
                 patch.object(atlas.subprocess,'Popen',return_value=Child()) as popen,patch.object(start_guard,'supervise',return_value=0):
                self.assertEqual(atlas.supervise_engine(),0)
                self.assertIsNone(popen.call_args.kwargs['stderr'])
                self.assertTrue((run/'missing').is_dir())

    def test_saved_but_unapplied_disable_filters_debug_and_clears_rules(self):
        applied=state_with_node();applied['settings']['adaptive_proxy_enabled']=True;config=core.make_config(applied)
        saved=copy.deepcopy(applied);saved['settings']['adaptive_proxy_enabled']=False
        class Child:stderr=io.BytesIO(b'DEBUG router: sensitive.example.com\nERROR connection failed\n')
        class Log:
            def __init__(self):self.buffer=io.BytesIO()
        with tempfile.TemporaryDirectory() as temp:
            run=Path(temp);statepath=run/'state.json';configpath=run/'config.json';log=Log()
            config['experimental']['cache_file']['path']=str(run/'cache'/'cache.db')
            statepath.write_text(json.dumps(saved));configpath.write_text(json.dumps(config))
            (run/'adaptive-rules.json').write_text('{"version":3,"rules":[{"domain":["old.example.com"]}]}')
            with patch.object(atlas,'RUN',run),patch.object(atlas,'DATA',run),patch.object(atlas,'STATE',statepath),patch.object(atlas,'CONFIG',configpath), \
                 patch.object(atlas,'restore_start_network',return_value=True),patch.object(atlas,'startup_report'), \
                 patch.object(atlas,'prepare_engine_start',side_effect=lambda c:c),patch.object(atlas,'check'), \
                 patch.object(atlas.subprocess,'Popen',return_value=Child()) as popen,patch.object(start_guard,'supervise',return_value=0),patch.object(atlas.sys,'stderr',log):
                self.assertEqual(atlas.supervise_engine(),0)
                self.assertEqual(popen.call_args.kwargs['stderr'],subprocess.PIPE)
            self.assertNotIn(b'DEBUG',log.buffer.getvalue());self.assertIn(b'ERROR',log.buffer.getvalue())
            self.assertEqual(json.loads((run/'adaptive-rules.json').read_text())['rules'],[])


if __name__=='__main__':unittest.main()
