import base64,copy,http.server,json,os,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,atlas
from test_expert_sections import sample,section
import test_extensions_rpc as fixtures
from version import VERSION

PAYLOAD={'version':3,'rules':[{'type':'logical','mode':'and','rules':[{'domain':['exact.example.org']},{'port':[443]},{'network':['tcp']}]},{'domain_regex':['^video\\.'], 'invert':True}]}

class CompleteRules(unittest.TestCase):
    setUp=fixtures.ExtensionsRPC.setUp
    tearDown=fixtures.ExtensionsRPC.tearDown
    def test_reported_version_matches_package(self):
        import re
        package=re.search(r'^PKG_VERSION:=(.+)$',(Path(__file__).resolve().parents[1]/'Makefile').read_text(),re.M)[1]
        self.assertEqual(VERSION,package)
        self.assertEqual(atlas.public_status()['version'],package)

    def test_full_json_import_backup_and_public_privacy(self):
        with mock.patch.object(atlas,'run',return_value=SimpleNamespace(returncode=0)):
            result=atlas.dispatch('import_rules',{'content':base64.b64encode(json.dumps(PAYLOAD).encode()).decode(),'target':'proxy'})
        self.assertEqual(result['rules'],2)
        saved=atlas.state();item=saved['settings']['remote_lists'][0]
        self.assertEqual(item['source_rules'],PAYLOAD)
        definition=core.make_config(saved,tun=False)['route']['rule_set'][0]
        self.assertEqual(definition['type'],'inline');self.assertEqual(definition['rules'],PAYLOAD['rules'])
        self.assertNotIn('source_rules',atlas.public_status()['settings']['remote_lists'][0])
        backup=atlas.dispatch('export_backup',{})['backup']
        with mock.patch.object(atlas,'run',return_value=SimpleNamespace(returncode=0)):
            atlas.dispatch('restore_backup',{'content':json.dumps(backup)})
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['source_rules'],PAYLOAD)
        submitted=atlas.public_status()['settings']
        atlas.dispatch('save_settings',{'settings':submitted})
        self.assertEqual(atlas.state()['settings']['remote_lists'][0]['source_rules'],PAYLOAD)

    def test_rejected_json_update_keeps_previous_file_and_state(self):
        state=sample();state['settings']['remote_lists']=[dict(id='c'*16,name='source',url='https://example.org/rules.json',policy='proxy',format='json',enabled=True,source_cached=True,source_rules=PAYLOAD)]
        state['settings']=core.validate_settings(state['settings']);item=state['settings']['remote_lists'][0]
        path=self.root/'rules'/('c'*16+'.json');atlas.atomic_bytes(path,json.dumps(PAYLOAD).encode())
        previous=copy.deepcopy(item);previous_bytes=path.read_bytes()
        with mock.patch.object(atlas,'run',return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(core.AtlasError):atlas.store_rule_set(state,item,b'{"version":3,"rules":[{"nonsense":true}]}',source=True)
        self.assertEqual(item,previous);self.assertEqual(path.read_bytes(),previous_bytes)

    def test_json_import_before_proxy_profiles_does_not_enable_direct_proxy_fallback(self):
        atlas.atomic(atlas.STATE,core.defaults())
        with mock.patch.object(atlas,'run',return_value=SimpleNamespace(returncode=0)):
            atlas.dispatch('import_rules',{'content':base64.b64encode(json.dumps(PAYLOAD).encode()).decode(),'target':'direct'})
        config=core.make_config(atlas.state(),tun=False)
        self.assertEqual(next(x for x in config['outbounds'] if x['tag']=='local-only-block')['type'],'block')
        self.assertEqual(config['route']['rule_set'][0]['rules'],PAYLOAD['rules'])

    def test_large_lists_sources_and_interfaces(self):
        settings=sample()['settings']
        entries=['d%d.example.org'%i for i in range(50001)]
        settings['remote_lists']=[dict(name=str(i),url='https://example.org/%d.txt'%i,policy='proxy',format='domains',enabled=True,domains=entries if i==0 else []) for i in range(100)]
        settings['sections']=[section(source_interfaces=['br%d'%i for i in range(12)])]
        normalized=core.validate_settings(settings)
        self.assertEqual(len(normalized['remote_lists']),100)
        self.assertEqual(len(normalized['remote_lists'][0]['domains']),50001)
        self.assertEqual(len(normalized['sections'][0]['source_interfaces']),12)
        for value in (0,8*1024*1024):self.assertEqual(core.validate_settings({'list_max_bytes':value})['list_max_bytes'],value)
        self.assertEqual(len(core.validate_settings({'domains':entries[:1001]})['domains']),1001)
        settings['sections'][0]['domains']=entries[:1001]
        self.assertEqual(len(core.validate_settings(settings)['sections'][0]['domains']),1001)
        from outbounds import outbound_graph
        self.assertEqual(len(outbound_graph([dict(type='direct',tag='n%d'%i) for i in range(65)])),65)

    @unittest.skipUnless(os.environ.get('ATLAS_RULE_ENGINE'),'Set ATLAS_RULE_ENGINE')
    def test_complete_json_accepted_by_actual_engine(self):
        state=sample();state['settings']['remote_lists']=[dict(id='d'*16,name='json',url='https://example.org/full.json',policy='proxy',format='json',enabled=True)]
        state['settings']=core.validate_settings(state['settings'])
        with mock.patch.object(atlas,'BINARY',os.environ['ATLAS_RULE_ENGINE']):
            atlas.store_rule_set(state,state['settings']['remote_lists'][0],json.dumps(PAYLOAD).encode(),source=True)
        config=self.root/'real-config.json';config.write_text(json.dumps(core.make_config(state,tun=False)))
        result=subprocess.run([os.environ['ATLAS_RULE_ENGINE'],'check','-c',str(config)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

class DownloadRetries(unittest.TestCase):
    def test_real_http_retries_only_temporary_errors_and_preserves_query(self):
        seen=[];status={'codes':[503,503,200]}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path);self.send_response(status['codes'].pop(0));self.end_headers();self.wfile.write(b'example.org\n')
            def log_message(self,*args):pass
        with http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                url='http://127.0.0.1:%d/list?token=x#ignored'%server.server_port
                with mock.patch.object(atlas.time,'sleep') as sleep:
                    self.assertEqual(atlas.fetch_rule_list(url,'auto',allow_private=True)[0],['example.org'])
                    self.assertEqual(sleep.call_count,2)
                self.assertEqual(seen,['/list?token=x']*3)
                status['codes']=[404]
                with self.assertRaises(core.AtlasError):atlas.fetch_rule_list(url,'auto',allow_private=True)
                self.assertEqual(len(seen),4)
                status['codes']=[200]
                with self.assertRaises(core.AtlasError):atlas.fetch_rule_bytes(url,allow_private=True,max_bytes=4)
                self.assertEqual(len(seen),5)
                status['codes']=[200]
                self.assertEqual(atlas.fetch_rule_bytes(url,allow_private=True,max_bytes=0),b'example.org\n')
            finally:server.shutdown();worker.join()
