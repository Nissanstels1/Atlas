import http.server, json, os, subprocess, sys, tempfile, threading, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,core
from test_expert_sections import sample

class SourcePermissions(unittest.TestCase):
    def test_benchmark_report_is_repeatable_and_does_not_expose_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json';state.write_text(json.dumps(sample()))
            tool=Path(__file__).resolve().parents[1]/'tools/benchmark-router.py'
            result=subprocess.run([sys.executable,str(tool),'--state',str(state),'--iterations','3'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads(result.stdout)
            self.assertTrue(report['deterministic_config']);self.assertEqual(report['iterations'],3)
            self.assertNotIn('private-password',result.stdout);self.assertNotIn('example.com',result.stdout)

    def test_private_flags_are_validated_and_preserved(self):
        source=dict(name='NAS',url='http://nas.lan/domains',policy='proxy',format='auto',enabled=True,allow_private=True,allow_symlinks=True)
        normalized=core.validate_settings({'remote_lists':[source]})['remote_lists'][0]
        self.assertTrue(normalized['allow_private']);self.assertTrue(normalized['allow_symlinks'])
        for flag in ('allow_private','allow_symlinks'):
            with self.assertRaises(core.AtlasError):core.validate_settings({'remote_lists':[dict(source,**{flag:'true'})]})

    def test_real_private_http_download_requires_permission(self):
        seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'example.org\n')
            def log_message(self,*args):pass
        with http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                url='http://127.0.0.1:%d/domains?version=2'%server.server_port
                with self.assertRaises(core.AtlasError):atlas.fetch_rule_list(url,'auto')
                self.assertEqual(seen,[])
                self.assertEqual(atlas.fetch_rule_list(url,'auto',allow_private=True)[0],['example.org'])
                self.assertEqual(seen,['/domains?version=2'])
            finally:server.shutdown();worker.join()

    def test_redirect_uses_same_private_permission(self):
        request=atlas.urllib.request.Request('http://example.org/list')
        target='http://127.0.0.1/list'
        with self.assertRaises(core.AtlasError):atlas.PublicHTTPSRedirect().redirect_request(request,None,302,'',{},target)
        self.assertEqual(atlas.PublicHTTPSRedirect(True).redirect_request(request,None,302,'',{},target).full_url,target)
        with self.assertRaises(core.AtlasError):atlas.PublicHTTPSRedirect(True).redirect_request(atlas.urllib.request.Request('https://example.org/list'),None,302,'',{},target)

    @unittest.skipUnless(os.name=='posix','Actual symlinks require POSIX')
    def test_actual_symlink_file_and_parent_and_scheduler_target_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'real').mkdir();target=root/'real'/'domains';target.write_text('example.org\n')
            (root/'alias').symlink_to(root/'real',target_is_directory=True)
            link=root/'list';link.symlink_to(target)
            for path in (link,root/'alias'/'domains'):
                url=path.as_uri()
                with self.assertRaises(core.AtlasError):atlas.local_rule_bytes(url)
                self.assertEqual(atlas.fetch_rule_list(url,'auto',allow_symlinks=True)[0],['example.org'])
            previous=atlas.local_rule_version(link.as_uri());target.write_text('another.example.org\n')
            self.assertNotEqual(atlas.local_rule_version(link.as_uri()),previous)
            broken=root/'broken';broken.symlink_to(root/'missing')
            with self.assertRaises(core.AtlasError):atlas.local_rule_bytes(broken.as_uri(),allow_symlinks=True)
