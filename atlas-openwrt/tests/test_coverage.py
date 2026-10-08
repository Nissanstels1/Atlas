import json,sys,unittest,os,tempfile,subprocess
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core,atlas,planner,firewall_diag
from test_expert_sections import sample,section

class Coverage(unittest.TestCase):
    def test_query_is_forwarded_intact_when_downloading_rule_list(self):
        url='https://example.org/list?token=a%2Fb&version=2'
        response=mock.MagicMock()
        response.__enter__.return_value=response
        response.geturl.return_value=url
        response.read.side_effect=[b'example.org\n',b'']
        opener=mock.Mock();opener.open.return_value=response
        with mock.patch.object(atlas,'require_public_https',return_value=url), mock.patch.object(atlas.urllib.request,'build_opener',return_value=opener):
            self.assertEqual(atlas.fetch_rule_list(url,'auto')[0],['example.org'])
        self.assertEqual(opener.open.call_args.args[0].full_url,url)

    def test_extensionless_local_list_is_read_and_parsed(self):
        self.assertEqual(core.rule_list_url('file:///opt/lists/domains'),'file:///opt/lists/domains')
        with mock.patch.object(atlas,'Path') as path:
            path.return_value.parents=[]
            path.return_value.is_symlink.return_value=False
            path.return_value.is_file.return_value=True
            path.return_value.open.return_value.__enter__.return_value.read.return_value=b'example.org\n'
            self.assertEqual(atlas.fetch_rule_list('file:///opt/lists/domains','auto')[0],['example.org'])

    @unittest.skipUnless(os.name=='posix' and os.environ.get('ATLAS_TEST_ENGINE'),'Native Linux TUN engine required')
    def test_exact_interface_config_accepted_by_real_engine(self):
        s=sample();s['settings']['sections']=[section(source_interfaces=['br-a','br-b'])]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';path.write_text(json.dumps(core.make_config(s)))
            result=subprocess.run([os.environ['ATLAS_TEST_ENGINE'],'check','-c',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
    def test_over_256_sections_and_selector_choices(self):
        s=sample()['settings'];s['sections']=[section(str(i),enabled=False) for i in range(300)]
        s['section_choices']={str(i):'entry' for i in range(300)}
        self.assertEqual(len(core.validate_settings(s)['sections']),300)
    def test_interfaces_are_exact_even_when_clients_share_subnet(self):
        s=sample();s['settings']['sections']=[section('A',source_interfaces=['br-a']),section('B',source_interfaces=['br-b'])]
        cfg=core.make_config(s)
        for name,index in [('br-a',0),('br-b',1)]:
            q=dict(domain='example.org',ip='1.1.1.1',source_ip='192.168.1.2',port=443,network='tcp',protocol='tls',inbound=core.interface_inbound(name))
            r=planner.explain_route(cfg,q)
            self.assertTrue(r['certain']);self.assertIn(core.validate_settings(s['settings'])['sections'][index]['id'],r['outbound'])
        self.assertEqual(next(x for x in cfg['inbounds'] if x['tag']=='tun')['exclude_interface'],['br-a','br-b'])
    def test_http_lists_public_and_no_https_downgrade(self):
        with mock.patch.object(atlas.socket,'getaddrinfo',return_value=[(0,0,0,'',('1.1.1.1',80))]):
            self.assertEqual(atlas.require_public_https('http://example.org/list.txt'),'http://example.org/list.txt')
        req=atlas.urllib.request.Request('https://example.org/list.txt')
        with self.assertRaises(core.AtlasError):atlas.PublicHTTPSRedirect().redirect_request(req,None,302,'',{},'http://example.org/list.txt')
        with self.assertRaises(core.AtlasError):core.subscription_url('http://example.org/sub')
    def test_custom_local_paths(self):
        s=core.validate_settings({'cache_storage':'external','cache_custom_path':'/opt/data/cache.db','config_storage':'external','config_custom_dir':'/opt/data/atlas'})
        self.assertEqual(s['cache_custom_path'],'/opt/data/cache.db')
        self.assertEqual(core.rule_list_url('file:///opt/data/rules.txt'),'file:///opt/data/rules.txt')
    def test_nft_diagnostics_reports_missing_tables_and_commands(self):
        calls=[]
        def run(cmd,timeout):
            calls.append(cmd);return SimpleNamespace(returncode=0,stdout=json.dumps({'nftables':[{'table':{'family':'inet','name':'fw4'}}]}).encode() if '-j' in cmd else b'')
        result=firewall_diag.inspect(run,{'inbounds':[{'type':'tun','interface_name':'atlas0'}]})
        checks={x['id']:x['ok'] for x in result['checks']}
        self.assertTrue(checks['fw4']);self.assertFalse(checks['atlas0']);self.assertEqual(len(calls),5)
        self.assertTrue(all('show' in c or 'list' in c for c in calls))
    def test_empty_direct_expert_dns_does_not_use_invalid_detour(self):
        s=sample();s['subscriptions']=[];s['settings']['sections']=[section(outbound_config=[dict(type='direct',tag='entry')])]
        cfg=core.make_config(s)
        self.assertNotIn('detour',next(x for x in cfg['dns']['servers'] if x['tag']=='secure'))
    def test_firewall_scoped_capture_only_targets_own_tun_zone(self):
        calls=[]
        def run(cmd,timeout):calls.append(cmd);return SimpleNamespace(returncode=0,stdout=b'')
        with mock.patch.object(atlas,'run',side_effect=run):atlas.manage_ingress_firewall(True)
        self.assertIn(['/sbin/uci','add_list','firewall.atlas_ingress.device=atli+'],calls)
        self.assertIn(['/sbin/uci','set','firewall.atlas_ingress_capture.dest=atlas_ingress'],calls)
        self.assertFalse(any('atlas_kill_switch' in str(x) for x in calls))
