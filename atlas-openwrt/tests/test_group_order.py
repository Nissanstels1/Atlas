import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import core
from test_expert_sections import sample,section

class GroupOrder(unittest.TestCase):
    def config(self,ordered):
        s=sample();s['settings']['group_order']=ordered
        s['settings']['sections']=[section('first',id='a'*16,outbound_config=[],domains=['first.example'],auto_interval_seconds=60,resolver='https://dns.google/dns-query'),section('second',id='c'*16,outbound_config=[],domains=['example.org'],auto_interval_seconds=60,resolver='https://cloudflare-dns.com/dns-query')]
        s['settings']['remote_lists']=[dict(id='d'*16,name='first list',url='https://example.org/domains.txt',format='domains',policy='proxy',enabled=True,section='a'*16,domains=['example.org'],cidrs=[])]
        return core.make_config(s)
    def test_group_list_precedes_next_group_domain(self):
        c=self.config(True)
        rules=c['route']['rules']
        first=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('outbound','').startswith('section_'+'a'*16))
        second=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('outbound','').startswith('section_'+'c'*16))
        self.assertLess(first,second)
    def test_old_order_remains_until_explicitly_enabled(self):
        c=self.config(False);rules=c['route']['rules']
        first=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('outbound','').startswith('section_'+'a'*16))
        second=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('outbound','').startswith('section_'+'c'*16))
        self.assertLess(second,first)
    def test_group_dns_matches_group_route_order(self):
        c=self.config(True);rules=c['dns']['rules']
        first_tag=next(s['tag'] for s in c['dns']['servers'] if s.get('server')=='dns.google')
        second_tag=next(s['tag'] for s in c['dns']['servers'] if s.get('server')=='cloudflare-dns.com')
        first=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('server')==first_tag)
        second=next(i for i,r in enumerate(rules) if 'example.org' in r.get('domain_suffix',[]) and r.get('server')==second_tag)
        self.assertLess(first,second)

    def test_block_list_belongs_to_block_group(self):
        s=sample();s['settings']['group_order']=True
        s['settings']['sections']=[section('deny',id='a'*16,outbound_config=[],policy='block',domains=[])]
        s['settings']['remote_lists']=[dict(id='d'*16,name='deny list',url='https://example.org/list',format='domains',policy='block',enabled=True,section='a'*16,domains=['example.org'],cidrs=[])]
        c=core.make_config(s)
        self.assertTrue(any(r.get('action')=='reject' and 'example.org' in r.get('domain_suffix',[]) for r in c['route']['rules']))

