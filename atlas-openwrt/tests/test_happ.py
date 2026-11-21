import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'))
import core, happ

def b64(b):return base64.b64encode(b)
def pairs(b):return b''.join(b[i:i+2][::-1] for i in range(0,len(b),2))
def shuffle(b):return b''.join(b[i+2:i+4]+b[i:i+2] for i in range(0,len(b)//4*4,4))+b[len(b)//4*4:]

class HappImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        der=cls.rsa.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        cls.keys={'crypt5':{'abcdwxyz':b64(der).decode()},'aes':{'test':b64(b'0123456789abcdef').decode()}}
    def link(self,url,salted):
        key=bytes(range(32));salt=b'12345678';nonce=b'fixtureNonce'
        actual=bytes(x^salt[i%8] for i,x in enumerate(key)) if salted else key
        ct=b64(ChaCha20Poly1305(actual).encrypt(nonce,pairs(b64(url.encode())),None))
        wrapped=b64(self.rsa.public_key().encrypt(pairs(b64(key)),padding.PKCS1v15()))
        header=nonce+(b'!!'+salt if salted else b'')
        packet=b'abcd'+header+str(len(ct)).encode()+b':'+ct+wrapped+b'wxyz'
        return 'happ://crypt5/'+shuffle(packet).decode()
    def test_both_layouts_become_https_urls(self):
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            for salted in (False,True):
                self.assertEqual(core.subscription_url(self.link('https://example.com/sub?key=test',salted)),'https://example.com/sub?key=test')
    def test_decrypted_non_https_rejected(self):
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            with self.assertRaises(core.AtlasError):core.subscription_url(self.link('file:///etc/passwd',True))
    def test_unknown_marker(self):
        with mock.patch.object(happ,'_keys',return_value={'crypt5':{},'aes':{}}):
            with self.assertRaises(happ.HappError):happ.decrypt_link(self.link('https://example.com',True))
    def test_malformed_and_oversized_links(self):
        for link in ['happ://crypt5/a','happ://crypt5/'+'x'*20000,'happ://crypt5/\ninvalid']:
            with self.assertRaises(happ.HappError):happ.decrypt_link(link)
    def test_link_tamper_rejected(self):
        link=self.link('https://example.com/sub',True);i=len('happ://crypt5/')+65
        link=link[:i]+('X' if link[i]!='X' else 'Y')+link[i+1:]
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            with self.assertRaises(happ.HappError):happ.decrypt_link(link)
    def body(self):
        plain=b'vless://11111111-1111-4111-8111-111111111111@example.com:443#EE-Test'
        ct=AESGCM(b'0123456789abcdef').encrypt(b'kkkkkkkkkkkk',plain,None)
        return plain,b64(ct[:-16]),b64(ct[-16:]).decode()
    def test_body_becomes_importable_profiles(self):
        plain,body,tag=self.body()
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            decoded=happ.decrypt_body('https://example.com/sub?key=test',body,tag)
        self.assertEqual(decoded,plain);self.assertEqual(len(core.parse_subscription(decoded)['nodes']),1)

    def test_xray_imports_websocket_without_flattening_a_chain(self):
        uid = '11111111-1111-4111-8111-111111111111'
        def outbound(network):
            stream = {'network': network, 'security': 'tls',
                      'tlsSettings': {'serverName': 'cdn.example.com', 'fingerprint': 'chrome',
                                      'enableSessionResumption': True}}
            if network == 'ws':
                stream['tlsSettings']['alpn'] = ['http/1.1']
                stream['wsSettings'] = {'host': 'api.example.net', 'headers': {}, 'path': '/api/test'}
            else:
                stream['tcpSettings'] = {}
            return {'tag': network, 'protocol': 'vless', 'settings': {'vnext': [{'address': 'cdn.example.com',
                    'port': 443, 'users': [{'id': uid, 'encryption': 'none', 'flow': ''}]}]},
                    'streamSettings': stream, 'mux': {'enabled': False}}
        tcp, ws, chain = outbound('tcp'), outbound('ws'), outbound('tcp')
        ws['mux'] = {'enabled': True, 'concurrency': 8}
        chain['streamSettings']['sockopt'] = {'dialerProxy': 'ws'}
        doc = [{'remarks': 'Германия', 'outbounds': [tcp, ws, chain, {'protocol': 'blackhole'}]}]
        parsed = core.parse_subscription(json.dumps(doc).encode())
        self.assertEqual(parsed['format'], 'Xray JSON')
        self.assertEqual(len(parsed['nodes']), 2)
        self.assertEqual(parsed['warnings'], ['Цепочки подключений пока не импортированы: 1',
                                              'Профили Xray добавлены без мультиплексирования: 1'])
        imported = next(x for x in parsed['nodes'] if x['outbound'].get('transport', {}).get('type') == 'ws')
        uri = ('vless://' + uid + '@cdn.example.com:443?encryption=none&type=ws&security=tls'
               '&sni=cdn.example.com&fp=chrome&alpn=http%2F1.1&host=api.example.net&path=%2Fapi%2Ftest#Germany')
        self.assertEqual(imported['outbound'], core.uri_node(uri)['outbound'])
        self.assertIn('WebSocket', imported['name'])

    def test_xray_does_not_weaken_tls_or_use_chained_only_profiles(self):
        entry = {'protocol':'vless', 'settings':{'vnext':[{'address':'example.com', 'port':443,
                 'users':[{'id':'11111111-1111-4111-8111-111111111111'}]}]},
                 'streamSettings':{'network':'tcp','security':'tls',
                                   'tlsSettings':{'serverName':'example.com','allowInsecure':True}}}
        for item in (entry, dict(entry, streamSettings={'network':'tcp','sockopt':{'dialerProxy':'elsewhere'}})):
            with self.subTest(item=item), self.assertRaises(core.AtlasError):
                core.parse_subscription(json.dumps([{'outbounds':[item]}]).encode())

    def test_xray_country_variants_keep_a_safe_loopback_chain(self):
        uid = '11111111-1111-4111-8111-111111111111'
        def vless(tag, server, network='tcp'):
            stream = {'network':network, 'security':'tls', 'tlsSettings':{'serverName':server}}
            if network == 'ws': stream['wsSettings'] = {'host':'front.example', 'path':'/route'}
            return {'tag':tag, 'protocol':'vless', 'settings':{'vnext':[{'address':server,'port':443,
                    'users':[{'id':uid,'encryption':'none'}]}]}, 'streamSettings':stream}
        direct, ws, chained = vless('base','node.example'), vless('cdn','cdn.example','ws'), vless('chain','node.example')
        chained['streamSettings']['sockopt'] = {'dialerProxy':'internal-socks'}
        auth = {'user':'fixture','pass':'fixture-password'}
        config = {'remarks':'Финляндия', 'inbounds':[{'tag':'local','protocol':'socks','listen':'127.0.0.1',
                  'port':10811,'settings':{'auth':'password','accounts':[auth],'udp':True}}],
                  'outbounds':[direct,ws,chained,{'tag':'block','protocol':'blackhole'},
                  {'tag':'internal-socks','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1',
                   'port':10811,'users':[auth]}]}}, {'tag':'loop','protocol':'loopback','settings':{'inboundTag':'virtual'}}],
                  'routing':{'domainStrategy':'IPIfNonMatch','rules':[
                  {'type':'field','ip':['::/0'],'outboundTag':'block'},
                  {'type':'field','network':'udp','port':'443','outboundTag':'block'},
                  {'type':'field','inboundTag':['local'],'balancerTag':'a'},
                  {'type':'field','inboundTag':['virtual'],'balancerTag':'b'}],
                  'balancers':[{'tag':'a','selector':['missing-'],'fallbackTag':'loop','strategy':{'type':'leastLoad'}},
                               {'tag':'b','selector':['cdn'],'fallbackTag':'block','strategy':{'type':'leastLoad'}}]}}
        result = core.parse_subscription(json.dumps([config]).encode())
        self.assertEqual(len(result['nodes']), 3)
        node = next(n for n in result['nodes'] if n.get('chain'))
        self.assertTrue(node['chain_ipv4_only'])
        self.assertEqual(node['chain'][0]['transport']['type'], 'ws')
        current = core.defaults()
        current['subscriptions'] = [{'id':'a'*16,'name':'Test','url':'https://example.com/sub',
                                     'nodes':result['nodes'],'enabled':True}]
        rendered = core.make_config(current, tun=False)
        outs = {x['tag']:x for x in rendered['outbounds']}
        tag = 'a'*16 + node['id']
        self.assertEqual(outs[tag]['domain_resolver'], {'server':'bootstrap','strategy':'ipv4_only'})
        hop = outs[outs[tag]['detour']]
        self.assertEqual(hop['type'],'vless')
        self.assertEqual(hop['transport']['type'],'ws')
        self.assertNotIn(hop['tag'], outs['auto']['outbounds'])
        # A public direct fallback is never silently substituted into a chain.
        unsafe = copy.deepcopy(config)
        unsafe['outbounds'].append({'tag':'direct','protocol':'freedom'})
        unsafe['routing']['balancers'][1]['fallbackTag'] = 'direct'
        blocked = core.parse_subscription(json.dumps([unsafe]).encode())
        self.assertFalse(any(n.get('chain') for n in blocked['nodes']))
        self.assertTrue(any('Цепочки' in warning for warning in blocked['warnings']))
        invalid_auth = copy.deepcopy(config)
        invalid_auth['outbounds'][4]['settings']['servers'][0]['users'] = [{'user':'fixture','pass':'wrong'}]
        blocked = core.parse_subscription(json.dumps([invalid_auth]).encode())
        self.assertFalse(any(n.get('chain') for n in blocked['nodes']))

    def test_xray_keeps_named_variants_with_identical_outbounds(self):
        uid = '11111111-1111-4111-8111-111111111111'
        ws = {'tag':'cdn','protocol':'vless','settings':{'vnext':[{'address':'cdn.example','port':443,
              'users':[{'id':uid}]}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/'}}}
        body = [{'name':'Финляндия','outbounds':[ws]}, {'name':'Германия','outbounds':[copy.deepcopy(ws)]}]
        result = core.parse_subscription(json.dumps(body).encode())
        self.assertEqual(len(result['nodes']),2)
        self.assertEqual(len({n['id'] for n in result['nodes']}),2)
        self.assertTrue(any('Финляндия' in n['name'] for n in result['nodes']))
        self.assertTrue(any('Германия' in n['name'] for n in result['nodes']))
    def test_authentication_required(self):
        _,body,tag=self.body()
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            with self.assertRaises(happ.HappError):happ.decrypt_body('https://example.com/?key=test',body,b64(bytes(16)).decode())
    def test_unknown_or_ambiguous_body_key(self):
        _,body,tag=self.body()
        with mock.patch.object(happ,'_keys',return_value=self.keys):
            for query in ['','?key=unknown','?key=test&key=other']:
                with self.assertRaises(happ.HappError):happ.decrypt_body('https://example.com/'+query,body,tag)
    def test_plain_subscription_not_mistaken_for_encrypted(self):
        body=b'ordinary response';self.assertEqual(happ.decrypt_body('https://example.com/?key=test',body,None),body)
    def test_known_compatibility_data_includes_key11(self):
        keys=happ._keys();self.assertIn('key11',keys['aes']);self.assertEqual(len(base64.b64decode(keys['aes']['key11'])),16)
