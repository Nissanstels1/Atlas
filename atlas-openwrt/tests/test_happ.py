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
