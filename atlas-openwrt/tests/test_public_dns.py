import ipaddress,json,os,sys,unittest
from pathlib import Path
from unittest import mock
if os.name=='nt':sys.modules.setdefault('fcntl',mock.Mock())
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,public_dns

class PublicDNS(unittest.TestCase):
    def test_fakeip_is_checked_against_public_dns(self):
        active={'dns':{'servers':[{'type':'fakeip','inet4_range':'198.18.0.0/15'}]}}
        with mock.patch.object(atlas.socket,'getaddrinfo',return_value=[(None,None,None,None,('198.18.0.4',443))]),mock.patch.object(atlas,'read_json',return_value=active),mock.patch.object(public_dns,'public_addresses',return_value=[ipaddress.ip_address('8.8.8.8')]) as lookup:
            self.assertEqual(atlas.require_public_https('https://example.org/'),'https://example.org/')
            lookup.assert_called_once_with('example.org',None)

    def test_private_addresses_and_fakeip_literals_are_not_relaxed(self):
        active={'dns':{'servers':[{'type':'fakeip','inet4_range':'198.18.0.0/15'}]}}
        for url,address in [('https://example.org/','192.168.1.2'),('https://198.18.0.4/','198.18.0.4')]:
            with mock.patch.object(atlas.socket,'getaddrinfo',return_value=[(None,None,None,None,(address,443))]),mock.patch.object(atlas,'read_json',return_value=active),mock.patch.object(public_dns,'public_addresses') as lookup:
                with self.assertRaises(atlas.AtlasError):atlas.require_public_https(url)
                lookup.assert_not_called()

    def test_public_lookup_rejects_nonpublic_answer_and_closes_socket(self):
        response=mock.Mock(status=200);response.read.return_value=json.dumps({'Status':0,'Answer':[{'type':1,'data':'127.0.0.1'}]}).encode()
        connection=mock.Mock();connection.getresponse.return_value=response
        with mock.patch.object(public_dns.http.client,'HTTPSConnection',return_value=connection):
            with self.assertRaises(ValueError):public_dns.public_addresses('example.org')
        connection.close.assert_called_once()

    def test_proxy_lookup_checks_both_families_without_direct_fallback(self):
        connections=[]
        def connect(*args,**kwargs):
            connection=mock.Mock();response=mock.Mock(status=200)
            response.read.return_value=json.dumps({'Status':0,'Answer':[{'type':1,'data':'8.8.8.8'}]} if not connections else {'Status':0}).encode()
            connection.getresponse.return_value=response;connections.append(connection);return connection
        with mock.patch.object(public_dns.http.client,'HTTPSConnection',side_effect=connect) as factory:
            self.assertEqual(public_dns.public_addresses('example.org','http://user:password@127.0.0.1:18081'),[ipaddress.ip_address('8.8.8.8')])
        self.assertEqual(len(connections),2)
        for connection in connections:
            self.assertEqual(connection.set_tunnel.call_args.args,('1.1.1.1',443));connection.close.assert_called_once()
        self.assertTrue(all(x.args[0]=='127.0.0.1' for x in factory.call_args_list))
