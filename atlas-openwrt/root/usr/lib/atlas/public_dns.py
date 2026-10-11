"""Validate public destinations when local DNS returns Atlas FakeIP addresses."""
import base64,http.client,ipaddress,json
from urllib.parse import urlencode,urlsplit,unquote

def public_addresses(host,proxy_url=None):
    addresses=[]
    for family,kind in ((4,'A'),(6,'AAAA')):
        if proxy_url:
            proxy=urlsplit(proxy_url)
            if proxy.scheme!='http' or proxy.hostname!='127.0.0.1':raise ValueError('Invalid diagnostic proxy')
            connection=http.client.HTTPSConnection(proxy.hostname,proxy.port,timeout=3)
            headers={}
            if proxy.username:
                credentials=unquote(proxy.username)+':'+unquote(proxy.password or '')
                headers['Proxy-Authorization']='Basic '+base64.b64encode(credentials.encode()).decode()
            connection.set_tunnel('1.1.1.1',443,headers=headers)
        else:
            connection=http.client.HTTPSConnection('1.1.1.1',443,timeout=3)
        try:
            connection.request('GET','/dns-query?'+urlencode({'name':host,'type':kind}),headers={'Host':'cloudflare-dns.com','Accept':'application/dns-json','Connection':'close'})
            response=connection.getresponse();body=response.read(65537)
            if response.status!=200 or len(body)>65536:raise ValueError('Invalid public DNS response')
            value=json.loads(body)
            if not isinstance(value,dict) or value.get('Status')!=0:raise ValueError('Public DNS lookup failed')
            answers=value.get('Answer',[])
            if not isinstance(answers,list) or len(answers)>64:raise ValueError('Invalid DNS answers')
            for answer in answers:
                if not isinstance(answer,dict):raise ValueError('Invalid DNS answer')
                if answer.get('type')!=(1 if family==4 else 28):continue
                address=ipaddress.ip_address(answer.get('data',''))
                if address.version!=family or not address.is_global:raise ValueError('DNS destination is not public')
                addresses.append(address)
        finally:
            connection.close()
    if not addresses:raise ValueError('No public DNS addresses')
    return addresses
