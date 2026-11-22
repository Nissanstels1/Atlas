"""Experimental opt-in policy for temporary, verified proxy routes.

The policy considers explicit direct dial failures and observed stalled HTTPS
connections; any temporary exact-domain route requires a verified tunnel.
"""
from collections import OrderedDict, deque
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import ssl
import stat
import struct
import tempfile
import subprocess
import threading
import time


ANSI = re.compile(r'\x1b\[[0-9;]*m')
DIRECT_FAILURE = re.compile(
    r'\bconnection: open connection to ([a-zA-Z0-9.-]{1,253}):443 '
    r'using outbound/direct\[direct\]: (.+)$'
)
CONTEXT_ID=re.compile(r'\[(\d{1,20})\s+[^\]]+\]')
SNI_LINE=re.compile(r'\brouter: sniffed protocol: tls, domain: ([a-zA-Z0-9.-]{1,253})(?:\s|$)')
DIRECT_IP_FAILURE=re.compile(r'\bconnection: open connection to (\[[0-9a-fA-F:]+\]|[0-9.]+):443 using outbound/direct\[direct\]:')
DOM = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def failed_hostname(line):
    if not isinstance(line, str) or len(line) > 8192:
        return None
    clean = ANSI.sub('', line)
    match = DIRECT_FAILURE.search(clean)
    if not match:
        return None
    host = match.group(1).lower().rstrip('.')
    if not DOM.fullmatch(host) or host.endswith(('.local', '.localhost', '.internal', '.lan', '.test', '.invalid', '.onion')):
        return None
    # Hosts consisting solely of numeric labels can be IP addresses or unusual
    # numeric address syntaxes; never infer a destination from them.
    if all(part.isdigit() for part in host.split('.')):
        return None
    return host


class FailureObserver:
    """Correlate TLS sniff and dial failure by the engine's connection ID."""
    def __init__(self, settings, *, now=time.monotonic, maximum=512, ttl=30):
        self.settings,self.now,self.maximum,self.ttl=settings,now,maximum,ttl
        self.names=OrderedDict()
        self.lock=threading.Lock()

    def event(self,line):
        with self.lock:return self._event(line)

    def prune(self):
        with self.lock:
            now=self.now()
            while self.names and now-next(iter(self.names.values()))[1]>self.ttl:self.names.popitem(last=False)

    def _event(self,line):
        if not isinstance(line,str) or len(line)>8192:return None
        clean=ANSI.sub('',line);direct=failed_hostname(clean)
        if direct:return direct,None
        identity=CONTEXT_ID.search(clean)
        if not identity:return None
        key=identity.group(1);now=self.now()
        while self.names and now-next(iter(self.names.values()))[1]>self.ttl:self.names.popitem(last=False)
        sniff=SNI_LINE.search(clean)
        if sniff:
            host=sniff.group(1).lower().rstrip('.')
            # Reuse the same strict domain validation as direct failures.
            candidate=failed_hostname('connection: open connection to '+host+':443 using outbound/direct[direct]: x')
            if candidate:
                self.names[key]=(candidate,now);self.names.move_to_end(key)
                if len(self.names)>self.maximum:self.names.popitem(last=False)
            return None
        failure=DIRECT_IP_FAILURE.search(clean)
        if not failure:return None
        previous=self.names.pop(key,None)
        if not previous:return None
        try:ip=ipaddress.ip_address(failure.group(1).strip('[]'))
        except ValueError:return None
        if ip.version!=4:return None
        # Only normal public destinations or Atlas IPv4 FakeIP qualify.
        fake=ip.version==4 and ip in ipaddress.ip_network('198.18.0.0/15')
        if (not ip.is_global or ip.is_multicast) and not (fake and self.settings().get('fakeip')):return None
        return previous[0],str(ip)


class StalledConnectionObserver:
    """Track bounded direct TLS candidates that have sent bytes but received none."""
    def __init__(self, *, now=time.monotonic, wait=4, maximum=512):
        self.now,self.wait,self.maximum=now,wait,maximum
        self.pending=OrderedDict()

    def observe(self, snapshot):
        if not isinstance(snapshot,dict) or not isinstance(snapshot.get('connections'),list):
            return []
        now=self.now();seen=set();events=[]
        for connection in snapshot['connections'][:2048]:
            if not isinstance(connection,dict):continue
            identity=connection.get('id');meta=connection.get('metadata');chains=connection.get('chains')
            if not isinstance(identity,str) or not 1<=len(identity)<=128 or not isinstance(meta,dict) or not isinstance(chains,list):continue
            host=meta.get('host');port=meta.get('destinationPort');network=meta.get('network')
            sent=connection.get('upload');received=connection.get('download')
            if (not isinstance(host,str) or not isinstance(network,str) or network.lower()!='tcp' or str(port)!='443'
                or len(chains)!=1 or not isinstance(chains[0],str) or chains[0].lower()!='direct'
                or type(sent) is not int or not 0<sent<=65536 or type(received) is not int or received!=0):continue
            host=host.lower().rstrip('.')
            if not failed_hostname('connection: open connection to '+host+':443 using outbound/direct[direct]: x'):continue
            address=meta.get('destinationIP')
            try:
                parsed=ipaddress.ip_address(address)
                fake=parsed.version==4 and parsed in ipaddress.ip_network('198.18.0.0/15')
                if parsed.version!=4 or parsed.is_multicast or (not parsed.is_global and not fake):continue
                address=str(parsed)
            except (ValueError,TypeError):address=None
            seen.add(identity);old=self.pending.get(identity)
            if old is None or old[0]!=host or old[1]!=address:
                self.pending[identity]=(host,address,now,False)
            elif not old[3] and now-old[2]>=self.wait:
                self.pending[identity]=(host,address,old[2],True);events.append((host,address))
            self.pending.move_to_end(identity)
            while len(self.pending)>self.maximum:self.pending.popitem(last=False)
        for identity in list(self.pending):
            if identity not in seen:self.pending.pop(identity,None)
        return events


def matches(host, suffixes):
    return any(host == s or host.endswith('.' + s) for s in suffixes)


RULE_SET_DIRECTORY=Path('/etc/atlas/rules')
_block_list_cache=OrderedDict()
_block_match_cache=OrderedDict()
_block_cache_lock=threading.RLock()


def _block_list_identity(item):
    """Only global, cached binary DNS lists can be checked this way."""
    if (item.get('policy')!='dnsblock' or item.get('section') or item.get('format')!='srs'
            or not item.get('srs_cached') or not re.fullmatch(r'[a-f0-9]{16}',str(item.get('id','')))):
        return None
    path=RULE_SET_DIRECTORY/(item['id']+'.srs')
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=131072:return None
        return (str(path),info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    except OSError:return None


def _domain_only_block_list(item):
    identity=_block_list_identity(item)
    if not identity:return None
    with _block_cache_lock:
        if identity in _block_list_cache:
            _block_list_cache.move_to_end(identity)
            return identity if _block_list_cache[identity] else None
        valid=False
        try:
            from engine_features import binary_path
            with tempfile.TemporaryDirectory(prefix='atlas-block-check-') as directory:
                out=Path(directory)/'rules.json'
                command=['/bin/sh','-c','ulimit -f 8192; exec "$@"','atlas-limit',binary_path(),
                         'rule-set','decompile','--output',str(out),identity[0]]
                result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
                if result.returncode==0 and out.is_file() and out.stat().st_size<=4194304 and _block_list_identity(item)==identity:
                    data=json.loads(out.read_bytes())
                    rules=data.get('rules') if isinstance(data,dict) else None
                    allowed={'domain','domain_suffix','domain_keyword','domain_regex'}
                    valid=isinstance(rules,list) and bool(rules) and all(
                        isinstance(rule,dict) and bool(rule) and set(rule)<=allowed for rule in rules)
                    if valid:
                        examples=[v for rule in rules for key in ('domain','domain_suffix')
                                  for v in ([rule[key]] if isinstance(rule.get(key),str) else rule.get(key,[]))
                                  if isinstance(v,str) and DOM.fullmatch(v)]
                        valid=False
                        if examples:
                            with tempfile.TemporaryFile() as output:
                                matched=subprocess.run([binary_path(),'rule-set','match','--format','binary',identity[0],examples[0]],
                                                       stdin=subprocess.DEVNULL,stdout=output,stderr=output,timeout=5)
                                output.seek(0)
                                valid=matched.returncode==0 and bool(output.read(1)) and _block_list_identity(item)==identity
        except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):pass
        _block_list_cache[identity]=valid
        while len(_block_list_cache)>8:_block_list_cache.popitem(last=False)
        return identity if valid else None


def _blocked_by_binary_list(host, item):
    """Fail closed if the engine cannot prove that this name is outside the list."""
    identity=_domain_only_block_list(item)
    if not identity:return True
    now=time.monotonic();key=(identity,host)
    with _block_cache_lock:
        cached=_block_match_cache.get(key)
        if cached and 0<=now-cached[0]<120:
            _block_match_cache.move_to_end(key)
            return cached[1]
        blocked=True
        try:
            from engine_features import binary_path
            with tempfile.TemporaryFile() as output:
                result=subprocess.run([binary_path(),'rule-set','match','--format','binary',identity[0],host],
                                      stdin=subprocess.DEVNULL,stdout=output,stderr=output,timeout=5)
                output.seek(0)
                blocked=result.returncode!=0 or bool(output.read(1)) or _block_list_identity(item)!=identity
        except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):pass
        _block_match_cache[key]=(now,blocked)
        while len(_block_match_cache)>256:_block_match_cache.popitem(last=False)
        return blocked


def suspension_reason(settings):
    if not isinstance(settings,dict) or settings.get('mode')!='rules':return 'mode'
    if settings.get('routing_excluded_ips'):return 'devices'
    sections={x.get('id'):x for x in settings.get('sections',[]) if isinstance(x,dict)}
    for item in settings.get('remote_lists',[]):
        assigned=sections.get(item.get('section'),{})
        if not item.get('enabled'):continue
        if item.get('policy')=='dnsblock' and not item.get('section') and _domain_only_block_list(item):continue
        if item.get('policy') in ('direct','exclude','block','dnsblock') or assigned.get('policy') in ('direct','exclude','block'):
            return 'lists'  # Unknown or scoped lists remain fail-closed.
    for section in settings.get('sections',[]):
        if not section.get('enabled'):continue
        if section.get('exclude_source_ips') or section.get('exclude_cidrs'):return 'sections'
        if section.get('policy') not in ('direct','exclude','block'):continue
        if any(section.get(key) for key in ('source_ips','routed_source_ips','source_interfaces','ports','networks')):
            return 'sections'
        for rule in section.get('connection_rules',[]):
            if rule.get('cidrs'):return 'sections'
        if section.get('cidrs') or not section.get('domains'):
            return 'sections'
    return ''


def may_probe(host, settings):
    """Fail closed where the log lacks the information needed by exclusions."""
    if suspension_reason(settings):return False
    protected=(list(settings.get('bypass_domains',[]))+list(settings.get('blocked_domains',[]))+
               [x for x in (settings.get('custom_dns_sni'),settings.get('bootstrap_dns_sni'),
                            'cloudflare-dns.com','dns.adguard-dns.com') if isinstance(x,str) and x])
    if matches(host, protected):return False
    for item in settings.get('remote_lists',[]):
        if item.get('enabled') and item.get('policy')=='dnsblock' and _blocked_by_binary_list(host,item):return False
    for section in settings.get('sections',[]):
        if not section.get('enabled'):continue
        if matches(host, section.get('exclude_domains',[])):return False
        if section.get('policy') not in ('direct','exclude','block'):continue
        if matches(host,section.get('domains',[])):return False
        for rule in section.get('connection_rules',[]):
            if matches(host,rule.get('domains',[])):return False
    return True


def public_not_excluded(addresses, networks):
    try:
        parsed=[ipaddress.ip_network(n,strict=False) for n in networks]
        values=[ipaddress.ip_address(a) for a in addresses]
        return bool(values) and all(a.is_global and not a.is_multicast and
            not any(a.version==n.version and a in n for n in parsed) for a in values)
    except ValueError:
        return False


def dns_query(host, identity):
    labels = host.encode('ascii').split(b'.')
    return struct.pack('!HHHHHH',identity,0x0100,1,0,0,0) + b''.join(bytes([len(x)])+x for x in labels) + b'\x00\x00\x01\x00\x01'


def skip_dns_name(packet, pos):
    """Skip one bounded DNS name; do not follow compression pointers."""
    start=pos
    while pos < len(packet) and pos-start <= 255:
        n=packet[pos];pos+=1
        if n==0:return pos
        if n & 0xc0 == 0xc0:
            if pos >= len(packet) or ((n & 0x3f)<<8 | packet[pos]) >= len(packet):raise ValueError('bad DNS pointer')
            return pos+1
        if n & 0xc0 or n>63 or pos+n>len(packet):raise ValueError('bad DNS label')
        pos+=n
    raise ValueError('bad DNS name')


def dns_public_addresses(packet, identity, query):
    if len(packet)<12 or len(packet)>65535:raise ValueError('bad DNS packet')
    ident,flags,qd,an,ns,ar=struct.unpack_from('!HHHHHH',packet)
    if ident!=identity or not flags & 0x8000 or flags & 0x020f or qd!=1 or an>64:
        raise ValueError('DNS response not successful')
    expected=query[12:]
    if packet[12:12+len(expected)].lower()!=expected.lower():raise ValueError('DNS question changed')
    pos=12+len(expected);addresses=[]
    for _ in range(an):
        pos=skip_dns_name(packet,pos)
        if pos+10>len(packet):raise ValueError('truncated DNS answer')
        kind,cls,_,length=struct.unpack_from('!HHIH',packet,pos);pos+=10
        if pos+length>len(packet):raise ValueError('truncated DNS record')
        if cls==1 and kind==1 and length==4:
            address=ipaddress.ip_address(packet[pos:pos+length])
            if not address.is_global or address.is_multicast:raise ValueError('non-public DNS answer')
            addresses.append(str(address))
        pos+=length
    return list(dict.fromkeys(addresses))


def proxy_connect(proxy_port, username, password, address, timeout):
    ip=ipaddress.ip_address(address)
    if not ip.is_global or ip.is_multicast or (ip.version==6 and ip.ipv4_mapped):raise ValueError('non-public target')
    authority=('['+str(ip)+']' if ip.version==6 else str(ip))+':443'
    credentials=(username+':'+password).encode('utf-8')
    request=('CONNECT '+authority+' HTTP/1.1\r\nHost: '+authority+
             '\r\nProxy-Authorization: Basic '+base64.b64encode(credentials).decode('ascii')+
             '\r\nConnection: keep-alive\r\n\r\n').encode('ascii')
    raw=socket.create_connection(('127.0.0.1',proxy_port),timeout=timeout)
    try:
        raw.settimeout(timeout);raw.sendall(request);header=b''
        while not header.endswith(b'\r\n\r\n') and len(header)<8192:
            chunk=raw.recv(1)
            if not chunk:raise OSError('proxy closed')
            header+=chunk
        if not header.endswith(b'\r\n\r\n') or not re.fullmatch(rb'HTTP/1\.[01] 200(?: .*)?',header.split(b'\r\n',1)[0]):
            raise OSError('proxy refused')
        return raw
    except BaseException:
        raw.close()
        raise


def doh_http2(query, proxy_port, username, password, server, sni, path, timeout):
    """Ask the same resolver through the same proxy; secrets stay off argv."""
    try:
        ip=ipaddress.ip_address(server)
        if not ip.is_global or ip.is_multicast or (ip.version==6 and ip.ipv4_mapped):return b''
        if not DOM.fullmatch(sni) or not path.startswith('/') or any(c in path for c in '\r\n \t'):
            return b''
        if not 1<=proxy_port<=65535 or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',x) for x in (username,password)):
            return b''
        curl=next((p for p in ('/usr/bin/curl','/bin/curl') if os.path.isfile(p) and os.access(p,os.X_OK)),None)
        if not curl:return b''
        address='['+str(ip)+']' if ip.version==6 else str(ip)
        quote=lambda x:json.dumps(str(x),ensure_ascii=True)
        marker=b'ATLAS_DOH_META:'
        options=['silent','show-error','http2','proto = "=https"','max-filesize = 65535',
            'max-time = '+str(max(1,min(12,int(timeout)))), 'noproxy = ""',
            'proxy = '+quote('http://127.0.0.1:'+str(proxy_port)),
            'proxy-user = '+quote(username+':'+password),
            'connect-to = '+quote(sni+':443:'+address+':443'),
            'header = "Content-Type: application/dns-message"',
            'header = "Accept: application/dns-message"',
            'data-binary = "@-"', 'write-out = "ATLAS_DOH_META:%{http_code}:%{content_type}"',
            'url = '+quote('https://'+sni+path)]
        config=('\n'.join(options)+'\n').encode('ascii')
        if len(config)>3000:return b''
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,config);os.close(write_fd);write_fd=None
            result=subprocess.run([curl,'-q','--config','/proc/self/fd/'+str(read_fd)],input=query,
                                  pass_fds=(read_fd,),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                  timeout=max(2,min(14,timeout+2)),env={'PATH':'/usr/bin:/bin'})
        finally:
            os.close(read_fd)
            if write_fd is not None:os.close(write_fd)
        body,sep,metadata=result.stdout.rpartition(marker)
        code,_,mime=metadata.partition(b':')
        if result.returncode or not sep or code!=b'200' or mime.split(b';',1)[0].strip().lower()!=b'application/dns-message' or len(body)>65535:return b''
        return body
    except (OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):
        return b''


def tunnel_dns_a(host, proxy_port, username, password, *, server='1.1.1.1',
                 sni='cloudflare-dns.com', path='/dns-query', timeout=4, context=None):
    """Resolve through the tunnel using authenticated DNS-over-HTTPS only."""
    if not isinstance(host,str) or not DOM.fullmatch(host) or not isinstance(sni,str) or not DOM.fullmatch(sni):return []
    if not isinstance(path,str) or not path.startswith('/') or any(c in path for c in '\r\n '):return []
    try:
        context=context or ssl.create_default_context()
        if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:return []
        identity=secrets.randbelow(65536);query=dns_query(host,identity)
        with proxy_connect(proxy_port,username,password,server,timeout) as raw:
            with context.wrap_socket(raw,server_hostname=sni) as tls:
                header=('POST '+path+' HTTP/1.1\r\nHost: '+sni+'\r\nContent-Type: application/dns-message\r\n'
                        'Accept: application/dns-message\r\nContent-Length: '+str(len(query))+'\r\nConnection: close\r\n\r\n').encode('ascii')
                tls.sendall(header+query)
                response=http.client.HTTPResponse(tls);response.begin()
                if response.status in (426,505):
                    body=doh_http2(query,proxy_port,username,password,server,sni,path,timeout)
                    return dns_public_addresses(body,identity,query) if body else []
                if response.status!=200 or response.getheader('Content-Type','').split(';')[0].strip().lower()!='application/dns-message':return []
                body=response.read(65536)
                return dns_public_addresses(body,identity,query)
    except (OSError,ValueError,TypeError,ssl.SSLError,http.client.HTTPException,struct.error,UnicodeError):
        return []


def tunnel_tls_probe(host, address, proxy_port, username, password, timeout=4, *, context=None):
    """Verify a public IP through a loopback proxy, with TLS hostname validation.

    Address resolution is a separate operation; callers must use authenticated
    DNS and pass a public answer. No page, URL path or browser data is sent.
    """
    if not isinstance(host, str) or not DOM.fullmatch(host) or not 1 <= proxy_port <= 65535:
        return False
    try:
        context = context or ssl.create_default_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            return False
        with proxy_connect(proxy_port, username, password, address, timeout) as raw:
            tls = context.wrap_socket(raw, server_hostname=host)
            tls.close()
            return True
    except (OSError, ValueError, TypeError, ssl.SSLError):
        return False


def direct_tls_probe(host, address, timeout=3, *, context=None):
    """Test a public IP directly without sending a page request."""
    try:
        ip=ipaddress.ip_address(address)
        if ip.version!=4 or not ip.is_global or ip.is_multicast or not DOM.fullmatch(host):return False
        context=context or ssl.create_default_context()
        if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:return False
        with socket.create_connection((str(ip),443),timeout=timeout) as raw:
            with context.wrap_socket(raw,server_hostname=host):return True
    except (OSError,ValueError,TypeError,ssl.SSLError):
        return False


def atlas_verifier(settings, proxy_port, username, password, *, require_direct_failure=False):
    """Prepare a fail-closed probe using the current configured DoH service."""
    def verify(host):
        current=settings()
        if not may_probe(host,current):return False
        kind=current.get('dns_filter')
        if kind=='cloudflare':server,sni,path='1.1.1.1','cloudflare-dns.com','/dns-query'
        elif kind=='adguard':server,sni,path='94.140.14.14','dns.adguard-dns.com','/dns-query'
        elif kind=='custom' and current.get('custom_dns_type')=='https':
            server=current.get('custom_dns_server','');sni=current.get('custom_dns_sni','');path=current.get('custom_dns_path','')
        else:return False
        addresses=tunnel_dns_a(host,proxy_port,username,password,server=server,sni=sni,path=path)
        current=settings()
        if not may_probe(host,current) or not public_not_excluded(addresses,current.get('bypass_cidrs',[])):
            return False
        # Two addresses avoid treating a single unavailable CDN endpoint as a
        # blocked domain. No direct test is needed for explicit dial failures.
        targets=addresses[:2]
        if require_direct_failure and any(direct_tls_probe(host,address) for address in targets):
            return False
        return any(tunnel_tls_probe(host,address,proxy_port,username,password) for address in targets)
    return verify


class AdaptivePolicy:
    def __init__(self, *, direct_exclusions=(), now=time.monotonic, threshold=2,
                 window=30, cooldown=60, ttl=3600, maximum=100, max_probes=12):
        self.direct_exclusions = tuple(direct_exclusions)
        self.now, self.threshold, self.window = now, threshold, window
        self.cooldown, self.ttl, self.maximum, self.max_probes = cooldown, ttl, maximum, max_probes
        self.failures, self.last_probe, self.active = {}, {}, {}
        self.probes = deque()

    def observe(self, line, verify, *, minimum_failures=None):
        host = failed_hostname(line)
        if not host or matches(host, self.direct_exclusions):
            return None
        now = self.now()
        self.expire()
        if host in self.active:
            return None
        seen = [at for at in self.failures.get(host, []) if now-at <= self.window]
        seen.append(now)
        self.failures[host] = seen[-self.threshold:]
        # Bound attacker-controlled per-host bookkeeping as well as active rules.
        if len(self.failures) > self.maximum * 4:
            oldest = min(self.failures, key=lambda x: self.failures[x][-1])
            del self.failures[oldest]
        while self.probes and now-self.probes[0] >= 60:
            self.probes.popleft()
        threshold=self.threshold if minimum_failures is None else minimum_failures
        if (len(seen) < threshold or now-self.last_probe.get(host, -float('inf')) < self.cooldown
                or len(self.probes) >= self.max_probes or len(self.active) >= self.maximum):
            return None
        self.probes.append(now)
        self.last_probe[host] = now
        if len(self.last_probe) > self.maximum * 4:
            for key in sorted(self.last_probe, key=self.last_probe.get)[:len(self.last_probe)-self.maximum*4]:
                del self.last_probe[key]
        try:
            success = verify(host) is True
        except Exception:
            success = False
        if not success:
            return None
        # No broadening to parent domains, other sites, IPs or subnets.
        self.active[host] = now + self.ttl
        self.failures.pop(host, None)
        return host

    def expire(self):
        now = self.now()
        for host in [h for h, until in self.active.items() if until <= now]:
            del self.active[host]
        for host in [h for h, times in self.failures.items() if not times or now-times[-1]>self.window]:
            del self.failures[host]
        for host in [h for h, last in self.last_probe.items() if now-last>=self.cooldown]:
            del self.last_probe[host]

    def rules(self):
        self.expire()
        return {'version': 3, 'rules': [{'domain': sorted(self.active)}] if self.active else []}

    def write_rules(self, path):
        path = Path(path)
        body = json.dumps(self.rules(), separators=(',', ':')).encode()
        fd, temporary = tempfile.mkstemp(prefix='.atlas-adaptive-', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class AdaptiveWorker:
    """Bounded event queue; the engine never waits for a connectivity probe."""
    def __init__(self, path, settings, verifier, *, policy=None, suppressed=lambda: set(),
                 connection_snapshot=None, stall_verifier=None):
        self.path=Path(path)
        self.settings=settings
        self.verifier=verifier
        self.suppressed=suppressed
        self.policy=policy or AdaptivePolicy()
        self.observer=FailureObserver(settings)
        self.stalls=StalledConnectionObserver()
        self.connection_snapshot=connection_snapshot
        self.stall_verifier=stall_verifier
        self.queue=queue.Queue(maxsize=128)
        self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)
        self.monitor_thread=None

    def offer(self, line):
        try:event=self.observer.event(line)
        except (OSError,ValueError,TypeError):return False
        if not event:return False
        try:self.queue.put_nowait((*event,False));return True
        except queue.Full:return False

    def start(self):
        self.policy.write_rules(self.path)
        self.path.with_name('adaptive-status.json').unlink(missing_ok=True)
        self.thread.start()
        if self.connection_snapshot and self.stall_verifier:
            self.monitor_thread=threading.Thread(target=self.monitor,daemon=True)
            self.monitor_thread.start()

    def close(self):
        self.stop.set()
        if self.monitor_thread and self.monitor_thread.ident is not None:self.monitor_thread.join(timeout=3)
        if self.thread.ident is not None:self.thread.join(timeout=12)

    def monitor(self):
        while not self.stop.wait(2):
            try:
                if suspension_reason(self.settings()):continue
                for host,address in self.stalls.observe(self.connection_snapshot()):
                    try:self.queue.put_nowait((host,address,True))
                    except queue.Full:break
            except (OSError,ValueError,TypeError,RuntimeError,http.client.HTTPException):
                pass

    def run(self):
        try:self._run()
        finally:
            # If the worker dies, never leave unmaintained temporary routes.
            self.policy.active.clear()
            try:self.policy.write_rules(self.path)
            except OSError:pass
            self.path.with_name('adaptive-status.json').unlink(missing_ok=True)

    def _run(self):
        last_rules=self.policy.rules()
        next_refresh=0
        next_heartbeat=0
        while not self.stop.is_set():
            try:
                host,address,stalled=self.queue.get(timeout=.25)
                current=self.settings()
                # An IP-specific direct exclusion can only be honored if the
                # actual direct destination is known and is not a FakeIP.
                excluded=current.get('bypass_cidrs',[])
                fake=address and ipaddress.ip_address(address) in ipaddress.ip_network('198.18.0.0/15')
                if fake and not current.get('fakeip'):continue
                if excluded and (not address or fake or not public_not_excluded([address],excluded)):
                    continue
                if host and host not in self.suppressed() and may_probe(host,self.settings()):
                    def verify(name):
                        probe=self.stall_verifier if stalled else self.verifier
                        return (not self.stop.is_set() and name not in self.suppressed() and may_probe(name,self.settings()) and probe(name)
                                and not self.stop.is_set() and name not in self.suppressed() and may_probe(name,self.settings()))
                    synthetic='connection: open connection to '+host+':443 using outbound/direct[direct]: observed'
                    self.policy.observe(synthetic,verify,minimum_failures=1 if stalled else None)
            except queue.Empty:pass
            except (OSError,ValueError,TypeError):pass
            if time.monotonic()>=next_refresh:
                self.observer.prune()
                try:
                    exclusions=self.suppressed();current_settings=self.settings()
                    for name in list(self.policy.active):
                        if name in exclusions or not may_probe(name,current_settings):
                            del self.policy.active[name]
                except (OSError,ValueError,TypeError):
                    self.policy.active.clear()
                next_refresh=time.monotonic()+1
            if time.monotonic()>=next_heartbeat:
                try:
                    info={'at':int(time.time()),'suspended':suspension_reason(self.settings())}
                    target=self.path.with_name('adaptive-status.json')
                    fd,tmp=tempfile.mkstemp(prefix='.atlas-adaptive-status-',dir=str(target.parent))
                    try:
                        with os.fdopen(fd,'w') as stream:json.dump(info,stream,separators=(',',':'))
                        os.chmod(tmp,0o600);os.replace(tmp,target)
                    finally:
                        if os.path.exists(tmp):os.unlink(tmp)
                except (OSError,ValueError,TypeError):pass
                next_heartbeat=time.monotonic()+5
            # Preserve the last valid file on any writer error and let a later
            # iteration retry, instead of interrupting the engine's traffic.
            current=self.policy.rules()
            if current!=last_rules:
                try:self.policy.write_rules(self.path);last_rules=current
                except OSError:pass
