"""Experimental, opt-in policy; not wired into the Atlas service.

This module intentionally accepts only direct HTTPS dial failures with an
identified hostname and installs a temporary exact-domain rule only after an
independent, caller-supplied tunnel probe succeeds.
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
import struct
import tempfile
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


def matches(host, suffixes):
    return any(host == s or host.endswith('.' + s) for s in suffixes)


def suspension_reason(settings):
    if not isinstance(settings,dict) or settings.get('mode')!='rules':return 'mode'
    if settings.get('routing_excluded_ips'):return 'devices'
    sections={x.get('id'):x for x in settings.get('sections',[]) if isinstance(x,dict)}
    for item in settings.get('remote_lists',[]):
        assigned=sections.get(item.get('section'),{})
        if item.get('enabled') and (item.get('policy') in ('direct','exclude','block','dnsblock') or assigned.get('policy') in ('direct','exclude','block')):
            return 'lists'  # A compiled list cannot be classified from its URL.
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


def atlas_verifier(settings, proxy_port, username, password):
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
        # Bound time and load: use only one public result per candidate.
        return tunnel_tls_probe(host,addresses[0],proxy_port,username,password)
    return verify


class AdaptivePolicy:
    def __init__(self, *, direct_exclusions=(), now=time.monotonic, threshold=2,
                 window=30, cooldown=60, ttl=3600, maximum=100, max_probes=12):
        self.direct_exclusions = tuple(direct_exclusions)
        self.now, self.threshold, self.window = now, threshold, window
        self.cooldown, self.ttl, self.maximum, self.max_probes = cooldown, ttl, maximum, max_probes
        self.failures, self.last_probe, self.active = {}, {}, {}
        self.probes = deque()

    def observe(self, line, verify):
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
        if (len(seen) < self.threshold or now-self.last_probe.get(host, -float('inf')) < self.cooldown
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
    def __init__(self, path, settings, verifier, *, policy=None, suppressed=lambda: set()):
        self.path=Path(path)
        self.settings=settings
        self.verifier=verifier
        self.suppressed=suppressed
        self.policy=policy or AdaptivePolicy()
        self.observer=FailureObserver(settings)
        self.queue=queue.Queue(maxsize=128)
        self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)

    def offer(self, line):
        try:event=self.observer.event(line)
        except (OSError,ValueError,TypeError):return False
        if not event:return False
        try:self.queue.put_nowait(event);return True
        except queue.Full:return False

    def start(self):
        self.policy.write_rules(self.path)
        self.path.with_name('adaptive-status.json').unlink(missing_ok=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread.ident is not None:self.thread.join(timeout=12)

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
                host,address=self.queue.get(timeout=.25)
                current=self.settings()
                # An IP-specific direct exclusion can only be honored if the
                # actual direct destination is known and is not a FakeIP.
                excluded=current.get('bypass_cidrs',[])
                fake=address and ipaddress.ip_address(address) in ipaddress.ip_network('198.18.0.0/15')
                if excluded and (not address or fake or not public_not_excluded([address],excluded)):
                    continue
                if host and host not in self.suppressed() and may_probe(host,self.settings()):
                    def verify(name):
                        return (not self.stop.is_set() and name not in self.suppressed() and may_probe(name,self.settings()) and self.verifier(name)
                                and not self.stop.is_set() and name not in self.suppressed() and may_probe(name,self.settings()))
                    synthetic='connection: open connection to '+host+':443 using outbound/direct[direct]: observed'
                    self.policy.observe(synthetic,verify)
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
