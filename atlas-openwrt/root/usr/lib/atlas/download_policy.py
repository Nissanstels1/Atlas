"""Bounded transfer proofs for guarded selection; no response bodies retained."""
import hashlib
import time

MAX_PROOFS=4096
PROOF_TTL=300

class DownloadPolicy:
    def __init__(self, saved, generation, check, now=None):
        self.now=int(time.time() if now is None else now)
        self.generation=generation
        self.check=check
        self.calls=0
        self.started=time.monotonic()
        self.deadline=self.started+22
        self.round={}
        self.proofs={}
        saved=saved if isinstance(saved,dict) else {}
        self.cursor=saved.get('cursor',0) if type(saved.get('cursor')) is int else 0
        raw=saved.get('proofs',{}) if saved.get('generation')==generation else {}
        if isinstance(raw,dict) and len(raw)<=MAX_PROOFS:
            for key,stamp in raw.items():
                if isinstance(key,str) and len(key)==64 and all(c in '0123456789abcdef' for c in key) and type(stamp) is int and 0<=self.now-stamp<PROOF_TTL:
                    self.proofs[key]=stamp

    def current_time(self):
        # Use elapsed monotonic time: NTP changes must not extend a proof mid-cycle.
        return self.now+int(max(0,time.monotonic()-self.started))

    def fresh(self, identity):
        stamp=self.proofs.get(identity)
        return type(stamp) is int and 0<=self.current_time()-stamp<PROOF_TTL

    def payload(self, settings):
        return settings['urltest_download_url']

    def signature(self, payload):
        return payload

    def accepted(self, result, payload):
        return isinstance(result,dict) and result.get('ok') is True and type(result.get('received')) is int and result['received']==65536

    def choose(self, members, settings, proxies, previous, rank):
        remaining=members
        while remaining:
            key=rank(remaining,settings,proxies)
            if not key or not any(node['key']==key for node in remaining):return 'policy-block','no-candidate'
            url=self.payload(settings)
            identity=hashlib.sha256((self.generation+'\0'+key+'\0'+self.signature(url)).encode()).hexdigest()
            if identity in self.round:
                passed=self.round[identity]
            elif previous==key and self.fresh(identity):
                if rank([node for node in remaining if node['key']==key],settings,proxies)==key:
                    return key,'verified-reused'
                remaining=[node for node in remaining if node['key']!=key]
                continue
            elif self.calls>=4 or time.monotonic()>=self.deadline:
                # Checking a new, faster candidate must not discard an existing
                # selection whose same-generation proof and RTT still qualify.
                selected=[node for node in remaining if node['key']==previous]
                if selected and rank(selected,settings,proxies)==previous:
                    previous_identity=hashlib.sha256((self.generation+'\0'+previous+'\0'+self.signature(url)).encode()).hexdigest()
                    if self.round.get(previous_identity) is not False and self.fresh(previous_identity):
                        return previous,'verified-budget-reused'
                return 'policy-block','check-budget'
            else:
                self.calls+=1
                try:result=self.check(key,url)
                except Exception:result={}
                passed=time.monotonic()<self.deadline and self.accepted(result,url)
                self.round[identity]=passed
                if passed:self.proofs[identity]=self.current_time()
                else:self.proofs.pop(identity,None)
            if passed and rank([node for node in remaining if node['key']==key],settings,proxies)==key:
                return key,'verified'
            remaining=[node for node in remaining if node['key']!=key]
        return 'policy-block','download-failed'

    def export(self, groups):
        proofs=dict(sorted(((key,stamp) for key,stamp in self.proofs.items() if self.fresh(key)),key=lambda item:item[1],reverse=True)[:MAX_PROOFS])
        return {'generation':self.generation,'proofs':proofs,'cursor':(self.cursor+1)%max(1,groups)}
