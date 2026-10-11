"""Section-specific website proofs with bounded retries and no retained content."""
import hashlib,json
from download_policy import DownloadPolicy,MAX_PROOFS

class SitePolicy(DownloadPolicy):
    def __init__(self,saved,generation,check,now=None):
        self.failures={}
        self.ttl=60
        def measured(key,payload):
            identity=hashlib.sha256((generation+'\0'+key+'\0'+self.signature(payload)).encode()).hexdigest()
            result=check(key,payload,self.deadline)
            if self.accepted(result,payload):self.failures.pop(identity,None)
            else:self.failures[identity]=self.current_time()
            return result
        super().__init__(saved,generation,measured,now)
        raw=saved.get('failures',{}) if isinstance(saved,dict) and saved.get('generation')==generation else {}
        if isinstance(raw,dict) and len(raw)<=MAX_PROOFS:
            for key,stamp in raw.items():
                if isinstance(key,str) and len(key)==64 and all(x in '0123456789abcdef' for x in key) and type(stamp) is int and 0<=self.now-stamp<120:
                    self.failures[key]=stamp;self.round[key]=False

    def payload(self,settings):
        return {'sites':settings['site_checks'],'download':settings['urltest_download_url'] if settings['urltest_download_check']=='custom' else ''}

    def signature(self,payload):return json.dumps(payload,sort_keys=True,separators=(',',':'))

    def accepted(self,result,payload):
        return isinstance(result,dict) and result.get('ok') is True and type(result.get('tested')) is int and result['tested']==len(payload['sites'])

    def fresh(self,identity):
        stamp=self.proofs.get(identity)
        return type(stamp) is int and 0<=self.current_time()-stamp<self.ttl

    def choose(self,members,settings,proxies,previous,rank):
        self.ttl=min(300,settings.get('auto_interval_seconds',60))
        return super().choose(members,settings,proxies,previous,rank)

    def export(self,groups):
        value=super().export(groups)
        value['failures']=dict(sorted(((k,v) for k,v in self.failures.items() if 0<=self.current_time()-v<120),key=lambda x:x[1],reverse=True)[:MAX_PROOFS])
        return value
