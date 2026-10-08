import base64,http.server,json,subprocess,sys,threading,time
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import atlas,core
def rpc(method,args={}):
    result=json.loads(subprocess.check_output(['ubus','call','atlas',method,json.dumps(args)],text=True))
    assert result.get('ok'),result
    return result
def wait_job():
    for _ in range(100):
        time.sleep(1);value=rpc('status')
        if value.get('job',{}).get('status') in ('done','error'):
            assert value['job']['status']=='done',value['job'];return
    raise AssertionError('job timeout')
assert rpc('status')['version']=='0.22.0'
rpc('action',{'operation':'stop'});wait_job()
original=atlas.STATE.read_bytes()
payload={'version':3,'rules':[{'type':'logical','mode':'and','rules':[{'domain':['exact.example.org']},{'port':[443]}]},{'domain_regex':['^video\\.'],'invert':True}]}
seen=[];codes=[503,503,200]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append(self.path);self.send_response(codes.pop(0) if codes else 200);self.end_headers();self.wfile.write(json.dumps(payload).encode())
    def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
try:
    atlas.atomic(atlas.STATE,core.defaults())
    imported_without_profiles=rpc('import_rules',{'content':base64.b64encode(json.dumps(payload).encode()).decode(),'target':'direct'})
    assert imported_without_profiles['rules']==2
    state=core.defaults();state['settings']['sections']=[dict(name='direct',policy='proxy',domains=['example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='',outbound_config=[dict(type='direct',tag='entry')])]
    state['settings']['remote_lists']=[dict(name='private-json',id='c'*16,url='http://127.0.0.1:%d/rules.json?token=test#fragment'%server.server_port,policy='direct',format='auto',enabled=True,allow_private=True)]
    state['settings']=core.validate_settings(state['settings'])
    atlas.atomic(atlas.STATE,state)
    try:atlas.refresh(state)
    except core.AtlasError:
        print(json.dumps({'source_errors':[item.get('error') for item in state['settings']['remote_lists']]},ensure_ascii=True),flush=True)
        raise
    assert seen==['/rules.json?token=test']*3,seen
    item=state['settings']['remote_lists'][0]
    assert item['source_rules']==payload and item['source_cached'],item
    atlas.atomic(atlas.STATE,state)
    preview=rpc('config_preview',{'validate':True})
    assert preview['validated']
    private=atlas.runtime_config(atlas.state(),persist=False)
    assert private['route']['rule_set'][0]['rules']==payload['rules']
    imported=rpc('import_rules',{'content':base64.b64encode(json.dumps(payload).encode()).decode(),'target':'block'})
    assert imported['rules']==2
    backup=rpc('export_backup')['backup']
    for item in atlas.state()['settings']['remote_lists']:
        if item.get('source_rules'):(atlas.DATA/'rules'/(item['id']+'.json')).unlink()
    rpc('restore_backup',{'content':json.dumps(backup)})
    restored=atlas.state()
    assert all(item.get('source_rules')==payload for item in restored['settings']['remote_lists'])
    assert all((atlas.DATA/'rules'/(item['id']+'.json')).exists() for item in restored['settings']['remote_lists'])
    rpc('config_preview',{'validate':True})
    rpc('action',{'operation':'start'});wait_job()
    assert rpc('status')['running']
    rpc('action',{'operation':'stop'});wait_job()
    print(json.dumps({'version':'0.22.0','actual_openwrt':Path('/etc/openwrt_release').read_text(),'http_attempts':len(seen),'logical_json_preserved':True,'preview_engine_check':True,'local_json_import':True,'json_import_before_proxy_profiles':True,'backup_restore_after_file_removal':True,'native_service_start_stop':True}))
finally:
    server.shutdown();worker.join();server.server_close()
    atlas.STATE.write_bytes(original)
