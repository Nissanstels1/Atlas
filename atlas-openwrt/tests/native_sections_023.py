import json,subprocess,sys,time
sys.path.insert(0,'/usr/lib/atlas')
import atlas,core

def rpc(method,args={}):
    result=json.loads(subprocess.check_output(['ubus','call','atlas',method,json.dumps(args)],text=True));assert result.get('ok'),result;return result
def wait_job():
    for _ in range(180):
        value=rpc('status')
        if value.get('job',{}).get('status') in ('done','error'):
            assert value['job']['status']=='done',value['job'];return
        time.sleep(1)
    raise AssertionError('Job did not finish')
assert rpc('status')['version']=='0.23.0'
rpc('action',dict(operation='stop'));wait_job()
original=atlas.STATE.read_bytes()
recovery_path=atlas.RUN/'recovery.json'
prior_recovery=recovery_path.read_bytes() if recovery_path.exists() else None
atlas.atomic(recovery_path,{'attempts':[]})
try:
    current=core.defaults()
    current['subscriptions']=[dict(id='b'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('http://127.0.0.1:9#fixture')])]
    def section(name,interval,resolve):
        return dict(name=name,policy='proxy',domains=[name.lower()+'.example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='',auto_interval_seconds=interval,auto_tolerance_ms=50 if name=='A' else 120,resolve_real_ip=resolve,urltest_url='https://cp.cloudflare.com/generate_204')
    current['settings']['sections']=[section('A',30,True),section('B',300,False)]
    current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'],interface_reload_delay_ms=150)
    current['settings']=core.validate_settings(current['settings']);atlas.atomic(atlas.STATE,current)
    cfg=atlas.runtime_config(current,persist=False)
    atlas.check(cfg)
    resolve=[x for x in cfg['route']['rules'] if x.get('action')=='resolve']
    assert any(x.get('domain_suffix')==['a.example.org'] for x in resolve)
    assert not any(x.get('domain_suffix')==['b.example.org'] for x in resolve)
    rpc('action',dict(operation='start'));wait_job()
    proxies=atlas.clash_request()['proxies']
    for sec in current['settings']['sections']:
        prefix='section_'+sec['id']+'_';assert prefix+'control' in proxies and prefix+'auto' in proxies
    # Cron is stopped by the test harness. This proves recovery uses its own event worker.
    event=atlas.record_interface_event('ifup','wan');assert event['reason']=='recorded'
    event_id=atlas.read_json(atlas.RUN/'interface-event.json',{})['id']
    for _ in range(180):
        handled=atlas.read_json(atlas.RUN/'interface-handled.json',{})
        if handled.get('id')==event_id:break
        time.sleep(1)
    else:raise AssertionError('Event recovery did not finish: '+str(atlas.read_json(atlas.RUN/'watchdog.json',{})))
    assert atlas.service_running()
    assert atlas.read_json(atlas.RUN/'watchdog.json',{})['reason']=='interface-restarted'
    for _ in range(90):
        try:
            live=atlas.clash_request()['proxies']
            if all('section_'+sec['id']+'_control' in live for sec in current['settings']['sections']):break
        except (core.AtlasError,OSError):pass
        time.sleep(1)
    else:raise AssertionError('Engine API not ready after event recovery')
    rpc('action',dict(operation='stop'));wait_job()
    print(json.dumps(dict(version='0.23.0',native_engine_check=True,independent_groups_live=True,per_section_real_ip=True,wan_event_recovery_without_cron=True,engine_api_after_recovery=True,configured_delay_ms=150,service_start_stop=True)))
finally:
    subprocess.run(['/etc/init.d/atlas','stop'],timeout=90)
    subprocess.run(['/etc/init.d/atlas','disable'],timeout=15)
    atlas.STATE.write_bytes(original)
    if prior_recovery is None:recovery_path.unlink(missing_ok=True)
    else:recovery_path.write_bytes(prior_recovery)
