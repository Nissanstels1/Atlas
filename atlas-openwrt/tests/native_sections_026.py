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
assert rpc('status')['version']==atlas.VERSION
for _ in range(180):
    if rpc('status').get('job',{}).get('status') not in ('queued','running'):break
    time.sleep(1)
else:raise AssertionError('Background operation did not finish before test')
rpc('action',dict(operation='stop'));wait_job()
original=atlas.STATE.read_bytes()
recovery_path=atlas.RUN/'recovery.json'
prior_recovery=recovery_path.read_bytes() if recovery_path.exists() else None
atlas.atomic(recovery_path,{'attempts':[]})
try:
    current=core.defaults()
    current['subscriptions']=[dict(id='b'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('socks5://fixture:fixture@127.0.0.1:9#fixture')])]
    def section(name,interval,resolve):
        return dict(name=name,policy='proxy',domains=[name.lower()+'.example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='',auto_interval_seconds=interval,auto_tolerance_ms=50 if name=='A' else 120,resolve_real_ip=resolve,urltest_url='https://cp.cloudflare.com/generate_204')
    current['settings']['sections']=[dict(section('A',30,True),udp_over_tcp=True,udp_over_tcp_version=1),dict(section('B',300,False),udp_over_tcp=False)]
    current['settings']['sections'] += [dict(section('C',30,False),id='c'*16,auto_interval_seconds=None,auto_tolerance_ms=None,urltest_url='',resolver='https://1.1.1.1/dns-query',ports=['443'],networks=['tcp'],outbound_config=[dict(type='http',tag='entry',server='127.0.0.1',server_port=9,detour='section_'+'d'*16+'_relay')]),dict(section('D',30,False),id='d'*16,auto_interval_seconds=None,auto_tolerance_ms=None,urltest_url='',outbound_config=[dict(type='socks',tag='relay',server='127.0.0.1',server_port=9)])]
    current['settings'].update(interface_monitoring=True,monitored_interfaces=['wan'],interface_reload_delay_ms=1200)
    current['settings']=core.validate_settings(current['settings']);atlas.atomic(atlas.STATE,current)
    cfg=atlas.runtime_config(current,persist=False)
    atlas.check(cfg)
    assert next(x for x in cfg['outbounds'] if x['tag']=='section_'+'c'*16+'_entry')['detour']=='section_'+'d'*16+'_relay'
    dns=next(x for x in cfg['dns']['rules'] if x.get('domain_suffix')==['c.example.org'])
    assert 'port' not in dns and 'network' not in dns
    import copy
    large=copy.deepcopy(current);large['settings']['sections']=[];large['settings']['max_active_nodes']=0
    base=large['subscriptions'][0]['nodes'][0]
    large['subscriptions'][0]['nodes']=[dict(base,id='%016x'%i) for i in range(1100)]
    atlas.check(core.make_config(large,tun=False))
    resolve=[x for x in cfg['route']['rules'] if x.get('action')=='resolve']
    assert any(x.get('domain_suffix')==['a.example.org'] for x in resolve)
    assert not any(x.get('domain_suffix')==['b.example.org'] for x in resolve)
    rpc('action',dict(operation='start'));wait_job()
    proxies=atlas.clash_request()['proxies']
    for sec in current['settings']['sections'][:2]:
        prefix='section_'+sec['id']+'_';assert prefix+'control' in proxies and prefix+'auto' in proxies
    for sec,enabled in zip(current['settings']['sections'],(True,False)):
        clones=[x for x in cfg['outbounds'] if x['type']=='socks' and x['tag'].startswith('section_'+sec['id']+'_')]
        assert len(clones)==1 and clones[0]['udp_over_tcp']['enabled']==enabled
        assert clones[0]['tag'] in proxies
    # Cron is stopped by the test harness. This proves recovery uses its own event worker.
    event=atlas.record_interface_event('ifup','wan');assert event['reason']=='recorded'
    from pathlib import Path
    def workers():
        result=[]
        for p in Path('/proc').glob('[0-9]*/cmdline'):
            try:
                args=p.read_bytes().split(b'\0')
                if b'iface-recover' in args:result.append(p.parent.name)
            except OSError:pass
        return result
    for _ in range(20):
        assert atlas.record_interface_event('ifup','wan')['reason']=='coalesced'
        assert len(workers())<=1,workers()
    assert len(workers())==1,workers()
    subprocess.run([sys.executable,'/usr/lib/atlas/atlas.py','scheduled'],check=True,timeout=120)
    event_id=atlas.read_json(atlas.RUN/'interface-event.json',{})['id']
    for _ in range(180):
        handled=atlas.read_json(atlas.RUN/'interface-handled.json',{})
        if handled.get('id')==event_id:break
        time.sleep(1)
    else:raise AssertionError('Event recovery did not finish: '+str(atlas.read_json(atlas.RUN/'watchdog.json',{})))
    assert len(atlas.read_json(recovery_path,{})['attempts'])==1
    assert atlas.service_running()
    assert atlas.read_json(atlas.RUN/'watchdog.json',{})['reason']=='interface-restarted'
    for _ in range(90):
        try:
            live=atlas.clash_request()['proxies']
            if all('section_'+sec['id']+'_control' in live for sec in current['settings']['sections'][:2]):break
        except (core.AtlasError,OSError):pass
        time.sleep(1)
    else:raise AssertionError('Engine API not ready after event recovery')
    rpc('action',dict(operation='stop'));wait_job()
    print(json.dumps(dict(version=atlas.VERSION,native_engine_check=True,independent_groups_live=True,per_section_real_ip=True,wan_event_recovery_without_cron=True,engine_api_after_recovery=True,configured_delay_ms=1200,burst_events=21,maximum_recovery_workers=1,concurrent_scheduled_recovery_restart_count=1,section_udp_over_tcp=True,service_start_stop=True,cross_section_detour=True,dns_with_port_scope=True,unlimited_pool_engine_check_nodes=1100)))
finally:
    subprocess.run(['/etc/init.d/atlas','stop'],timeout=90)
    subprocess.run(['/etc/init.d/atlas','disable'],timeout=15)
    atlas.STATE.write_bytes(original)
    if prior_recovery is None:recovery_path.unlink(missing_ok=True)
    else:recovery_path.write_bytes(prior_recovery)
