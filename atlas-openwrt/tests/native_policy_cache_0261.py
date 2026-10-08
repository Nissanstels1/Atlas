"""Guarded policy through actual procd launcher and authenticated router RPC."""
import json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/usr/lib/atlas')
import atlas,core
def rpc(method,args={}):
    value=json.loads(subprocess.check_output(['ubus','call','atlas',method,json.dumps(args)],text=True));assert value.get('ok'),value;return value
def job(operation):
    requested=rpc('action',{'operation':operation})['job']
    for _ in range(150):
        value=rpc('status').get('job',{})
        if value.get('id')==requested and value.get('status') in ('done','error'):
            assert value['status']=='done',value;return
        time.sleep(1)
    raise AssertionError('Job timeout')
assert not atlas.service_running()
original=atlas.STATE.read_bytes()
old_config=atlas.CONFIG.read_bytes() if atlas.CONFIG.exists() else None
try:
    current=core.defaults();current['subscriptions']=[dict(id='b'*16,name='fixture',source='local',enabled=True,nodes=[core.uri_node('socks5://127.0.0.1:9#fixture')])]
    current['settings'].update(max_ping_ms=50,sections=[dict(id='c'*16,name='private',policy='proxy',domains=['fixture.invalid'],cidrs=[],source_ips=[],udp_over_tcp=True)])
    current['settings']=core.validate_settings(current['settings']);atlas.atomic(atlas.STATE,current)
    node=core.all_nodes(current)[0]['key'];group='section_'+'c'*16+'_control';member='section_'+'c'*16+'_'+node
    job('start')
    wire=json.loads(atlas.CONFIG.read_text())
    assert wire['experimental']['cache_file']['cache_id']=='atlas-policy-v2'
    assert any(x['tag'].startswith('atlas_run_') for x in wire['outbounds'])
    assert rpc('status')['runtime']['blocked']
    assert atlas.clash_request()['proxies']['proxy']['now']=='policy-block'
    rpc('section_select',dict(id='c'*16,group=group,member=member))
    assert atlas.clash_request()['proxies'][group]['now']==member
    live=next(x for x in json.loads(atlas.CONFIG.read_text())['outbounds'] if x['tag']==group)
    assert live['default'].startswith('atlas_run_')
    assert 'section_'+'c'*16+'_auto' not in live['outbounds']
    rpc('section_select',dict(id='c'*16,group=group,member='section_'+'c'*16+'_auto'))
    assert atlas.clash_request()['proxies'][group]['now']=='policy-block'
    assert group not in atlas.state()['settings']['section_choices']
    atlas.clash_request('PUT','/proxies/proxy',{'name':node})
    assert atlas.clash_request()['proxies']['proxy']['now']==node
    job('apply')
    assert atlas.clash_request()['proxies']['proxy']['now']=='policy-block'
    assert rpc('status')['runtime']['blocked']
    report=dict(version=atlas.VERSION,procd_launch_aliases=True,rpc_status_normalized=True,section_manual_selection=True,auto_return_fail_closed=True,live_config_aliases_preserved=True,cached_main_choice_rejected_after_restart=True)
    Path('/tmp/atlas-policy-cache-0261.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
    job('stop')
finally:
    subprocess.run(['/etc/init.d/atlas','stop'],timeout=90);subprocess.run(['/etc/init.d/atlas','disable'],timeout=15)
    atlas.STATE.write_bytes(original)
    if old_config is not None:atlas.CONFIG.write_bytes(old_config)
    else:atlas.CONFIG.unlink(missing_ok=True)
