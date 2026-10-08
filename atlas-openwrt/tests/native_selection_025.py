from pathlib import Path
import sys,types,json,copy,calendar,time
from unittest import mock
root=Path('work/atlas/atlas-openwrt')
sys.path.insert(0,'/usr/lib/atlas')
if sys.platform=='win32':sys.modules['fcntl']=types.SimpleNamespace()
import core,atlas,sections

def section(**kwargs):return dict(name='fixture',id='a'*16,policy='proxy',domains=['example.org'],cidrs=[],source_ips=[],pool='',interface='',resolver='')|kwargs
def state():
    value=core.defaults()
    value['subscriptions']=[dict(id='b'*16,name='fixture',enabled=True,source='local',nodes=[core.uri_node('socks5://127.0.0.1:1080#fixture')])]
    return value
results=[]

current=state();current['settings'].update(auto_strategy='stable',auto_interval_seconds=60,sections=[section(auto_interval_seconds=300)])
current['settings']=core.validate_settings(current['settings'])
node=core.all_nodes(current)[0]
stamp=1700000000
history=[dict(delay=40,time=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(stamp-200)))]
tag='section_'+'a'*16+'_control'
proxies={node['key']:dict(history=history),tag:dict(now='old')}
with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}),mock.patch.object(atlas,'atomic'),mock.patch.object(atlas.time,'time',return_value=stamp):
    selected=next(x['selected'] for x in atlas.automatic_select(current)['groups'] if x['group']==tag)
expected=atlas.auto_choice([node],dict(current['settings'],auto_interval_seconds=300),proxies,now=stamp)
assert selected==expected==node['key']
results.append(dict(id='section_interval_ignored_by_custom_selection',resolved=True,section_interval_seconds=300,global_interval_seconds=60,measurement_age_seconds=200,actual=selected,expected='measured-node'))

current=state();current['settings']['sections']=[section(auto_interval_seconds=300)]
current['settings']=core.validate_settings(current['settings'])
cfg=core.make_config(current,tun=False);proxies={x['tag']:dict(now='old') for x in cfg['outbounds']}
calls=[]
def request(method='GET',path='/proxies',*args,**kwargs):
    if method=='GET':return {'proxies':proxies}
    calls.append(path)
    if path=='/proxies/proxy':raise core.AtlasError('simulated transient failure')
    return {}
with mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=request):
    result=atlas.automatic_select(current)
assert calls==['/proxies/proxy','/proxies/'+tag] and result['reason']=='partial-failure'
results.append(dict(id='one_group_error_aborts_all_remaining_groups',resolved=True,attempted=calls,processed_section=tag))

current=core.defaults();current['settings'].update(max_active_nodes=1024,sections=[section()])
for sid in ('b'*16,'c'*16):
    current['subscriptions'].append(dict(id=sid,name='fixture',enabled=True,source='local',nodes=[core.uri_node('socks5://127.0.0.1:'+str(10000+i)+'#fixture'+str(i)) for i in range(512)]))
current['settings']=core.validate_settings(current['settings']);cfg=core.make_config(current,tun=False)
all_tags={n['key'] for n in core.all_nodes(current)}
tested=sections.test_section(current,cfg,'a'*16,lambda *args,**kwargs:{'delay':1})
tested_nodes=all_tags.intersection(tested)
assert len(all_tags)==1024 and len(tested_nodes)==1024
results.append(dict(id='section_delay_test_silently_skips_last_two_of_1024_nodes',resolved=True,total_nodes=1024,tested_nodes=len(tested_nodes),skipped=0))
report=dict(version='0.25.0',podkop_reference='0.7.22',findings=results,scope='Deterministic counterexamples with mocked controller; no physical-router claims')

print(json.dumps(report,indent=2))
