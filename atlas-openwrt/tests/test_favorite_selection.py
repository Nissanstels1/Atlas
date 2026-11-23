"""Favorite selection and protection of active profile evidence."""
import json,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import atlas,core
from test_selection import sample

class FavoriteSelection(unittest.TestCase):
 def setup_nodes(self):
  current=sample();nodes=core.all_nodes(current);keys=[x['key'] for x in nodes]
  current['settings'].update(favorite_profile=keys[0],auto_strategy='fastest',auto_tolerance_ms=350)
  current['settings']=core.validate_settings(current['settings'])
  stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
  proxies={keys[0]:{'history':[{'delay':150,'time':stamp}]},keys[1]:{'history':[{'delay':80,'time':stamp}]}}
  return current,nodes,keys,proxies
 def test_favorite_wins_only_when_eligible_and_fresh(self):
  current,nodes,keys,proxies=self.setup_nodes()
  self.assertEqual(atlas.auto_choice(nodes,current['settings'],proxies),keys[0])
  self.assertEqual(atlas.auto_choice(nodes[1:],current['settings'],proxies),keys[1])
  proxies[keys[0]]['history']=[]
  self.assertEqual(atlas.auto_choice(nodes,current['settings'],proxies),keys[1])
  self.assertEqual(current['settings']['selected'],'auto')
 def test_favorite_can_return_after_a_new_success(self):
  current,nodes,keys,proxies=self.setup_nodes()
  old=proxies[keys[0]]['history'];proxies[keys[0]]['history']=[]
  self.assertEqual(atlas.auto_choice(nodes,current['settings'],proxies,previous=keys[1]),keys[1])
  proxies[keys[0]]['history']=old
  self.assertEqual(atlas.auto_choice(nodes,current['settings'],proxies,previous=keys[1]),keys[0])
 def test_favorite_failure_notice_ignores_manual_and_unknown_entries(self):
  current,nodes,keys,proxies=self.setup_nodes()
  proxies['proxy']={'now':keys[0]}
  self.assertFalse(atlas.favorite_failure_observed(current,proxies))
  proxies[keys[0]]['history']=[]
  self.assertTrue(atlas.favorite_failure_observed(current,proxies))
  current['settings']['selected']=keys[0]
  self.assertFalse(atlas.favorite_failure_observed(current,proxies))
  current['settings']['selected']='auto';del proxies[keys[0]]
  self.assertFalse(atlas.favorite_failure_observed(current,proxies))
 def test_favorite_failure_starts_selection_without_full_round(self):
  current,nodes,keys,proxies=self.setup_nodes()
  proxies['proxy']={'now':keys[0]};proxies[keys[0]]['history']=[]
  stop=mock.Mock();stop.wait.side_effect=[False,True]
  with tempfile.TemporaryDirectory() as directory,mock.patch.object(atlas,'RUN',Path(directory)),mock.patch.object(atlas,'state',return_value=current),mock.patch.object(atlas,'clash_request',return_value={'proxies':proxies}),mock.patch.object(atlas,'automatic_select_from_worker') as select:
   atlas.watch_favorite_failure(stop)
  select.assert_called_once_with(stop)
  self.assertEqual(stop.wait.call_args_list,[mock.call(5),mock.call(5)])
 def test_startup_retries_until_measured_profile_is_selected(self):
  current,nodes,keys,proxies=self.setup_nodes()
  stop=mock.Mock();stop.wait.return_value=False
  outcomes=[{'groups':[{'ok':True,'blocked':True}]},{'groups':[{'ok':True,'blocked':False}]}]
  with tempfile.TemporaryDirectory() as directory,mock.patch.object(atlas,'RUN',Path(directory)),mock.patch.object(atlas,'state',return_value=current),mock.patch.object(atlas,'automatic_select_from_worker',side_effect=outcomes) as select:
   atlas.bootstrap_auto_selection(stop)
  self.assertEqual(select.call_count,2)
 def test_active_member_checked_before_any_switch(self):
  for outcome in ('ok','failed','unknown'):
   with self.subTest(outcome=outcome):
    current,nodes,keys,proxies=self.setup_nodes();proxies['proxy']={'now':keys[0]};proxies[keys[0]]['history']=[];calls=[]
    def request(method='GET',path='/proxies',body=None,**kwargs):
     calls.append((method,path))
     if path=='/proxies':return {'proxies':proxies}
     if '/delay?' in path:
      if outcome=='failed':raise atlas.AtlasError('Локальный API вернул HTTP 503')
      if outcome=='unknown':raise OSError('connection lost')
      return {'delay':150}
     return {}
    with tempfile.TemporaryDirectory() as directory,mock.patch.object(atlas,'RUN',Path(directory)),mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=request):
     result=atlas.automatic_select(current)
    self.assertTrue(any('/delay?' in p for _,p in calls))
    switches=[x for x in calls if x[0]=='PUT']
    self.assertEqual(bool(switches),outcome=='failed')
    if outcome=='failed':self.assertEqual(result['selected'],keys[1])
    else:self.assertEqual(result['selected'],keys[0])
 def test_stable_tolerance_uses_latest_latency(self):
  s=core.validate_settings({'auto_strategy':'stable','auto_tolerance_ms':350})
  candidates=[(0,0,100,100,'new'),(0,0,900,200,'current')]
  self.assertEqual(core.rank_auto_candidates(candidates,s,'current'),'current')
 def test_fastest_mode_checks_current_member_before_round(self):
  current,nodes,keys,proxies=self.setup_nodes()
  current['settings']['favorite_profile']=''
  current['settings']['auto_interval_seconds']=1800
  proxies['proxy']={'now':'auto'};proxies['auto']={'now':keys[0]}
  proxies[keys[0]]['history']=[{'delay':150,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()-1700))}]
  calls=[]
  def request(method='GET',path='/proxies',body=None,**kwargs):
   calls.append((method,path))
   if path=='/proxies':return {'proxies':proxies}
   if '/delay?' in path:return {'delay':150}
   return {}
  with tempfile.TemporaryDirectory() as directory,mock.patch.object(atlas,'RUN',Path(directory)),mock.patch.object(atlas,'service_running',return_value=True),mock.patch.object(atlas,'clash_request',side_effect=request):
   atlas.automatic_select(current)
  self.assertTrue(any('/delay?' in path and keys[0] in path for _,path in calls))
 def test_active_is_scheduled_before_a_large_round(self):
  now=int(time.time());settings=core.validate_settings({'auto_interval_seconds':1800})
  def sample_at(age):return {'delay':100,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now-age))}
  self.assertFalse(atlas.active_sample_needs_check(sample_at(100),settings,now,pool_size=151))
  self.assertTrue(atlas.active_sample_needs_check(sample_at(1700),settings,now,pool_size=151))
  self.assertTrue(atlas.active_sample_needs_check({},settings,now,pool_size=151))
 def test_stable_history_preserves_failures(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);config=root/'config.json';config.write_text('{}')
   key='a'*32
   with mock.patch.object(atlas,'RUN',root),mock.patch.object(atlas,'CONFIG',config):
    first={'delay':100,'time':'2026-11-23T12:00:00Z'};second={'delay':120,'time':'2026-11-23T12:01:00Z'}
    atlas.remember_auto_history({key:{'history':[first]}})
    result=atlas.remember_auto_history({key:{'history':[second]}})
    self.assertEqual([x['delay'] for x in result[key]['history']],[100,120])
    failed=atlas.remember_auto_history({key:{'history':[]}})
    self.assertEqual(failed[key]['history'],[])
 def test_long_interval_and_no_forced_connection_reset(self):
  state=sample();state['settings'].update(auto_interval_seconds=7200,auto_strategy='stable',interrupt_connections=False)
  config=core.make_config(state)
  self.assertFalse(next(x for x in config['outbounds'] if x['tag']=='proxy')['interrupt_exist_connections'])
  group=next(x for x in config['outbounds'] if x['tag']=='auto')
  self.assertEqual(group['interval'],'7200s');self.assertEqual(group['idle_timeout'],'7200s')
  state,nodes,keys,_=self.setup_nodes();state['settings']['favorite_profile']=keys[2]
  cfg=core.make_config(state);self.assertEqual(next(x for x in cfg['outbounds'] if x['tag']=='auto')['outbounds'][0],keys[2])
  with self.assertRaises(core.AtlasError):core.validate_settings({'favorite_profile':'invalid'})

if __name__=='__main__':unittest.main()
