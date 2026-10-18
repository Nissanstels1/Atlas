const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../root/www/luci-static/resources/view/atlas/overview.js'),'utf8');
const h=new Function(source.slice(source.indexOf('function atlasElement'),source.indexOf('return view.extend({'))+'return {atlasHelp,atlasProfileHealth,atlasCommunityLists,atlasSelectableLists,atlasSectionChoice,atlasSectionConnection,atlasRouteChain,atlasActiveProfiles};')();
const now=new Date().toISOString(),old=new Date(Date.now()-600000).toISOString();
const data={running:true,settings:{auto_interval_seconds:60},nodes:[{key:'a'},{key:'b'},{key:'c'},{key:'d'},{key:'e',eligible:false}],runtime:{available:true,measurements:{a:{ok:true,latency_ms:150,checked_at:now},b:{ok:true,latency_ms:160,checked_at:old},c:{ok:false,latency_ms:0,checked_at:now},e:{ok:true,latency_ms:100,checked_at:now}}},checks:{d:{ok:true,latency_ms:10,checked:Date.now()/1000}}};
const health=h.atlasProfileHealth(data);
assert.equal(health.passed,1);assert.equal(health.stale,1);assert.equal(health.failed,1);assert.equal(health.missing,1);assert.equal(health.excluded,1);
assert(health.summary.includes('отвечают 1'));assert(!health.summary.includes('HTTPS'));
assert.equal(h.atlasProfileHealth({...data,runtime:{available:false}}).summary,'Автопроверка: нет данных от движка');
assert.equal(h.atlasProfileHealth({...data,running:false}).summary,'Автопроверка: Atlas остановлен');
assert.equal(h.atlasProfileHealth({...data,runtime:{available:true,measurements:{}}}).passed,0);
for(const title of ['Группа включена','Использовать список','Использовать подписку','Fail-closed: блокировать LAN → WAN при остановке Atlas','Автоматически направлять DNS dnsmasq в Atlas','Использовать FakeIP для доменов через прокси','Блокировать QUIC (UDP/443), чтобы приложения переходили на TCP','Разрывать текущие соединения при переключении','Проверять группы по порядку вместе с их списками']){
 const explanation=h.atlasHelp(title);assert(explanation.body,title+' needs purpose');assert(explanation.enabled,title+' needs enabled consequence');assert(explanation.disabled,title+' needs disabled consequence');
}
assert(h.atlasHelp('Исключить по названию').example.includes('LTE'));
assert(h.atlasHelp('Полностью маршрутизированные IP-адреса').body.includes('даже если сайты'));
assert(h.atlasHelp('Домены-исключения').body.includes('прямой доступ'));
assert(h.atlasHelp('Исключить домены').body.includes('не обязательно прямой'));
console.log('PASS: automatic status ignores manual tests, separates fresh/stale/failed/missing/filtered profiles; switch help explains purpose and both outcomes.');

assert.equal(h.atlasCommunityLists().length,25);assert(h.atlasCommunityLists().some(x=>x[0]==='google_meet'));
assert.equal(h.atlasSelectableLists({list_catalogue:[{id:'a'.repeat(16),name:'User source'}]}).length,26);

const sid='a'.repeat(16),sub='b'.repeat(16),key='b'.repeat(32),section={id:sid,name:'Videos',policy:'proxy',pool:'',pools:[]};
const choices={settings:{selected:key,section_choices:{}},subscriptions:[{id:sub,name:'Provider'}],nodes:[{key,name:'Profile'}]};
assert.equal(h.atlasSectionConnection(section,choices),'Автовыбор · Все подписки');
assert.equal(h.atlasSectionConnection({...section,pools:[sub]},choices),'Автовыбор · Подписок: 1');
assert.equal(h.atlasSectionConnection(section,choices,key),'Закреплён: Profile · Все подписки');
assert.equal(h.atlasSectionChoice(section,choices,'section_'+sid+'_'+key),key);
assert.equal(h.atlasSectionChoice(section,choices,'section_'+sid+'_auto'),'auto');
assert.equal(h.atlasSectionConnection({...section,pools:null},choices),'Закреплён: Profile · Общий пул');
choices.settings.section_choices['pool_'+sub]=key;
assert.equal(h.atlasSectionConnection({...section,pools:null,pool:sub},choices),'Закреплён: Profile · Provider');
choices.settings.section_choices['pool_'+sub]='auto_'+sub;
assert.equal(h.atlasSectionConnection({...section,pools:null,pool:sub},choices),'Автовыбор · Provider');
assert.equal(h.atlasSectionConnection({...section,outbound_config_set:true},choices),'Свой JSON выход');
assert.equal(h.atlasSectionConnection({...section,policy:'direct'},choices),'');
console.log('PASS: section cards and editor agree on independent/shared/manual/automatic/custom connections and staged selections.');

const routeData={nodes:[{key:'node',name:'Server'}],subscriptions:[],settings:{sections:[{id:'a'.repeat(16),name:'Video'}]}};
const prefix='section_'+'a'.repeat(16)+'_';
assert.equal(h.atlasRouteChain(['node',prefix+'auto',prefix+'control'],routeData),'Server → Секция: Video');
assert.equal(h.atlasRouteChain(['direct'],routeData),'Напрямую');
assert.equal(h.atlasRouteChain([],routeData),'неизвестно');
assert.equal(h.atlasRouteChain(['unrecognized','direct','unrecognized'],routeData),'unrecognized → Напрямую → unrecognized');
console.log('PASS: monitor collapses adjacent selector labels, preserves distinct route steps and unknown tags.');
const usageData={runtime:{available:true,selected:'one'},nodes:[{key:'one'},{key:'two'}],subscriptions:[]};
const selectedSection=(id,name,selected)=>({id,name,groups:[{tag:'control',type:'selector',selected:'auto'},{tag:'auto',type:'urltest',selected}]});
const used=h.atlasActiveProfiles(usageData,[selectedSection('a','Main','one'),selectedSection('b','YouTube','section_b_one'),selectedSection('c','Work','two')]);
assert.deepEqual(used.one.sections,['Main','YouTube']);assert.deepEqual(used.two.sections,['Work']);
assert.deepEqual(h.atlasActiveProfiles(usageData,[]).one.sources,['Общий профиль']);
const manual=selectedSection('d','Manual','two');manual.groups[0].selected='one';
const manualUsage=h.atlasActiveProfiles({...usageData,runtime:{}},[manual]);assert.deepEqual(manualUsage.one.sections,['Manual']);assert(!manualUsage.two);
const cycle=selectedSection('e','Cycle','control');assert.deepEqual(Object.keys(h.atlasActiveProfiles({...usageData,runtime:{}},[cycle])),[]);
console.log('PASS: active profiles list exact independent section names; manual choices ignore unused auto winners; cycles add no usage.');
