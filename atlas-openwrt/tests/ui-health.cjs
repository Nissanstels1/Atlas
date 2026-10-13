const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const source=fs.readFileSync(path.join(__dirname,'../root/www/luci-static/resources/view/atlas/overview.js'),'utf8');
const h=new Function(source.slice(source.indexOf('function atlasElement'),source.indexOf('return view.extend({'))+'return {atlasHelp,atlasProfileHealth,atlasCommunityLists,atlasSelectableLists};')();
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
