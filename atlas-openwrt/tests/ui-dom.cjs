// Structural DOM smoke check; not a browser/layout test.
const fs=require('fs'),path=require('path');
class N {
 constructor(tag,text=''){this.tag=tag;this.data=text;this.children=[];this.attributes={};this.listeners={};this.value='';this.checked=false;}
 appendChild(c){this.children.push(c);return c;}
 replaceChildren(...c){this.children=c;}
 setAttribute(k,v){this.attributes[k]=v;if(k==='value')this.value=v;}
 addEventListener(k,v){this.listeners[k]=v;}
 get textContent(){return this.data+this.children.map(c=>c.textContent||'').join('');}
 set textContent(s){this.children=[];this.data=s;}
}
global.document={createTextNode:s=>new N('#text',String(s)),createElement:t=>new N(t)};
global.FileReader=class { readAsArrayBuffer(file){const b=Buffer.from(file.content,'utf8');this.result=b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength);if(this.onload)this.onload();} };
function E(t,a={},c=[]){const n=new N(t);for(const [k,v] of Object.entries(a)){if(typeof v==='function')n.listeners[k]=v;else if(v!==false&&v!=null){n.setAttribute(k,v);if(['disabled','checked','selected'].includes(k))n[k]=v;}}const add=x=>{if(Array.isArray(x))x.forEach(add);else if(x!=null)n.appendChild(x instanceof N?x:new N('#text',String(x)));};add(c);if(t==='textarea')n.value=n.textContent;if(t==='select'){const opt=n.children.find(c=>c.selected)||n.children[0];n.value=opt?.attributes.value||'';}return n;}
const initial={ok:true,version:'0.12.0',running:false,engine:'sing-box 1.14.1',job:{},applied:{},privacy:{checks:[{id:'dns_hijack',ok:true,label:'DNS проверяется'}],notice:'Аудит конфигурации'},privacy_egress:{status:'done',same_exit:false},settings:{mode:'rules',selected:'auto',domains:[],cidrs:[],bypass_domains:[],bypass_cidrs:[],blocked_domains:[],interval_hours:12,dns_filter:'cloudflare',fakeip:false,fakeip_ttl_seconds:60,kill_switch:false,remote_lists:[]},subscriptions:[],nodes:[],checks:{}};
const calls=[];let data=structuredClone(initial),modal=null;
const rpc={declare:({method})=>(...args)=>{calls.push({method,args});if(method==='status')return Promise.resolve(structuredClone(data));if(method==='monitor')return Promise.resolve({ok:true,available:true,connections:[],rules:[],memory:{},upload_total:0,download_total:0});if(method==='save_settings')data.settings=args[0];if(method==='import_rules')return Promise.resolve({ok:true,domains:2,cidrs:1});if(method==='import_subscriptions')return Promise.resolve({ok:true,added:1,duplicates:1,errors:0,items:[{line:1,name:'provider.example',status:'added'},{line:2,name:'provider.example',status:'duplicate'}]});return Promise.resolve({ok:true});}};
const ui={addNotification(){},showModal(t,c){modal=E('div',{},c)},hideModal(){modal=null}};
const L={hasViewPermission:()=>true,resource:s=>s};
const app=new Function('view','rpc','poll','ui','L','E',fs.readFileSync(path.join(__dirname,'../root/www/luci-static/resources/view/atlas/overview.js'),'utf8'))({extend:x=>x},rpc,{add(){}},ui,L,E);
const assert=(v,m)=>{if(!v)throw Error(m)};
const all=n=>[n,...n.children.flatMap(all)];
(async()=>{
 app.render(await app.load());
 assert(app.root.textContent.includes('Начните с подписки'),'Empty state missing');
 for(const t of ['overview','subscriptions','nodes','routing','privacy','monitor','settings']){app.navigate(t);assert(app.root.children.length===2,t+' failed');}
 data.subscriptions=[{id:'a'.repeat(16),name:'<img src=x onerror=alert(1)>',host:'example.com',count:1,enabled:true,metadata:{}}];
 data.nodes=[{key:'a'.repeat(32),name:'Node',subscription:'Test',type:'vless',server:'example.com',port:443}];
 app.data=data;
 for(const t of ['overview','subscriptions','nodes','routing','privacy','monitor','settings'])app.navigate(t);
 app.navigate('subscriptions');assert(!all(app.root).some(n=>n.tag==='img'),'HTML injection');
 app.subscriptionDialog();assert(modal.textContent.includes('Ссылка подписки'),'Add modal');assert(modal.textContent.includes('HTTP-заголовки провайдера'),'Provider header input missing');
 const url=all(modal).find(n=>n.attributes.type==='password');assert(url,'Secret input missing');
 const headerBox=all(modal).find(n=>n.tag==='textarea'&&(n.attributes.placeholder||'').includes('Authorization: Bearer'));assert(headerBox,'HTTP header textarea missing');headerBox.value='Authorization: Bearer private';
 all(modal).find(n=>n.tag==='button'&&n.textContent==='Сохранить').listeners.click({currentTarget:all(modal).find(n=>n.tag==='button'&&n.textContent==='Сохранить')});await new Promise(r=>setTimeout(r,0));
 const subscriptionSave=calls.find(c=>c.method==='save_subscription');assert(subscriptionSave&&subscriptionSave.args[4]==='Authorization: Bearer private'&&subscriptionSave.args[5]===false,'Provider headers were not sent through subscription save RPC: '+JSON.stringify(subscriptionSave));
 app.navigate('subscriptions');const bulk=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Массовый импорт');assert(bulk,'Batch import control missing');bulk.listeners.click({currentTarget:bulk});await new Promise(r=>setTimeout(r,0));
 const bulkBox=all(modal).find(n=>n.tag==='textarea');bulkBox.value='https://one.example/sub\nReserve | https://two.example/sub?token=a,b';
 const bulkSave=all(modal).find(n=>n.tag==='button'&&n.textContent==='Добавить источники');bulkSave.listeners.click({currentTarget:bulkSave});await new Promise(r=>setTimeout(r,0));
 const bulkCall=calls.find(c=>c.method==='import_subscriptions');assert(bulkCall&&bulkCall.args[0].length===2&&bulkCall.args[0][1].url==='https://two.example/sub?token=a,b','Batch import broke URLs containing commas');
 assert(modal.textContent.includes('Добавлено: 1'),'Batch import row report missing');
 app.localProfilesDialog();
 const localName=all(modal).find(n=>(n.attributes.class||'').includes('at-local-name'));localName.value='Local';
 const localBox=all(modal).find(n=>(n.attributes.class||'').includes('at-local-profiles'));localBox.value='vless://example';
 const localSave=all(modal).find(n=>n.tag==='button'&&n.textContent==='Импортировать профили');localSave.listeners.click({currentTarget:localSave});await new Promise(r=>setTimeout(r,0));
 assert(calls.some(c=>c.method==='import_profiles'&&c.args[0]==='Local'&&c.args[1]==='vless://example'),'Inline profile import RPC missing');
 app.navigate('nodes');const geoButton=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Проверить IP выхода');geoButton.listeners.click({currentTarget:geoButton});await new Promise(r=>setTimeout(r,0));
 assert(calls.some(c=>c.method==='action'&&c.args[0]==='geo_check'&&c.args[1]==='a'.repeat(32)),'Exit country check targeted the wrong node');
 app.deleteDialog(data.subscriptions[0]);assert(modal.textContent.includes('Удалить'),'Delete confirmation');
 app.navigate('routing');const inputs=all(app.root).filter(n=>n.tag==='textarea');inputs[0].value='example.org\nexample.net';
 const button=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила');button.listeners.click({currentTarget:button});
 await new Promise(r=>setTimeout(r,0));
 const saved=calls.find(c=>c.method==='save_settings');assert(saved.args[0].domains.length===2,'Save rules did not call RPC');
 app.navigate('privacy');assert(app.root.textContent.includes('DNS проверяется'),'Privacy audit view missing');
 assert(app.root.textContent.includes('Функциональная самопроверка'),'Router self-test view missing');
 assert(app.root.textContent.includes('Запустить тест')&&app.root.textContent.includes('api.ipify.org'),'External privacy test disclosure missing');
 const privacyButton=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Запустить тест');privacyButton.listeners.click({currentTarget:privacyButton});await new Promise(r=>setTimeout(r,0));
 assert(calls.some(c=>c.method==='action'&&c.args[0]==='privacy'),'External privacy test RPC missing');
 app.navigate('monitor');await new Promise(r=>setTimeout(r,0));assert(app.root.textContent.includes('Активные соединения'),'Live connection monitor missing');assert(calls.some(c=>c.method==='monitor'),'Monitor RPC missing');
 app.navigate('settings');assert(app.root.textContent.includes('AdGuard DoH'),'AdGuard DNS option missing');
 assert(app.root.textContent.includes('dnsmasq'),'DHCP/dnsmasq integration control missing');assert(app.root.textContent.includes('Хранение конфигурации и кеша'),'Storage controls missing');
 app.navigate('routing');assert(app.root.textContent.includes('Удалённые списки правил'),'Remote list editor missing');
 const remote=all(app.root).find(n=>n.tag==='textarea'&&(n.attributes.placeholder||'').startsWith('EasyList'));
 assert(remote,'Remote list textarea missing');remote.value='Public ads | https://lists.example.org/domains.txt | dnsblock | auto | on |';
 all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила').listeners.click({currentTarget:all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила')});
 await new Promise(r=>setTimeout(r,0));
 const listSave=calls.filter(c=>c.method==='save_settings').at(-1).args[0].remote_lists[0];
 assert(listSave.name==='Public ads'&&listSave.policy==='dnsblock'&&listSave.enabled,'Remote list form did not serialize');
 const community=all(app.root).find(n=>n.tag==='select'&&n.attributes.class==='at-input at-community-catalog');
 const communityPolicy=all(app.root).find(n=>n.tag==='select'&&n.attributes.class==='at-input at-community-policy');
 const communityIface=all(app.root).find(n=>n.tag==='input'&&n.attributes.class==='at-input at-community-interface');
 assert(community&&communityPolicy&&communityIface,'Community SRS catalog controls missing');
 community.value='telegram';communityPolicy.value='interface';communityIface.value='wg0';
 const addCommunity=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Добавить community list');addCommunity.listeners.click({currentTarget:addCommunity});await new Promise(r=>setTimeout(r,0));
 const communityText=all(app.root).find(n=>n.tag==='textarea'&&(n.attributes.placeholder||'').startsWith('EasyList')).value;
 assert(communityText.includes('https://github.com/itdoginfo/allow-domains/releases/latest/download/telegram.srs | interface | srs | on')&&communityText.trim().endsWith('| wg0'),'Community SRS URL/interface row not added');
 const saveCommunity=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила');saveCommunity.listeners.click({currentTarget:saveCommunity});await new Promise(r=>setTimeout(r,0));
 const communitySave=calls.filter(c=>c.method==='save_settings').at(-1).args[0].remote_lists[1];
 assert(communitySave.policy==='interface'&&communitySave.interface==='wg0'&&communitySave.format==='srs','Community list route policy did not serialize');
 const proxyUpdate=all(app.root).find(n=>n.tag==='input'&&n.attributes.class==='at-fetch-lists-proxy');
 assert(proxyUpdate,'Proxy-only list update option missing');proxyUpdate.checked=true;
 const proxySave=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила');proxySave.listeners.click({currentTarget:proxySave});await new Promise(r=>setTimeout(r,0));
 const proxySettings=calls.filter(c=>c.method==='save_settings').at(-1).args[0];
 assert(proxySettings.fetch_lists_via_proxy===true&&proxySettings.remote_lists[1].interface==='wg0','Proxy-only list update or interface setting was lost');
 const sectionBox=all(app.root).find(n=>n.tag==='textarea'&&(n.attributes.placeholder||'').startsWith('Работа | proxy'));
 sectionBox.value='VPN intranet | interface | intranet.example | | | | wg0 | https://dns.example/dns-query | br-lan\nExclude | exclude | local.example | | | | |\nPorts | block | | | 192.168.1.25 | | | | | 443,10000-20000 | udp';
 const saveRules=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить правила');saveRules.listeners.click({currentTarget:saveRules});await new Promise(r=>setTimeout(r,0));
 const sectionSave=calls.filter(c=>c.method==='save_settings').at(-1).args[0].sections;
 assert(sectionSave[0].policy==='interface'&&sectionSave[0].resolver==='https://dns.example/dns-query'&&sectionSave[0].source_interfaces[0]==='br-lan'&&sectionSave[1].policy==='exclude','VPN split DNS and source interface section did not serialize');
 assert(sectionSave[2].ports.join(',')==='443,10000-20000'&&sectionSave[2].networks[0]==='udp','Ports and transport section did not serialize');
 app.autoDialog();
 const preset=all(modal).find(n=>n.tag==='button'&&n.textContent==='Только Эстония');preset.listeners.click({currentTarget:preset});
 const autoFields=all(modal);const verified=autoFields.find(n=>n.attributes.class==='at-verified-countries');assert(verified,'Verified country filter missing');verified.checked=true;autoFields.filter(n=>n.tag==='input'&&n.attributes.type!=='checkbox')[1].value='RU';autoFields.filter(n=>n.tag==='input'&&n.attributes.type!=='checkbox')[2].value='EE, DE';
 autoFields.filter(n=>n.tag==='input'&&n.attributes.type!=='checkbox')[3].value='100';autoFields.filter(n=>n.tag==='input'&&n.attributes.type!=='checkbox')[4].value='400';
 autoFields.filter(n=>n.tag==='input'&&n.attributes.type!=='checkbox')[5].value='https://www.gstatic.com/generate_204';
 autoFields.find(n=>n.tag==='select').value='slowest';
 await new Promise(r=>setTimeout(r,0));
 const saveAuto=all(modal).find(n=>n.tag==='button'&&n.textContent==='Сохранить автовыбор');saveAuto.listeners.click({currentTarget:saveAuto});
 await new Promise(r=>setTimeout(r,0));
 const filters=calls.filter(c=>c.method==='save_settings').at(-1).args[0];
 assert(filters.countries[0]==='EE'&&filters.excluded_countries[0]==='RU'&&filters.preferred_countries[1]==='DE'&&filters.selected==='auto','Country filter and exclusion did not save actual auto filter');
 assert(filters.require_verified_countries===true,'Verified country setting did not serialize');
 assert(filters.auto_strategy==='slowest'&&filters.min_ping_ms===100&&filters.max_ping_ms===400,'Automatic selection criteria did not serialize');
 assert(filters.auto_interval_seconds===60&&filters.auto_tolerance_ms===80,'Auto timing lost');
 app.navigate('settings');
 const ttl=all(app.root).find(n=>n.tag==='input'&&String(n.attributes.min)==='1'&&String(n.attributes.max)==='86400');assert(ttl,'FakeIP TTL control missing');ttl.value='120';
 const guard=all(app.root).find(n=>n.tag==='label'&&n.textContent.includes('Fail-closed')).children.find(n=>n.tag==='input');assert(guard,'Fail-closed toggle missing');guard.checked=true;
 const saveSettings=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Сохранить настройки');saveSettings.listeners.click({currentTarget:saveSettings});await new Promise(r=>setTimeout(r,0));
 assert(calls.filter(c=>c.method==='save_settings').at(-1).args[0].fakeip_ttl_seconds===120&&calls.filter(c=>c.method==='save_settings').at(-1).args[0].kill_switch,'FakeIP TTL or kill switch setting did not serialize');
 app.navigate('routing');
 const file=all(app.root).find(n=>n.tag==='input'&&n.attributes.type==='file');assert(file,'Local rules file picker missing');
 file.files=[{size:26,content:'ads.example\n203.0.113.0/24\n'}];file.listeners.change({target:file});await new Promise(r=>setTimeout(r,0));
 const imported=calls.filter(c=>c.method==='import_rules').at(-1);assert(imported&&imported.args[1]==='proxy'&&Buffer.from(imported.args[0],'base64').toString('utf8').includes('ads.example'),'Local file import was not sent to the authenticated router RPC');
 data.runtime={available:true,selected:data.nodes[0].key,name:'Actual engine choice',automatic:true,candidate_count:1};app.data=data;app.navigate('nodes');
 assert(app.root.textContent.includes('Actual engine choice'),'Actual runtime selection not displayed');
 data.running=true;app.data=data;app.navigate('nodes');const choose=all(app.root).find(n=>n.tag==='button'&&n.textContent==='Выбрать');choose.listeners.click({currentTarget:choose});await new Promise(r=>setTimeout(r,0));
 assert(calls.some(c=>c.method==='action'&&c.args[0]==='apply'),'Manual node selection did not apply to the running engine');
 const browserFetches=[];const beforeClient=calls.length;global.fetch=(url,options)=>{browserFetches.push({url,options});return Promise.resolve({ok:true,json:()=>Promise.resolve({ip:url.includes('api6.')?'2001:db8::1':'203.0.113.1'})})};
 app.navigate('privacy');assert(app.root.textContent.includes('Проверить браузер'),'Client privacy button missing');await app.clientPrivacyTest();
 assert(browserFetches.length===2&&browserFetches.every(x=>x.options.credentials==='omit'&&x.options.referrerPolicy==='no-referrer'),'Browser privacy request metadata');
 assert(calls.length===beforeClient&&app.root.textContent.includes('2001:db8::1'),'Client IP must remain on the page');
 const beforeFakeip=calls.length;global.fetch=(url,options)=>{assert(options.credentials==='omit'&&options.referrerPolicy==='no-referrer');return Promise.resolve({ok:true,text:()=>Promise.resolve(JSON.stringify({fakeip:true,IP:url.includes('fakeip.')?'203.0.113.1':'198.51.100.2'}))})};
 await app.browserFakeipTest();assert(calls.length===beforeFakeip&&app.root.textContent.includes('Браузер использует маршрут FakeIP')&&app.root.textContent.includes('выходы различаются'),'Browser FakeIP chain test');
 global.fetch=()=>Promise.reject(new Error('Offline'));await app.browserFakeipTest();assert(app.root.textContent.includes('Проверка недоступна'),'Unavailable service must not imply a leak');
 const beforeMonitor=calls.filter(c=>c.method==='monitor').length;
 const pendingMonitor=app.requestMonitor();
 assert(app.requestMonitor()===pendingMonitor,'Concurrent monitor requests must share one promise');
 await pendingMonitor;
 assert(calls.filter(c=>c.method==='monitor').length===beforeMonitor+1,'Monitor request was duplicated');
 await app.requestMonitor();
 assert(calls.filter(c=>c.method==='monitor').length===beforeMonitor+2,'Settled request must release monitor gate');
 data.job={status:'running',message:'Testing'};app.data=data;app.navigate('overview');
 assert(app.busy(),'Operation not busy');
 console.log('PASS: seven views, connection monitor, privacy audit/self-test, ad-filter/FakeIP TTL, DHCP/DNS and storage controls, local list import, fail-closed control, community SRS catalogue/interface routes, split DNS/source-interface sections, text escaping, subscription dialog/provider headers, batch import and per-row report, deletion confirmation, rule save RPC, immediate manual selection, country allow/deny, ping strategy/thresholds, actual runtime choice, busy state.');
})().catch(e=>{console.error(e);process.exit(1)});
