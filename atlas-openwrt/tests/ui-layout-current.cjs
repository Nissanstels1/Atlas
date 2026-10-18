/* Actual headless-browser tests with mocked router RPC, no external requests. */
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'..');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.ATLAS_BROWSER||undefined});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 try {
  await page.setContent('<html lang="ru"><meta charset="utf-8"><body style="margin:0;padding:20px;background:#e9edf3"><div id="app"></div></body></html>');
  await page.addStyleTag({content:fs.readFileSync(path.join(root,'root/www/luci-static/resources/atlas/atlas.css'),'utf8')});
  await page.evaluate(source=>{
   window.calls=[];window.notifications=[];
   const E=(tag,attrs={},children=[])=>{const n=document.createElement(tag);Object.entries(attrs).forEach(([k,v])=>{if(typeof v==='function')n.addEventListener(k,v);else if(v!=null&&v!==false){if(['checked','disabled','selected'].includes(k))n[k]=v;else n.setAttribute(k,String(v));}});const add=x=>{if(Array.isArray(x))x.forEach(add);else if(x!=null)n.appendChild(x instanceof Node?x:document.createTextNode(String(x)));};add(children);return n;};
   const settings={mode:'rules',selected:'auto',domains:[],cidrs:[],bypass_domains:[],bypass_cidrs:[],sections:[],remote_lists:[{id:'c'.repeat(16),name:'Fixture list',url:'https://example.org/rules.txt',policy:'proxy',format:'domains',enabled:true}],interval_hours:12,dns_filter:'cloudflare'};
   const state={ok:true,version:'0.19.0',running:false,engine:'sing-box 1.12.17',job:{},applied:{},settings,subscriptions:[{id:'b'.repeat(16),name:'Локальные профили',source:'local',enabled:true,count:1,metadata:{}}],nodes:[{key:'b'.repeat(32),name:'Fixture',type:'trojan',subscription:'Локальные профили',eligible:true}],checks:{},interfaces:['br-lan','wg0']};
   state.subscriptions[0].host='Локальный импорт';state.autostart=true;state.running=true;state.settings={"mode": "rules", "selected": "auto", "domains": [], "cidrs": [], "bypass_domains": [], "bypass_cidrs": [], "interval_hours": 12, "list_catalogue": [], "countries": [], "excluded_countries": [], "preferred_countries": [], "require_verified_countries": false, "protocols": [], "include_names": [], "exclude_names": [], "group_order": false, "auto_interval_seconds": 60, "auto_tolerance_ms": 80, "interrupt_connections": false, "auto_strategy": "fastest", "min_ping_ms": 0, "max_ping_ms": 0, "urltest_url": "https://www.gstatic.com/generate_204", "urltest_fallbacks": [], "urltest_download_check": "default", "urltest_download_url": "", "bootstrap_dns_type": "https", "bootstrap_dns_server": "1.1.1.1", "bootstrap_dns_sni": "cloudflare-dns.com", "bootstrap_dns_path": "/dns-query", "udp_over_tcp": false, "udp_over_tcp_version": 2, "interface_monitoring": false, "monitored_interfaces": [], "interface_reload_delay_ms": 2000, "default_interface": "", "log_level": "warn", "dns_filter": "cloudflare", "fakeip": false, "fakeip_ttl_seconds": 60, "resolve_real_ip": false, "browser_diagnostics": false, "yacd_enabled": false, "yacd_wan": false, "yacd_listen": "127.0.0.1", "blocked_domains": [], "max_active_nodes": 2048, "routing_excluded_ips": [], "routed_source_ips": [], "capture_interfaces": [], "sections": [{"name": "Video", "policy": "proxy", "pool": "", "pools": [], "interface": "", "resolver": "", "resolve_real_ip": null, "auto_interval_seconds": null, "auto_tolerance_ms": null, "urltest_url": "", "udp_over_tcp": null, "udp_over_tcp_version": null, "urltest_fallbacks": [], "urltest_download_check": "default", "urltest_download_url": "", "site_checks": [], "id": "aaaaaaaaaaaaaaaa", "enabled": true, "outbound_config": [], "mixed_proxy": {"enabled": false, "listen": "", "port": 2081, "username": "", "password": ""}, "source_interfaces": [], "ports": [], "networks": [], "domains": ["example.org"], "cidrs": [], "source_ips": [], "routed_source_ips": [], "exclude_domains": [], "exclude_cidrs": [], "exclude_source_ips": []}], "disable_quic": false, "exclude_ntp": false, "kill_switch": false, "custom_dns_type": "https", "custom_dns_server": "", "custom_dns_sni": "", "custom_dns_path": "/dns-query", "mixed_proxy_enabled": false, "mixed_proxy_listen": "", "mixed_proxy_port": 2080, "mixed_proxy_username": "", "mixed_proxy_password": "", "block_known_doh": false, "fetch_lists_via_proxy": false, "fetch_lists_subscription": "", "fetch_lists_section": "", "section_choices": {}, "remote_lists": [], "list_max_bytes": 4194304, "dhcp_dns_enabled": false, "config_storage": "flash", "config_custom_dir": "", "cache_storage": "flash", "cache_custom_path": ""};state.nodes[0].server='very-long-proxy-address.for-layout-testing.example.org';state.nodes[0].port=443;state.engine_features=['urltest.fallbacks','urltest.download_url','tools.decode-link'];
   const status=()=>{const data=structuredClone(state);data.settings.sections.forEach(x=>{x.outbound_config_set=!!x.outbound_config?.length;delete x.outbound_config;if(x.mixed_proxy)delete x.mixed_proxy.password;});return data;};
   const rpc={declare:({method})=>(...args)=>{window.calls.push({method,args});if(method==='nft_diagnostics')return Promise.resolve({ok:true,checks:[{ok:true,label:'nft fixture'}],details:{}});
    if(method==='set_autostart'){state.autostart=args[0];return Promise.resolve({ok:true});}
    if(method==='service_logs')return Promise.resolve({ok:true,content:'<b>fixture journal</b>',truncated:false});
    if(method==='config_preview')return Promise.resolve({ok:true,config:{route:{final:'direct'}},validated:args[0],conflicts:[]});
    if(method==='route_explain')return Promise.resolve({ok:true,certain:true,outbound:'direct',action:'route',trace:[{index:4,match:'yes'}]});
    if(method==='section_clone'){const old=state.settings.sections.find(x=>x.id===args[0]);state.settings.sections.push({...structuredClone(old),name:args[1],id:'d'.repeat(16),enabled:false,mixed_proxy:{enabled:false}});return Promise.resolve({ok:true,id:'d'.repeat(16)});}
    if(method==='section_dashboard')return Promise.resolve({ok:true,sections:[{id:'1'.repeat(16),name:'Независимая секция',groups:[{tag:'section_group',type:'selector',selected:'one',shared:false,members:[{tag:'one',name:'Первый',delay:12},{tag:'two',name:'Второй',delay:25}]}]}]});
    if(method==='section_select')return Promise.resolve({ok:true});
    if(method==='monitor')return Promise.resolve({ok:true,available:true,connections:[{host:'very-long-subdomain.for-layout-testing.example.org',rule:'domain_suffix=example.org',source:'192.168.1.25:12345',network:'tcp',chains:['section_'+'a'.repeat(16)+'_auto','section_'+'a'.repeat(16)+'_control'],upload:12345,download:67890}],rules:[],memory:{}});if(method==='status')return Promise.resolve(status());
    if(method==='save_settings'){state.settings=structuredClone(args[0]);state.settings.sections.forEach((x,i)=>{x.id=x.id||String(i+1).padStart(16,'0');});}
    if(method==='section_details')return Promise.resolve({ok:true,outbound_config:state.settings.sections.find(x=>x.id===args[0]).outbound_config||[]});
    if(method==='get_profiles')return Promise.resolve({ok:true,content:JSON.stringify({outbounds:[{type:'trojan',server:'fixture.example',server_port:443,password:'fixture-only',tls:{enabled:true},tag:'Fixture'}]})});
    if(method==='import_profiles')return Promise.resolve({ok:true,count:1});
    if(method==='import_rules')return Promise.resolve({ok:true,rules:2,domains:0,cidrs:0});
    if(method==='diagnostic_report')return Promise.resolve({ok:true,report:{format:'atlas-diagnostics',version:'0.19.0'}});
    if(method==='export_backup')return Promise.resolve({ok:true,backup:{format:'atlas-backup',schema:1,state}});
    return Promise.resolve({ok:true});}};
   const ui={addNotification:(n,m)=>window.notifications.push(m.textContent),hideModal:()=>document.querySelector('#modal')?.remove(),showModal:(title,children)=>{ui.hideModal();document.body.appendChild(E('div',{id:'modal',style:'position:fixed;inset:20px;max-width:960px;margin:auto;padding:24px;background:#202632;color:white;z-index:10;overflow:auto;border-radius:12px;'},[E('h2',{},title),children]));}};
   const app=new Function('view','rpc','poll','ui','L','E',source)({extend:x=>x},rpc,{add(){}},ui,{hasViewPermission:()=>true,resource:()=> 'data:text/css,'},E);
   window.app=app;window.state=state;
   app.load().then(d=>document.querySelector('#app').appendChild(app.render(d)));
  },fs.readFileSync(path.join(root,'root/www/luci-static/resources/view/atlas/overview.js'),'utf8'));

  // Reproduce the inherited rule in the user's LuCI theme.
  await page.addStyleTag({content:'button{word-break:break-all}#app{max-width:940px;margin:auto}'});
  const results=[];
  for(const width of [320,360,390,420,421,650,651,768,1024,1150,1280,1440]) {
   await page.setViewportSize({width,height:1000});
   for(const tab of ['overview','subscriptions','nodes','routing','lists','privacy','monitor','settings']) {
    await page.evaluate(t=>app.navigate(t),tab);
    const check=await page.evaluate(()=>{
     const r=document.querySelector('.atlas'),box=r.getBoundingClientRect();
     const outside=Array.from(r.querySelectorAll('button,input,select,textarea')).filter(e=>{const b=e.getBoundingClientRect();return b.width>0&&(b.left<box.left-1||b.right>box.right+1)}).map(e=>e.textContent||e.getAttribute('aria-label'));
     const nav=Array.from(r.querySelectorAll('.at-nav button')).map(e=>{
      const text=e.querySelector('.at-nav-text');const range=document.createRange();range.selectNodeContents(text);
      const b=e.getBoundingClientRect(),rects=Array.from(range.getClientRects());
      return {name:text.textContent,broken:getComputedStyle(text).wordBreak!=='normal',outside:rects.some(x=>x.left<b.left-1||x.right>b.right+1)};
     });
     return {overflow:r.scrollWidth-r.clientWidth,outside,nav,connectionOverflow:Array.from(r.querySelectorAll('.at-flow-list')).some(e=>e.scrollWidth-e.clientWidth>1),bad:r.innerText.match(/.{0,60}(?:undefined|\[object Object\]).{0,60}/g)};
    });
    if(check.overflow>1||check.connectionOverflow||check.outside.length||check.bad||check.nav.some(x=>x.broken||x.outside))throw Error(JSON.stringify({width,tab,...check}));
   }
   await page.evaluate(()=>app.sectionDialog(app.data.settings.sections[0],()=>{}));
   const modal=await page.locator('#modal').evaluate(m=>({overflow:m.scrollWidth-m.clientWidth,bad:/undefined|\[object Object\]/.test(m.innerText)}));
   if(modal.overflow>1||modal.bad)throw Error(JSON.stringify({width,modal}));
   await page.getByRole('button',{name:'Отмена',exact:true}).click();
   results.push({width,views:8,sectionDialog:'PASS'});
  }
  // A long-lived page must mark real leaf selections, including independent
  // sections, without marking an unused urltest winner in manual mode.
  await page.evaluate(()=>{
   const base=app.data.nodes[0];app.data.nodes=[base,{...base,key:'c'.repeat(32),name:'Pool leaf'},{...base,key:'d'.repeat(32),name:'Section leaf'}];
   app.data.runtime={available:true,selected:base.key,groups:[{selected:'c'.repeat(32)}]};
   app.tab='nodes';app.draw();
   app.liveSections=[{id:'a'.repeat(16),groups:[{tag:'control',type:'selector',selected:'auto'},{tag:'auto',type:'urltest',selected:'section_'+'a'.repeat(16)+'_'+'d'.repeat(32)}]}];app.updateNodeTable();
  });
  if(await page.locator('.at-profile-rows tr.selected').count()!==3)throw Error('Missing active pool/section leaf');
  const selectedStyle=await page.locator('.at-profile-rows tr.selected').first().evaluate(e=>({background:getComputedStyle(e).backgroundColor,outline:getComputedStyle(e).outlineWidth,cell:getComputedStyle(e.cells[0]).backgroundColor}));
  if(selectedStyle.background==='rgba(0, 0, 0, 0)'||selectedStyle.outline==='0px'||selectedStyle.cell!=='rgba(0, 0, 0, 0)')throw Error('Active row is not highlighted as a whole');
  await page.evaluate(()=>{app.liveSections[0].groups[0].selected=app.data.nodes[0].key;app.updateNodeTable();});
  if(await page.locator('.at-profile-rows tr.selected').count()!==2)throw Error('Unused auto leaf highlighted in manual mode');
  for(const width of [390,1440]){
   await page.setViewportSize({width,height:1000});
   await page.evaluate(()=>{app.tab='monitor';app.monitor={available:true,connections:Array.from({length:10},(_,i)=>({host:'media'+i+'.example.org',source:'192.168.1.25:12345',network:'tcp',chains:['direct'],upload:12345,download:67890}))};app.draw();});
   const heights=await page.locator('.at-flow').evaluateAll(rows=>rows.map(e=>e.getBoundingClientRect().height));
   if(heights.length!==10||Math.max(...heights)>(width<650?95:65))throw Error(JSON.stringify({width,heights}));
  }
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: 96 page layouts and 12 section dialogs, inherited LuCI button wrapping, all navigation captions and controls inside their containers.');
  console.log(JSON.stringify(results));
  console.log('PASS: compact connection rows, full active-row colour, pool and independent-section leaf selection, unused auto winner excluded.');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
