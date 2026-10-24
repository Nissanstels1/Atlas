/* Browser actions with mocked router RPC; source semantics have native Python tests. */
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),{spawnSync}=require('child_process');
const root=path.resolve(__dirname,'..');
const defaults=spawnSync(process.env.ATLAS_TEST_PYTHON||'python3',['-c',"import json,sys;sys.path.insert(0,'root/usr/lib/atlas');import core;s=core.defaults();s['settings']['sections']=[dict(id='a'*16,name='Видео',policy='proxy',domains=['manual.example.org'],cidrs=[],source_ips=[],pools=[]),dict(id='b'*16,name='Работа',policy='proxy',domains=['work.example.org'],cidrs=[],source_ips=[],pools=[])];s['settings']=core.validate_settings(s['settings']);print(json.dumps(s))"],{cwd:root,encoding:'utf8'});
if(defaults.status!==0)throw Error(defaults.stderr);
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.ATLAS_BROWSER||undefined});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
 page.setDefaultTimeout(7000);
 page.on('pageerror',e=>errors.push(e.message));
 try{
  await page.setContent('<html lang="ru"><meta charset="utf-8"><style>body{margin:0;padding:12px;background:#11141c;color:#eee}#modal{background:#1b1f2a;color:#eee;padding:14px;position:fixed;inset:10px;overflow:auto;z-index:20}#modal:empty{display:none}button,input,textarea,select{font:inherit}button{cursor:pointer}</style><div id="app"></div><div id="modal"></div>');
  await page.addStyleTag({content:fs.readFileSync(path.join(root,'root/www/luci-static/resources/atlas/atlas.css'),'utf8')});
  await page.evaluate(({source,data})=>{
   window.calls=[];window.fakeFailure=false;window.state={...data,ok:true,running:false,engine:'Atlas Engine fixture',subscriptions:[],nodes:[],runtime:{available:true,measurements:{}},checks:{},job:{},privacy:{checks:[]},version:'fixture',engine_features:[]};
   window.flow={id:'fixture-flow',host:'img.example.org',destination:'1.1.1.1',source:'192.168.1.20',network:'tcp',chains:['direct'],upload:1,download:2000};
   const rpc={declare:({method})=>(...args)=>{
    calls.push({method,args});
    if(method==='status')return Promise.resolve(structuredClone(state));
    if(method==='monitor')return Promise.resolve({ok:true,available:true,connections:[flow],rules:[]});
    if(method==='connection_rule'){
     const [operation,section,id,target]=args;
     if(operation==='preview')return Promise.resolve({ok:true,domain:flow.host,site:'example.org',cidr:'1.1.1.1/32',related:['other.example.net']});
     if(window.fakeFailure)return Promise.resolve({ok:false,error:'Проверочная ошибка; настройки сохранены'});
     state.settings.sections.forEach(s=>{s.connection_rules=(s.connection_rules||[]).filter(r=>r.id!==id);});
     if(operation==='save')state.settings.sections.find(s=>s.id===section).connection_rules.push({...structuredClone(target),id:id||'c'.repeat(16)});
     return Promise.resolve({ok:true,id:id||'c'.repeat(16)});
    }
    if(method==='section_details')return Promise.resolve({ok:true,outbound_config:[]});
    return Promise.resolve({ok:true});
   }};
   const E=(tag,attrs,children)=>{const e=document.createElement(tag);Object.entries(attrs||{}).forEach(([k,v])=>{if(typeof v==='function')e.addEventListener(k,v);else if(v!=null){if(k in e&&['value','checked','disabled','selected'].includes(k))e[k]=v;else e.setAttribute(k,String(v));}});const add=c=>{if(Array.isArray(c))c.forEach(add);else if(c!=null)e.append(c instanceof Node?c:document.createTextNode(String(c)));};add(children);return e;};
   const ui={showModal:(title,content)=>{const m=document.querySelector('#modal');m.replaceChildren(E('h2',{},title),...content);},hideModal:()=>document.querySelector('#modal').replaceChildren(),addNotification(){}};
   window.app=new Function('view','rpc','poll','ui','L','E',source)({extend:x=>x},rpc,{add(){}},ui,{hasViewPermission:()=>true,resource:()=> 'data:text/css,'},E);
   app.tab='monitor';app.monitor={available:true,connections:[flow],rules:[]};
   document.querySelector('#app').append(app.render(structuredClone(state)));
   app.monitor={available:true,connections:[flow],rules:[]};app.navigate('monitor');
  },{source:fs.readFileSync(path.join(root,'root/www/luci-static/resources/view/atlas/overview.js'),'utf8'),data:JSON.parse(defaults.stdout)});
  await page.locator('summary[aria-label="Активные соединения"]').click();
  await page.getByRole('button',{name:'В секцию',exact:true}).click();
  await page.locator('.at-connection-domains').waitFor();
  if(await page.locator('.at-connection-domains').inputValue()!=='example.org')throw Error('Site and subdomains not suggested');
  if(await page.locator('.at-connection-ips').inputValue()!=='')throw Error('Shared IP silently enabled');
  await page.getByRole('checkbox',{name:/Добавить IP/}).check();
  await page.locator('.at-connection-section').selectOption('b'.repeat(16));
  await page.getByRole('button',{name:'Сохранить',exact:true}).click();
  await page.waitForFunction(()=>state.settings.sections[1].connection_rules.length===1);
  await page.evaluate(()=>app.sectionDialog(app.data.settings.sections[1],value=>window.sectionDraft=value));
  await page.locator('.at-section-connection-rules > summary').click();
  await page.locator('.at-section-connection-rules').getByRole('textbox',{name:'Домены и поддомены',exact:true}).fill('example.org\nmedia.example.net');
  await page.getByRole('button',{name:'Добавить в форму',exact:true}).click();
  if(!await page.evaluate(()=>sectionDraft.connection_rules[0].domains.includes('media.example.net')&&sectionDraft.domains.includes('work.example.org')))throw Error('Section editor did not preserve owned/manual addresses');
  await page.getByRole('button',{name:'Правило',exact:true}).click();
  await page.locator('.at-connection-domains').fill('example.org\nassets.example.net');
  await page.locator('.at-connection-section').selectOption('a'.repeat(16));
  await page.getByRole('button',{name:'Сохранить',exact:true}).click();
  await page.waitForFunction(()=>state.settings.sections[0].connection_rules.length===1&&state.settings.sections[1].connection_rules.length===0);
  await page.evaluate(()=>{app.monitor.connections=[];app.draw();});
  await page.locator('summary[aria-label="Добавлено из соединений"]').click();
  await page.getByRole('button',{name:'Изменить',exact:true}).click();
  for(const width of [320,390,800,1440]){
   await page.setViewportSize({width,height:1000});
   const bad=await page.locator('#modal').evaluate(root=>Array.from(root.querySelectorAll('input,select,textarea,button')).filter(e=>{const a=e.getBoundingClientRect(),b=root.getBoundingClientRect();return a.width>0&&(a.left<b.left-1||a.right>b.right+1)}).map(e=>e.className));
   if(bad.length)throw Error(JSON.stringify({width,bad}));
  }
  await page.getByRole('button',{name:'Отмена',exact:true}).click();
  await page.getByRole('button',{name:'Убрать',exact:true}).click();
  await page.getByRole('button',{name:'Убрать',exact:true}).last().click();
  await page.waitForFunction(()=>state.settings.sections[0].connection_rules.length===0);
  if(!await page.evaluate(()=>state.settings.sections[0].domains.includes('manual.example.org')))throw Error('Manual rule removed');
  await page.evaluate(()=>{app.monitor.connections=[flow];app.draw();});
  await page.getByRole('button',{name:'В секцию',exact:true}).click();
  await page.evaluate(()=>window.fakeFailure=true);
  await page.getByRole('button',{name:'Сохранить',exact:true}).click();
  await page.getByText('Проверочная ошибка; настройки сохранены',{exact:true}).waitFor();
  if(!await page.getByRole('button',{name:'Сохранить',exact:true}).isEnabled())throw Error('Cannot retry after failure');
  await page.evaluate(()=>window.fakeFailure=false);
  await page.getByRole('button',{name:'Отмена',exact:true}).click();
  await page.evaluate(()=>{state.running=true;app.data=structuredClone(state);app.draw();});
  await page.getByRole('button',{name:'В секцию',exact:true}).click();
  await page.getByRole('button',{name:'Сохранить и применить',exact:true}).click();
  await page.waitForFunction(()=>calls.some(c=>c.method==='action'&&c.args[0]==='apply'));
  await page.evaluate(()=>{app.monitor={available:true,connections:[flow],rules:[]};app.draw();});
  await page.setViewportSize({width:390,height:900});
  await page.screenshot({path:path.join(process.env.ATLAS_TEST_OUTPUT||root,'monitor-routing-demo.png'),fullPage:true});
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: site/subdomain choice, opt-in IP, save, edit/move, persistent management, removal, manual data, retry and explicit apply; modal widths 320–1440. Router RPC mocked.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
