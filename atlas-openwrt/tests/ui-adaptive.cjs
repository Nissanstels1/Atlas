/* Browser checks for the adaptive routing controls against a fake RPC. */
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),{spawnSync}=require('child_process');
const root=path.resolve(__dirname,'..');
const defaults=spawnSync(process.env.ATLAS_TEST_PYTHON||'python',['-c',"import json,sys;sys.path.insert(0,'root/usr/lib/atlas');import core;s=core.defaults();s['settings']['sections']=[dict(id='a'*16,name='Видео',policy='proxy',domains=['example.org'],cidrs=[],source_ips=[],pools=[])];s['settings']=core.validate_settings(s['settings']);print(json.dumps(s))"],{cwd:root,encoding:'utf8'});
if(defaults.status!==0)throw Error(defaults.stderr);
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.ATLAS_BROWSER||undefined});
 const page=await browser.newPage({viewport:{width:390,height:900}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(7000);
 try{
  await page.setContent('<html lang="ru"><meta charset="utf-8"><style>body{margin:0;padding:8px}#modal{background:#fff;color:#111;padding:14px;position:fixed;inset:10px;overflow:auto;z-index:20}#modal:empty{display:none}button,input,textarea,select{font:inherit}</style><div id="app"></div><div id="modal"></div>');
  await page.addStyleTag({content:fs.readFileSync(path.join(root,'root/www/luci-static/resources/atlas/atlas.css'),'utf8')});
  await page.evaluate(({source,data})=>{
   window.calls=[];window.entries=['blocked.example.com'];
   window.state={...data,ok:true,running:false,engine:'fixture',subscriptions:[],nodes:[],runtime:{available:true,measurements:{}},checks:{},job:{},privacy:{checks:[]},version:'fixture',engine_features:[],adaptive_proxy:{active:true,healthy:true,count:1}};
   const rpc={declare:({method})=>(...args)=>{
    calls.push({method,args});
    if(method==='status')return Promise.resolve(structuredClone(state));
    if(method==='adaptive_list')return Promise.resolve({ok:true,active:true,healthy:true,domains:[...entries]});
    if(method==='adaptive_settings'){state.settings.adaptive_proxy_enabled=args[0];state.settings.adaptive_proxy_section=args[1];return Promise.resolve({ok:true});}
    if(method==='adaptive_rule'){entries=entries.filter(h=>h!==args[1]);state.adaptive_proxy.count=entries.length;return Promise.resolve({ok:true});}
    if(method==='connection_rule'){state.settings.sections.find(s=>s.id===args[1]).connection_rules.push({...args[3],id:'b'.repeat(16)});return Promise.resolve({ok:true});}
    return Promise.resolve({ok:true});
   }};
   const E=(tag,attrs,children)=>{const e=document.createElement(tag);Object.entries(attrs||{}).forEach(([k,v])=>{if(typeof v==='function')e.addEventListener(k,v);else if(v!=null){if(k in e&&['value','checked','disabled','selected'].includes(k))e[k]=v;else e.setAttribute(k,String(v));}});const add=c=>{if(Array.isArray(c))c.forEach(add);else if(c!=null)e.append(c instanceof Node?c:document.createTextNode(String(c)));};add(children);return e;};
   const ui={showModal:(title,content)=>{document.querySelector('#modal').replaceChildren(E('h2',{},title),...content);},hideModal:()=>document.querySelector('#modal').replaceChildren(),addNotification(){}};
   window.app=new Function('view','rpc','poll','ui','L','E',source)({extend:x=>x},rpc,{add(){}},ui,{hasViewPermission:()=>true,resource:()=> 'data:text/css,'},E);
   app.tab='routing';document.querySelector('#app').append(app.render(structuredClone(state)));app.navigate('routing');
  },{source:fs.readFileSync(path.join(root,'root/www/luci-static/resources/view/atlas/overview.js'),'utf8'),data:JSON.parse(defaults.stdout)});
  await page.locator('.at-adaptive-card').getByRole('button',{name:'Настроить'}).click();
  await page.getByText('blocked.example.com',{exact:true}).waitFor();
  for(const width of [320,390,800,1440]){
   await page.setViewportSize({width,height:900});
   const bad=await page.locator('#modal').evaluate(root=>Array.from(root.querySelectorAll('input,select,textarea,button')).filter(e=>{const a=e.getBoundingClientRect(),b=root.getBoundingClientRect();return a.width>0&&(a.left<b.left-1||a.right>b.right+1)}).length);
   if(bad)throw Error('Controls overflow at '+width);
  }
  await page.locator('#modal select').selectOption('a'.repeat(16));
  await page.locator('#modal').getByRole('button',{name:'В секцию',exact:true}).click();
  await page.getByText('Добавлено в секцию. Примените изменения для постоянного правила.',{exact:true}).waitFor();
  if(!await page.evaluate(()=>state.settings.sections[0].connection_rules.some(r=>r.domains.includes('blocked.example.com'))))throw Error('Site was not saved to selected section');
  await page.getByRole('button',{name:'Убрать',exact:true}).click();
  await page.getByText('Пока нет адресов.',{exact:true}).waitFor();
  await page.getByRole('checkbox',{name:/Пробовать через прокси/}).check();
  await page.locator('#modal select').selectOption('a'.repeat(16));
  await page.locator('#modal').getByRole('button',{name:'Сохранить и применить'}).click();
  await page.waitForFunction(()=>state.settings.adaptive_proxy_enabled&&state.settings.adaptive_proxy_section==='a'.repeat(16));
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: adaptive list is private to explicit RPC; removal, section selection and responsive controls');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
