/* Exercise favorite and long intervals in an actual browser. */
const {chromium}=require('playwright');
const fs=require('fs'),path=require('path'),{spawnSync}=require('child_process');
const root=path.resolve(__dirname,'..');
const defaults=spawnSync(process.env.ATLAS_TEST_PYTHON||'python',['-c',"import json,sys;sys.path.insert(0,'root/usr/lib/atlas');import core;print(json.dumps(core.defaults()))"],{cwd:root,encoding:'utf8'});
if(defaults.status!==0)throw Error(defaults.stderr);
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.ATLAS_BROWSER||undefined});
 const page=await browser.newPage({viewport:{width:390,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 try{
  await page.setContent('<html lang="ru"><meta charset="utf-8"><style>body{margin:0}#modal{background:white;color:#111;position:fixed;inset:8px;overflow:auto;z-index:20;padding:12px}#modal:empty{display:none}</style><div id="app"></div><div id="modal"></div>');
  await page.addStyleTag({content:fs.readFileSync(path.join(root,'root/www/luci-static/resources/atlas/atlas.css'),'utf8')});
  await page.evaluate(({source,data})=>{
   const key='a'.repeat(32);
   window.state={...data,ok:true,running:false,engine:'fixture',subscriptions:[],nodes:[{key,name:'Сервер тест',server:'example.org',port:443,type:'vless',subscription:'Тест',eligible:true}],runtime:{available:false,measurements:{}},checks:{},job:{},privacy:{checks:[]},version:'fixture',engine_features:[]};
   const rpc={declare:({method})=>(...args)=>{if(method==='status')return Promise.resolve(structuredClone(state));if(method==='save_settings')state.settings=args[0];return Promise.resolve({ok:true});}};
   const E=(tag,attrs,children)=>{const e=document.createElement(tag);Object.entries(attrs||{}).forEach(([k,v])=>{if(typeof v==='function')e.addEventListener(k,v);else if(v!=null){if(k in e&&['value','checked','disabled','selected'].includes(k))e[k]=v;else e.setAttribute(k,String(v));}});const add=c=>{if(Array.isArray(c))c.forEach(add);else if(c!=null)e.append(c instanceof Node?c:document.createTextNode(String(c)));};add(children);return e;};
   const ui={showModal:(title,content)=>document.querySelector('#modal').replaceChildren(E('h2',{},title),...content),hideModal:()=>document.querySelector('#modal').replaceChildren(),addNotification(){}};
   window.app=new Function('view','rpc','poll','ui','L','E',source)({extend:x=>x},rpc,{add(){}},ui,{hasViewPermission:()=>true,resource:()=> 'data:text/css,'},E);
   app.tab='nodes';document.querySelector('#app').append(app.render(structuredClone(state)));app.navigate('nodes');
  },{source:fs.readFileSync(path.join(root,'root/www/luci-static/resources/view/atlas/overview.js'),'utf8'),data:JSON.parse(defaults.stdout)});
  await page.getByRole('button',{name:'☆ Любимый'}).click();
  await page.waitForFunction(()=>state.settings.favorite_profile==='a'.repeat(32));
  await page.locator('tr.favorite').getByText('Любимый',{exact:true}).waitFor();
  for(const width of [320,390,800,1440]){
   await page.setViewportSize({width,height:900});
   const bad=await page.locator('.at-profile-rows').evaluate(root=>Array.from(root.querySelectorAll('button')).filter(e=>{let a=e.getBoundingClientRect(),b=root.getBoundingClientRect();return a.width>0&&(a.left<b.left-2||a.right>b.right+2)}).length);
   if(bad)throw Error('Favorite control overflows at '+width);
  }
  await page.getByRole('button',{name:'Общие фильтры профилей'}).click();
  await page.locator('.at-auto-interval-unit').selectOption('60');await page.locator('.at-auto-interval').fill('90');
  await page.getByRole('button',{name:'Сохранить фильтры',exact:true}).click();
  await page.waitForFunction(()=>state.settings.auto_interval_seconds===5400);
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: favorite is saved and highlighted; 90 minutes saved as 5400 seconds; responsive controls');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
