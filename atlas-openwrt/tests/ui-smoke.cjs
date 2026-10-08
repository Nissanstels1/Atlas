/* LuCI view smoke test with mocked RPC. No router is required. */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
(async () => {
  const browser = await chromium.launch({headless:true,args:['--no-sandbox']});
  const page = await browser.newPage({ viewport: {width:1440,height:1100}, deviceScaleFactor:1 });
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.setContent('<html lang="ru"><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#e9edf3"><div style="font:12px system-ui;color:#607089;margin:0 0 12px">Atlas · демонстрационные данные интерфейса</div><div id="app"></div></body></html>');
  await page.addStyleTag({content:fs.readFileSync(path.join(root,'root/www/luci-static/resources/atlas/atlas.css'),'utf8')});
  await page.evaluate(source=>{
    const el=(tag,attrs={},children=[])=>{
      const n=document.createElement(tag);
      Object.entries(attrs).forEach(([k,v])=>{
        if(typeof v==='function')n.addEventListener(k,v);
        else if(v==null||v===false){}
        else if(k==='checked'||k==='disabled'||k==='selected')n[k]=v;
        else n.setAttribute(k,String(v));
      });
      const add=x=>{if(Array.isArray(x))x.forEach(add);else if(x!=null)n.appendChild(x instanceof Node?x:document.createTextNode(String(x)));};add(children);return n;
    };
    window.calls=[];
    let d={ok:true,version:'0.1.0',running:true,engine:'sing-box version 1.14.1',job:{},applied:{at:1789945200},
      settings:{mode:'rules',selected:'auto',domains:['example.com','example.net'],cidrs:['203.0.113.0/24'],bypass_domains:[],bypass_cidrs:[],interval_hours:12},
      subscriptions:[{id:'a'.repeat(16),name:'Основная подписка',host:'vpn.example.com',enabled:true,count:3,format:'Base64 URI',updated:1789981200,metadata:{download:43800000000,total:500000000000}},
                     {id:'b'.repeat(16),name:'Резервный канал',host:'backup.example.com',enabled:true,count:1,format:'sing-box JSON',updated:1789981200,metadata:{}}],
      nodes:['Амстердам','Франкфурт','Хельсинки','Варшава'].map((name,i)=>({name,key:String(i+1).repeat(32),type:'vless',subscription:i===3?'Резервный канал':'Основная подписка',server:'node-'+i+'.example.com',port:443})),checks:{}};
    d.nodes.slice(0,3).forEach((n,i)=>d.checks[n.key]={ok:true,latency_ms:42+i*14,checked:1789981200});
    window.data=d;
    const rpc={declare:({method,params})=>(...args)=>{window.calls.push({method,args});
      if(method==='status')return Promise.resolve(structuredClone(d));
      if(method==='save_settings')d.settings=args[0];
      if(method==='save_subscription'){
        let [id,name,url,enabled]=args;
        if(!name||(!id&&!url.startsWith('https://')))return Promise.resolve({ok:false,error:'Нужен HTTPS URL'});
        if(id)Object.assign(d.subscriptions.find(s=>s.id===id),{name,enabled});
        else d.subscriptions.push({id:'c'.repeat(16),name,enabled,count:0,host:new URL(url).hostname,metadata:{}});
      }
      if(method==='delete_subscription')d.subscriptions=d.subscriptions.filter(s=>s.id!==args[0]);
      if(method==='action')d.job={id:'testjob',status:'done',message:'Готово'};
      return Promise.resolve({ok:true});}};
    const ui={addNotification:()=>{},hideModal:()=>document.querySelector('#modal')?.remove(),showModal:(title,children)=>{ui.hideModal();let modal=el('div',{id:'modal',style:'position:fixed;top:10%;left:25%;width:50%;padding:30px;background:#202632;color:white;border:1px solid #888;z-index:10'},[el('h2',{},title),children]);document.body.appendChild(modal);}};
    const view={extend:x=>x},poll={add:f=>window.poll=f},L={hasViewPermission:()=>true,resource:()=> 'data:text/css,'};
    const app=new Function('view','rpc','poll','ui','L','E',source)(view,rpc,poll,ui,L,el);
    window.app=app;app.load().then(d=>document.querySelector('#app').appendChild(app.render(d)));
  },fs.readFileSync(path.join(root,'root/www/luci-static/resources/view/atlas/overview.js'),'utf8'));
  await page.getByRole('heading',{name:'Всё идёт своим путём.'}).waitFor();
  await page.screenshot({path:path.join(root,'docs/interface-demo.png'),fullPage:true});
  await page.getByRole('button',{name:'▤ Подписки',exact:false}).click();
  await page.getByRole('button',{name:'+ Подписка',exact:true}).click();
  await page.getByPlaceholder('Например, основная подписка').fill('Тестовая подписка');
  await page.locator('#modal input[type=password]').fill('https://new.example.com/sub/test');
  await page.locator('#modal').getByRole('button',{name:'Сохранить',exact:true}).click();
  await page.getByText('Тестовая подписка',{exact:true}).waitFor();
  await page.getByRole('button',{name:'◎ Серверы',exact:false}).click();
  await page.getByLabel('Поиск сервера').fill('Франкфурт');
  if(await page.locator('tbody tr').count()!==1)throw Error('Search did not filter nodes');
  await page.getByRole('button',{name:'Выбрать',exact:true}).click();
  await page.getByRole('button',{name:'Выбран',exact:true}).waitFor();
  await page.getByRole('button',{name:'⇄ Маршрутизация',exact:false}).click();
  await page.locator('textarea').first().fill('new.example.org\nvideo.example.com');
  await page.getByRole('button',{name:'Сохранить правила'}).click();
  const domains=await page.evaluate(()=>window.data.settings.domains);
  if(domains.join(',')!=='new.example.org,video.example.com')throw Error('Rules not saved');
  await page.getByRole('button',{name:'⚙ Настройки',exact:false}).click();
  await page.locator('input[type=number]').fill('24');
  await page.getByRole('button',{name:'Сохранить',exact:true}).click();
  if(await page.evaluate(()=>window.data.settings.interval_hours)!==24)throw Error('Interval not saved');
  await page.getByRole('button',{name:'◈ Обзор',exact:false}).click();
  await page.getByRole('button',{name:'Применить изменения'}).click();
  const actions=await page.evaluate(()=>window.calls.filter(c=>c.method==='action'));
  if(!actions.some(c=>c.args[0]==='apply'))throw Error('Apply RPC not invoked');
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(root,'docs/interface-mobile-demo.png'),fullPage:true});
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);
  if(overflow)throw Error('Mobile horizontal overflow');
  await page.evaluate(()=>{window.data.subscriptions[0].name='<img src=x onerror="window.XSS=true">';window.app.data=window.data;window.app.draw();});
  if(await page.evaluate(()=>!!window.XSS))throw Error('HTML injection');
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: desktop/mobile rendering, add subscription, node search/selection, rule save, interval save, apply RPC, HTML escaping.');
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
