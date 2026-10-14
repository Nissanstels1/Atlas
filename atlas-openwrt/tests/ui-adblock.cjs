const fs=require('fs'),path=require('path'),assert=require('assert/strict');
class N{
 constructor(tag,text=''){this.tag=tag;this.data=text;this.children=[];this.attributes={};this.listeners={};this.value='';this.checked=false;}
 appendChild(c){this.children.push(c);return c;} replaceChildren(...c){this.children=c;}
 setAttribute(k,v){this.attributes[k]=String(v);if(k==='value')this.value=v;if(k==='type')this.type=v;if(['checked','selected','disabled'].includes(k))this[k]=true;}
 addEventListener(k,v){this.listeners[k]=v;} querySelectorAll(tag){return this.children.flatMap(c=>[...(c.tag===tag?[c]:[]),...c.querySelectorAll(tag)]);}
 get textContent(){return this.data+this.children.map(c=>c.textContent||'').join('');}set textContent(v){this.data=v;this.children=[];}
}
global.document={createTextNode:t=>new N('#text',String(t)),createElement:t=>new N(t)};
function E(tag,attrs={},children=[]){const n=new N(tag);for(const[k,v]of Object.entries(attrs)){if(typeof v==='function')n.listeners[k]=v;else if(v!=null)n.setAttribute(k,v);}const add=c=>{if(c!=null)n.appendChild(c instanceof N?c:new N('#text',String(c)));};(Array.isArray(children)?children:[children]).forEach(add);if(tag==='select')n.value=(n.children.find(c=>c.selected)||n.children[0])?.attributes.value||'';return n;}
let modal,calls=[];
const settings={dns_filter:'cloudflare',selected:'auto',sections:[],remote_lists:[
 {id:'a'.repeat(16),name:'Peter',url:'https://pgl.yoyo.org/[saved]',policy:'dnsblock',enabled:true,adblock_preset:'peter'},
 {id:'b'.repeat(16),name:'Old duplicate',url:'https://pgl.yoyo.org/[saved]',policy:'dnsblock',enabled:true,adblock_preset:'peter'},
 {id:'c'.repeat(16),name:'My unrelated filter',url:'https://pgl.yoyo.org/[saved]',policy:'dnsblock',enabled:true},
 {id:'d'.repeat(16),name:'Section filter',url:'https://pgl.yoyo.org/[saved]',policy:'dnsblock',section:'e'.repeat(16),enabled:true,adblock_preset:'peter'}
]};
const data={ok:true,settings,job:{},subscriptions:[],nodes:[],privacy:{checks:[]}};
const rpc={declare:({method})=>(...args)=>{calls.push({method,args});return Promise.resolve(method==='status'?data:{ok:true});}};
const ui={showModal(title,children){modal=E('div',{},children);},hideModal(){modal=null;},addNotification(){}};
const source=fs.readFileSync(path.join(__dirname,'../root/www/luci-static/resources/view/atlas/overview.js'),'utf8');
const app=new Function('view','rpc','poll','ui','L','E',source)({extend:x=>x},rpc,{},ui,{hasViewPermission:()=>true},E);
app.data=data;app.reload=()=>Promise.resolve();app.wizardWait=()=>Promise.resolve();
const all=n=>[n,...n.children.flatMap(all)];
async function press(title){let button=all(modal).find(n=>n.tag==='button'&&n.textContent===title);assert(button,title);await button.listeners.click({currentTarget:button});await new Promise(r=>setTimeout(r,0));}
function saved(){return calls.filter(x=>x.method==='save_settings').at(-1).args[0];}
(async()=>{
 app.adblockDialog();assert(all(modal).find(n=>(n.attributes.class||'').includes('at-adblock-preset')).checked,'Saved filter was not recognized');
 await press('Сохранить без применения');let s=saved();assert.equal(s.remote_lists.length,4);assert(s.remote_lists[0].enabled);assert(!s.remote_lists[1].enabled);assert(s.remote_lists[2].enabled&&s.remote_lists[3].enabled);
 assert(!calls.some(x=>x.method==='action'),'Save-only unexpectedly applied network changes');
 app.data.settings=s;app.adblockDialog();await press('Включить Peter Lowe');s=saved();assert.equal(s.remote_lists.length,4);assert.equal(s.remote_lists.filter(x=>x.adblock_preset==='peter'&&!x.section&&x.enabled).length,1);
 app.data.settings=s;app.adblockDialog();await press('Выключить готовые фильтры');s=saved();assert(!s.remote_lists[0].enabled&&!s.remote_lists[1].enabled);assert(s.remote_lists[2].enabled&&s.remote_lists[3].enabled);
 const helpers=new Function(source.slice(source.indexOf('function atlasElement'),source.indexOf('return view.extend({'))+'return {atlasRouteName};')();
 const d={settings:{sections:[{id:'s',name:'Видео'}]},nodes:[{key:'node',name:'Estonia'}],subscriptions:[{id:'sub',name:'Provider'}]};
 assert.equal(helpers.atlasRouteName('direct',d),'Напрямую');assert.equal(helpers.atlasRouteName('node',d),'Estonia');assert.equal(helpers.atlasRouteName('pool_sub',d),'Подписка: Provider');assert.equal(helpers.atlasRouteName('section_s_auto',d),'Секция: Видео');assert.equal(helpers.atlasRouteName('unknown',d),'unknown');
 app.data=d;app.monitor={available:true,connections:[{host:'fixture.example',source:'192.0.2.1',network:'tcp',chains:['node','pool_sub','direct'],upload:10,download:20}],rules:[],memory:{}};
 const monitor=app.monitorPage();assert(monitor.textContent.includes('Estonia → Подписка: Provider → Напрямую'),'Populated live monitor did not render readable routes');
 console.log('PASS: masked presets reopen correctly; repeated enable creates no copies; disable preserves unrelated and section filters; save-only applies nothing; populated monitor renders verified route names.');
})().catch(e=>{console.error(e);process.exit(1)});
