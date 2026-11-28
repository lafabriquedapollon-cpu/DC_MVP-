import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';
import path from 'node:path';
assert.equal(process.env.GITHUB_ACTIONS,'true');
const require=createRequire(path.join(process.env.DC_BROWSER_TOOLS,'package.json'));
const {chromium}=require('playwright-core');
const bundle=fs.readFileSync(path.join(process.env.DC_LAB,'bundle.js'));
const server=http.createServer((req,res)=>{
 if(req.url==='/bundle.js'){res.writeHead(200,{'Content-Type':'application/javascript'});res.end(bundle);}
 else{res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><html><head><style>:root{--primary:#2563eb;--card-bg:#ffffff;--bg-medical-pearl:#f8fafc}</style></head><body><script src="/bundle.js"></script></body></html>');}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let browser;const rows=[];
try{
 browser=await chromium.launch({executablePath:process.env.DC_CHROME,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const context=await browser.newContext();
 const page=await context.newPage();
 await page.goto('http://127.0.0.1:'+server.address().port);
 await page.waitForFunction(()=>!!window.DCTheme);
 const result=await page.evaluate(()=>{
  const a=window.DCTheme;const out=[];
  const run=(label,fn)=>{try{if(!fn())throw Error('assertion');out.push({label,pass:true})}catch(e){out.push({label,pass:false,error:e.name})}};
  const root=document.documentElement;
  const prop=n=>root.style.getPropertyValue(n);
  const identity={api_base_url:'https://cabinet-a.invalid:8005',publicId:'synthetic-a',device_id:'device-a'};
  const key=a.mobileThemeCacheKey(identity);
  const other=a.mobileThemeCacheKey({...identity,publicId:'synthetic-b'});
  const device=a.mobileThemeCacheKey({...identity,device_id:'device-b'});
  const origin=a.mobileThemeCacheKey({...identity,api_base_url:'https://cabinet-b.invalid:8005'});
  run('mobile cache key distinguishes identity device and origin',()=>new Set([key,other,device,origin]).size===4);
  run('Desktop authorized projection applies tokens',()=>{a.applyRuntimeTheme({selected_theme:'rose',primary_color:'#cc3344'},true);return root.dataset.theme==='rose'&&prop('--primary')==='#cc3344'&&localStorage.getItem('digitalcrown_theme')==='rose'});
  run('Desktop fallback removes previous custom tokens',()=>{a.applyRuntimeTheme(null);return root.dataset.theme===''&&!prop('--primary')});
  run('Desktop rejects malformed color and unknown palette',()=>{a.applyRuntimeTheme({selected_theme:'not-a-theme',primary_color:'url(example.invalid)'});return root.dataset.theme===''&&!prop('--primary')});
  run('Mobile cabinet A cache survives scoped save',()=>{a.applyMobileRuntimeTheme({selected_theme:'rose',primary_color:'#cc3344'},key);return JSON.parse(localStorage.getItem(key)).primary_color==='#cc3344'&&localStorage.getItem(other)===null});
  run('Mobile cabinet B cache is distinct',()=>{a.applyMobileRuntimeTheme({selected_theme:'ocean',primary_color:'#223344'},other);return JSON.parse(localStorage.getItem(key)).primary_color==='#cc3344'&&JSON.parse(localStorage.getItem(other)).primary_color==='#223344'&&prop('--primary')==='#223344'});
  run('Mobile bootstrap removes prior cabinet palette',()=>{a.bootstrapMobileRuntimeTheme();return root.dataset.theme===''&&!prop('--primary')});
  run('Mobile does not overwrite Desktop legacy preference',()=>localStorage.getItem('digitalcrown_theme')==='rose');
  const lum=h=>[1,3,5].map(i=>parseInt(h.slice(i,i+2),16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
  const ratio=(x,y)=>(Math.max(lum(x),lum(y))+.05)/(Math.min(lum(x),lum(y))+.05);
  for(const color of ['#777777','#808080','#0080ff','#ffffff','#000000','#ff0099']){
    run('Desktop foreground contrast '+color,()=>{a.applyRuntimeTheme({primary_color:color});return ratio(color,prop('--text-on-primary'))>=4.5});
    run('Mobile foreground contrast '+color,()=>ratio(color,a.textColorForHex(color))>=4.5);
  }
  return out;
 });
 rows.push(...result);for(const row of rows)console.log('LOT01_D_CASE '+JSON.stringify(row));
 await context.close();
}finally{
 if(browser)await browser.close();
 await new Promise(resolve=>server.close(resolve));
 fs.writeFileSync(path.join(process.env.DC_EVIDENCE,'theme.json'),JSON.stringify(rows,null,2));
}
assert.equal(rows.length,20);
assert(rows.every(r=>r.pass),'theme contract failure');
