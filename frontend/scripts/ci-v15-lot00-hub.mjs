// CI-only real Chromium + local API; no auth storage injection or request mocks.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { certifyCompanionVault } from './ci-r02-vault.mjs';
import {setTimeout as sleep} from 'node:timers/promises';
const base = 'http://127.0.0.1:8008';
const packaged = process.env.DC_PACKAGED_DESKTOP === 'true';
const web = packaged ? base : 'http://127.0.0.1:5173';
const evidence = process.env.DC_EVIDENCE;
const password = process.env.DC_SYNTH_PASSWORD;
assert(process.env.GITHUB_ACTIONS === 'true' && password && evidence);
const wait = async (label, fn, ms=60000) => {
  const end=Date.now()+ms;
  while(Date.now()<end) {
    try { const value=await fn(); if(value) return value; } catch {}
    await sleep(500);
  }
  throw new Error(label+' timeout');
};
const restart=process.argv.includes('--verify-restart');
let ws;
if(packaged){
  const session=globalThis.__dcDesktopCDP;
  assert(session && typeof session.send==='function','PACKAGED_PIPE_SESSION_REQUIRED');
  // Adapt the already qualified CDP driver to a private Playwright pipe.
  const listeners=new Set();
  const events=['Network.requestWillBeSent','Network.loadingFailed','Network.responseReceived'];
  for(const method of events)session.on(method,params=>{
    for(const listener of listeners)listener({data:JSON.stringify({method,params})});
  });
  ws={
    addEventListener(type,listener){if(type==='message')listeners.add(listener)},
    send(raw){
      const {id,method,params}=JSON.parse(raw);
      session.send(method,params).then(result=>{
        for(const listener of listeners)listener({data:JSON.stringify({id,result})});
      },()=>{
        for(const listener of listeners)listener({data:JSON.stringify({id,error:{code:-1}})});
      });
    },
    close(){listeners.clear()}
  };
  console.log('R02_DESKTOP_CDP_PIPE_ATTACH_PASS');
}else{
  const target=await wait('CDP',async()=>{
    const list=await (await fetch('http://127.0.0.1:9222/json/list')).json();
    return list.find(t=>t.type==='page' && t.url.startsWith(web));
  });
  ws=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
}
let seq=0;
const pending=new Map(), requests=new Map(), responses=[];
ws.addEventListener('message',e=>{
  const m=JSON.parse(e.data);
  if(m.id && pending.has(m.id)){
    const p=pending.get(m.id);pending.delete(m.id);
    if(m.error)p.reject(new Error('CDP '+m.error.code));else p.resolve(m.result);
  }
  if(m.method==='Network.requestWillBeSent') requests.set(m.params.requestId,m.params.request.method);
  if(m.method==='Network.loadingFailed'){
    const failure=m.params;
    if(failure.corsErrorStatus) console.log('BROWSER_CORS_FAILURE',failure.corsErrorStatus.corsError);
  }
  if(m.method==='Network.responseReceived'){
    const r=m.params.response;
    if(r.url.startsWith(base+'/api/')) responses.push({path:new URL(r.url).pathname,status:r.status,method:requests.get(m.params.requestId),fromServiceWorker:r.fromServiceWorker===true});
  }
});
const call=(method,params={})=>new Promise((resolve,reject)=>{
  const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));
});
const evalPage=async expression=>{
  const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails) throw new Error('Page evaluation failed: '+(r.exceptionDetails.exception?.className||'unknown'));
  return r.result.value;
};
// Only on the compiled R0.2 rehearsal, never on the historical dev-server run.
const pwaRehearsal=process.env.DC_BUILT_REHEARSAL==='true';
const pwaState=()=>evalPage(`(async()=>{
  const registrations=await navigator.serviceWorker.getRegistrations();
  const registration=await navigator.serviceWorker.getRegistration();
  const names=await caches.keys();
  let entries=0, apiEntries=0, foreignEntries=0;
  for(const name of names){
    for(const request of await (await caches.open(name)).keys()){
      const url=new URL(request.url);
      entries++;
      if(url.pathname==='/api'||url.pathname.startsWith('/api/'))apiEntries++;
      if(url.origin!==location.origin)foreignEntries++;
    }
  }
  return {secure:isSecureContext,active:registration?.active?.state==='activated',
    script:registration?.active?.scriptURL,scope:registration?.scope,
    controller:navigator.serviceWorker.controller?.scriptURL,entries,apiEntries,foreignEntries,
    legacy:names.includes('dc-mobile-v10')||registrations.some(r=>[r.active,r.waiting,r.installing].some(w=>w&&new URL(w.scriptURL).pathname==='/sw.js'))};
})()`);
const assertPwa=async({controlled=false}={})=>{
  if(!pwaRehearsal)return;
  const state=await wait('actual PWA registration and precache',async()=>{
    const s=await pwaState();
    return s.secure&&s.active&&s.entries>0&&(!controlled||s.controller===web+'/pwa-sw.js')?s:false;
  });
  assert.equal(state.script,web+'/pwa-sw.js');
  assert.equal(state.scope,web+'/');
  assert.equal(state.apiEntries,0);
  assert.equal(state.foreignEntries,0);
  assert.equal(state.legacy,false);
  console.log('PWA_BROWSER_ACTIVE_STATIC_ONLY_PASS',JSON.stringify({controlled,entries:state.entries,apiEntries:state.apiEntries,foreignEntries:state.foreignEntries}));
};
const capture=async name=>{
  const r=await call('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync(evidence+'/'+name+'.png',Buffer.from(r.data,'base64'));
};
const visible=q=>evalPage('(()=>{const e=document.querySelector('+JSON.stringify(q)+');return !!e && !!e.getClientRects().length})()');
const setField=async(q,v)=>{
  const ok=await evalPage('(()=>{const e=document.querySelector('+JSON.stringify(q)+');if(!e)return false;const p=e.tagName==="SELECT"?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(p,"value").set.call(e,'+JSON.stringify(v)+');e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return e.value==='+JSON.stringify(v)+'})()');
  assert(ok,'Field not set: '+q);
};
const clickSubmit=()=>evalPage('(()=>{const b=document.querySelector("form button[type=submit]");if(!b||b.disabled)return false;b.click();return true})()');
const pagePath=()=>evalPage('location.pathname');
const api=async(path,options={})=>{
  const r=await fetch(base+path,options);return {status:r.status,body:await r.json().catch(()=>null),cookies:r.headers.getSetCookie()};
};
const login=async email=>{
  const r=await api('/api/auth/login',{method:'POST',body:new URLSearchParams({username:email,password})});
  assert.equal(r.status,200);assert(r.body?.access_token&&r.body?.refresh_token);return r.body;
};
const bearer=t=>({Authorization:'Bearer '+t});
const workstationCookie=async()=>{
  const result=await call('Network.getCookies',{urls:[base]});
  const cookie=result.cookies.find(c=>c.name==='dc_workstation');
  assert(Boolean(cookie?.httpOnly && cookie.value),'Server workstation cookie missing');
  return 'dc_workstation='+cookie.value;
};
const withWorkstation=(token,cookie)=>({...bearer(token),Cookie:cookie});
const denied=async(path,headers,status,detail,label)=>{
  const r=await api(path,{headers});
  assert.equal(r.status,status,label);
  if(detail) assert.equal(r.body?.detail,detail,label+' reason');
};
const verifyIdentity=()=>evalPage('Boolean(document.body && document.body.innerText.toUpperCase().includes("CI-SYNTHETIC") && document.body.innerText.toUpperCase().includes("FIXTURE"))');

const go=async(path)=>{const r=await call('Page.navigate',{url:web+path});assert(!r.errorText);};
const pathIs=async(path)=>{try{await wait('route '+path,async()=>await pagePath()===path)}catch(e){console.log('LOT00_ROUTE_MISMATCH expected='+path+' actual='+String(await pagePath()).split('?')[0]);await capture('route-mismatch-'+path.replace(/[^a-z]/gi,'-'));throw e}};
const shown=q=>wait('visible '+q,()=>visible(q));
const click=async q=>assert(await evalPage('(()=>{const e=document.querySelector('+JSON.stringify(q)+');if(!e||e.disabled)return false;e.click();return true})()'));
const browserAPI=async(path,method='GET',body)=>evalPage('(async()=>{const r=await fetch('+JSON.stringify(base+path)+',{credentials:"include",method:'+JSON.stringify(method)+',headers:{"Content-Type":"application/json"},body:'+JSON.stringify(body===undefined?undefined:JSON.stringify(body))+'});return {status:r.status,body:await r.json().catch(()=>null)}})()');
const captureIsolatedSurface=async name=>{
  await sleep(400);
  assert.equal(await evalPage('document.querySelector("[data-offline-queue-viewer]")===null'),true,'Staff queue overlay leaked into '+name);
  await capture(name);
  console.log('LOT00_SURFACE_QUEUE_ISOLATED '+name);
};
const hub='[data-v15-hub]';
const station='[data-workstation-experience="station"]';
const control='[data-workstation-experience="control-center"]';
const pin='483726';
const checkMode=async mode=>{const r=await browserAPI('/api/workstation/bootstrap');assert.equal(r.status,200);assert.equal(r.body.defaultExperience,mode);return r.body};
const mode=async value=>{const r=await browserAPI('/api/workstation/mode','POST',{mode:value,ownerPin:pin});assert.equal(r.status,200,'mode '+value);assert.equal(r.body.defaultExperience,value)};
try{
 await call('Network.enable');await call('Page.enable');
 if(process.argv.includes('--theme-restart')){
   // Same browser profile, same encrypted database, new backend process.
   const expected={selected_theme:'rose',primary_color:'#852b56',secondary_color:'#59384f',accent_color:'#b77845'};
   const matchesPersisted=()=>evalPage('(()=>{const p='+JSON.stringify(expected)+';return [document.documentElement,document.body].every(e=>{const s=getComputedStyle(e);return e.dataset.theme===p.selected_theme&&s.getPropertyValue("--primary").trim().toLowerCase()===p.primary_color&&s.getPropertyValue("--secondary").trim().toLowerCase()===p.secondary_color&&s.getPropertyValue("--accent").trim().toLowerCase()===p.accent_color})})()');
   await go('/hub?select=1');await shown(hub);await wait('persisted theme after restart',matchesPersisted);
   const before=await browserAPI('/api/workstation/bootstrap');assert.equal(before.status,200);assert(before.body.authenticated&&before.body.workstationId);assert.equal(before.body.defaultExperience,'cabinet');
   for(const k of Object.keys(expected))assert.equal(String(before.body.theme[k]).toLowerCase(),expected[k],k);
   await captureIsolatedSurface('10-theme-after-backend-restart');
   // Use actual keyboard traversal, not storage or CSS injection.
   const buttons=await evalPage('Array.from(document.querySelectorAll("[data-hub-experience]")).map(e=>({id:e.dataset.hubExperience,tag:e.tagName,name:e.innerText.trim().length,disabled:e.disabled,tabIndex:e.tabIndex}))');
   assert.equal(buttons.length,3);assert(buttons.every(b=>b.tag==='BUTTON'&&b.name>0&&!b.disabled&&b.tabIndex===0));
   await evalPage('document.activeElement.blur()');
   const reached=new Set();
   for(let i=0;i<30&&reached.size<3;i++){
     await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
     await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
     const id=await evalPage('document.activeElement?.dataset?.hubExperience||null');if(id)reached.add(id);
   }
   assert.deepEqual([...reached].sort(),['cabinet','control','station']);
   await captureIsolatedSurface('11-hub-keyboard-focus');
   console.log('LOT00_THEME_RESTART_KEYBOARD_PASS');
   await go('/dashboard');await pathIs('/dashboard');await shown('button[title="Déconnexion"]');
   await click('button[title="Déconnexion"]');
   await wait('logout confirmation',()=>evalPage('Array.from(document.querySelectorAll("button")).some(b=>b.innerText.trim()==="Confirmer"&&b.getClientRects().length)'));
   assert(await evalPage('(()=>{const b=Array.from(document.querySelectorAll("button")).find(b=>b.innerText.trim()==="Confirmer"&&b.getClientRects().length);if(!b)return false;b.click();return true})()'));
   await pathIs('/login');await shown('input[type=email]');
   const neutral=()=>evalPage('(()=>{return [document.documentElement,document.body].every(e=>{const s=getComputedStyle(e);return !e.dataset.theme&&s.getPropertyValue("--primary").trim()==="#003380"&&s.getPropertyValue("--secondary").trim()==="#1e40af"&&s.getPropertyValue("--accent").trim()==="#60a5fa"})})()');
   await wait('neutral after logout',neutral);
   await go('/hub?select=1');await shown(hub);await wait('neutral public hub',neutral);
   const anonymous=await browserAPI('/api/workstation/bootstrap');assert.equal(anonymous.status,200);assert.equal(anonymous.body.authenticated,false);assert.equal(anonymous.body.theme??null,null);
   assert.equal((await browserAPI('/api/clinics/me')).status,401);
   await captureIsolatedSurface('12-hub-after-logout-neutral');
   await click('[data-hub-experience="cabinet"]');await pathIs('/login');await shown('input[type=email]');
   await setField('input[type=email]','ci-other@example.com');await setField('input[type=password]',password);assert(await clickSubmit());
   await wait('second tenant login',()=>responses.some(r=>r.path==='/api/auth/login'&&r.status===200));
   await wait('second tenant workstation',async()=>{const r=await browserAPI('/api/workstation/bootstrap');return r.status===200&&r.body.authenticated&&r.body.workstationId&&r.body.workstationId!==before.body.workstationId});
   await go('/hub?select=1');await shown(hub);
   const other=await browserAPI('/api/workstation/bootstrap');assert.equal(other.status,200);assert.notEqual(other.body.workstationId,before.body.workstationId);assert(other.body.theme);
   assert.notEqual(String(other.body.theme.primary_color).toLowerCase(),expected.primary_color);
   await wait('second tenant projected tokens',()=>evalPage('(()=>{const p='+JSON.stringify(other.body.theme)+';return [document.documentElement,document.body].every(e=>{const s=getComputedStyle(e);return e.dataset.theme===(p.selected_theme==="elite"?"":p.selected_theme)&&(!p.primary_color||s.getPropertyValue("--primary").trim().toLowerCase()===p.primary_color.toLowerCase())&&(!p.secondary_color||s.getPropertyValue("--secondary").trim().toLowerCase()===p.secondary_color.toLowerCase())&&(!p.accent_color||s.getPropertyValue("--accent").trim().toLowerCase()===p.accent_color.toLowerCase())})})()'));
   await captureIsolatedSurface('13-hub-second-tenant');
   console.log('LOT00_THEME_LOGOUT_TENANT_SWITCH_PASS');
 }else if(process.argv.includes('--offline')){
   // Actual backend stopped by shell, frontend remains running. No network mocks.
   await assert.rejects(fetch(base+'/health',{signal:AbortSignal.timeout(2000)}));
   await go('/dashboard');await pathIs('/hub');await shown(hub);await shown('[data-hub-offline]');
   await captureIsolatedSurface('08-offline-hub');
   assert.equal(await visible('[data-workstation-experience="station"]'),false);
   await go('/setup');await pathIs('/hub');await shown(hub);await shown('[data-hub-offline]');
   await captureIsolatedSurface('08b-offline-setup-refused');
   console.log('LOT00_OFFLINE_SETUP_REFUSED_PASS');
   await click('[data-hub-experience="control"]');await pathIs('/control-center');await shown(control);
   await captureIsolatedSurface('09-offline-control');
   console.log('LOT00_REAL_OFFLINE_FAIL_CLOSED_PASS');
 }else{
   await go('/hub');await shown(hub);
   for(const id of ['cabinet','station','control'])await shown('[data-hub-experience="'+id+'"]');
   await wait('official Hub logo loaded',()=>evalPage('(()=>{const e=document.querySelector("[data-hub-brand-logo]");return !!e&&e.complete&&e.naturalWidth>0&&e.alt==="Digital Crown"})()'));
   const fresh=await browserAPI('/api/workstation/bootstrap');
   assert.equal(fresh.status,200);assert.equal(fresh.body.authenticated,false);assert.equal(fresh.body.workstationId,null);assert.equal(fresh.body.defaultExperience,null);assert.equal(fresh.body.theme??null,null);
   assert.equal(await evalPage('getComputedStyle(document.body).getPropertyValue("--primary").trim().toLowerCase()'),'#003380');
   assert.equal((await api('/api/patients/')).status,401);
   await captureIsolatedSurface('01-fresh-hub-1440');
   // Original PNG: 677x369, visible alpha bounding box 354x194.
   const responsiveHub=async(width,height,name)=>{
     await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
     await sleep(300);
     const layout=await evalPage('(()=>{const img=document.querySelector("[data-hub-brand-logo]");const r=img.getBoundingClientRect();const cards=Array.from(document.querySelectorAll("[data-hub-experience]"));return {width:innerWidth,scrollWidth:document.documentElement.scrollWidth,logoWidth:r.width*354/677,logoHeight:r.height*194/369,logoNaturalWidth:img.naturalWidth,logoNaturalHeight:img.naturalHeight,cards:cards.map(e=>{const r=e.getBoundingClientRect();return {w:r.width,h:r.height,left:r.left,right:r.right}})}})()');
     assert.equal(layout.width,width);assert(layout.scrollWidth<=width+1,'document overflow '+width);
     assert.equal(layout.logoNaturalWidth,677);assert.equal(layout.logoNaturalHeight,369);
     assert(layout.logoWidth>=140&&layout.logoHeight>=75,'visible logo too small '+width);
     assert.equal(layout.cards.length,3);assert(layout.cards.every(c=>c.w>=44&&c.h>=44&&c.left>=0&&c.right<=width+1),'card clipping '+width);
     await captureIsolatedSurface(name);console.log('LOT00_HUB_RESPONSIVE_PASS '+JSON.stringify({name,...layout}));
   };

   // Browser-rendered Hub accessibility evidence; no persistent style changes.
   const a11yResults=[];
   const auditHub=async(name,width)=>{
     await call('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});
     await sleep(400);
     const result=await evalPage('('+function(){
       const root=document.querySelector('[data-v15-hub]');
       const canvas=document.createElement('canvas');canvas.width=canvas.height=1;
       const ctx=canvas.getContext('2d',{willReadFrequently:true});
       const rgba=s=>{ctx.clearRect(0,0,1,1);ctx.fillStyle='transparent';ctx.fillStyle=s;ctx.fillRect(0,0,1,1);const p=ctx.getImageData(0,0,1,1).data;return [p[0]/255,p[1]/255,p[2]/255,p[3]/255]};
       const over=(f,b)=>[f[0]*f[3]+b[0]*(1-f[3]),f[1]*f[3]+b[1]*(1-f[3]),f[2]*f[3]+b[2]*(1-f[3]),1];
       const lum=p=>p.slice(0,3).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4).reduce((a,x,i)=>a+x*[.2126,.7152,.0722][i],0);
       const ratio=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
       const textNodes=()=>{const nodes=[];const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode()){const e=n.parentElement;if(!n.textContent.trim()||!e||e.closest('script,style,[aria-hidden="true"],:disabled,.sr-only')||!e.getClientRects().length||getComputedStyle(e).visibility==='hidden')continue;const range=document.createRange();range.selectNodeContents(n);if(!Array.from(range.getClientRects()).some(r=>r.width>0&&r.height>0))continue;nodes.push(n)}return nodes};
       const nodes=textNodes();const contrast=[];let imageBackground=0;
       for(const n of nodes){
         const e=n.parentElement,s=getComputedStyle(e),chain=[];for(let p=e;p;p=p.parentElement)chain.unshift(p);
         // CSS background-color compositing, not a pixel audit of gradients/images.
         let bg=[1,1,1,1],uncertain=false;
         for(const p of chain){const x=getComputedStyle(p);if(x.backgroundImage!=='none')uncertain=true;const c=rgba(x.backgroundColor);bg=over(c,bg);if(c[3]===1&&x.backgroundImage==='none')uncertain=false}
         if(uncertain){imageBackground++;continue}
         const foreground=over(rgba(s.color),bg),large=parseFloat(s.fontSize)>=24||(parseFloat(s.fontSize)>=18.667&&Number(s.fontWeight)>=700),minimum=large?3:4.5;
         const actual=ratio(foreground,bg);contrast.push({text:n.textContent.trim().slice(0,85),ratio:Number(actual.toFixed(3)),minimum,pass:actual+0.001>=minimum});
       }
       const elements=[...new Set(nodes.map(n=>n.parentElement))];const original=elements.map(e=>({e,style:e.getAttribute('style'),size:parseFloat(getComputedStyle(e).fontSize),line:parseFloat(getComputedStyle(e).lineHeight)}));
       // 200% text-only enlargement: preserve other dimensions and all original inline styles.
       for(const p of original){p.e.style.setProperty('font-size',2*p.size+'px','important');if(Number.isFinite(p.line))p.e.style.setProperty('line-height',2*p.line+'px','important')}
       const clipped=[];for(const n of textNodes()){
         const range=document.createRange();range.selectNodeContents(n);
         for(const rect of range.getClientRects()){
           if(rect.width===0||rect.height===0)continue;
           let bad=rect.left<-.5||rect.right>document.documentElement.clientWidth+1;
           for(let p=n.parentElement;p&&p!==document.body;p=p.parentElement){
             const s=getComputedStyle(p),r=p.getBoundingClientRect();
             if(['hidden','clip'].includes(s.overflowX)&&(rect.left<r.left-1||rect.right>r.right+1))bad=true;
             if(['hidden','clip'].includes(s.overflowY)&&(rect.top<r.top-1||rect.bottom>r.bottom+1))bad=true;
           }
           if(bad){clipped.push(n.textContent.trim().slice(0,85));break}
         }
       }
       const zoom={documentWidth:document.documentElement.scrollWidth,viewport:document.documentElement.clientWidth,clipped:[...new Set(clipped)],allDoubled:original.every(p=>Math.abs(parseFloat(getComputedStyle(p.e).fontSize)-2*p.size)<.2)};
       // Keep screenshot of actual zoom state until Node captures it; restore via dedicated cleanup.
       window.__dcHubAuditRestore=()=>{for(const p of original){if(p.style===null)p.e.removeAttribute('style');else p.e.setAttribute('style',p.style)}delete window.__dcHubAuditRestore};
       return {textCount:nodes.length,contrast,imageBackground,zoom};
     }.toString()+')()');
     try{await capture('r9-'+name+'-'+width+'-text200');}finally{await evalPage('window.__dcHubAuditRestore?.()')}
     const pass=result.contrast.length>0&&result.imageBackground===0&&result.contrast.length===result.textCount&&result.contrast.every(x=>x.pass)&&result.zoom.allDoubled&&result.zoom.clipped.length===0&&result.zoom.documentWidth<=result.zoom.viewport+1;
     a11yResults.push({name,width,pass,...result});
     console.log('LOT00_HUB_A11Y '+JSON.stringify({name,width,pass,textCount:result.textCount,contrastCount:result.contrast.length,contrastFailures:result.contrast.filter(x=>!x.pass),imageBackground:result.imageBackground,zoom:result.zoom}));
   };
   for(const width of [390,430,768,1280])await responsiveHub(width,900,'r8-neutral-'+width);
   for(const width of [390,768,1280])await auditHub('neutral',width);
   await call('Emulation.clearDeviceMetricsOverride');
   await call('Emulation.setDeviceMetricsOverride',{width:768,height:900,deviceScaleFactor:1,mobile:false});
   assert(await evalPage('document.documentElement.scrollWidth<=innerWidth'));await captureIsolatedSurface('02-fresh-hub-768');
   await call('Emulation.clearDeviceMetricsOverride');
   await click('[data-hub-experience="control"]');await pathIs('/control-center');await shown(control);await captureIsolatedSurface('03-control-fresh');
   await go('/station');await pathIs('/hub');await shown(hub);assert.equal(await evalPage('new URLSearchParams(location.search).get("select")'),'1');
   await click('[data-hub-experience="cabinet"]');await pathIs('/login');await shown('input[type=email]');
   await setField('input[type=email]','ci-owner@example.com');await setField('input[type=password]',password);assert(await clickSubmit());
   await wait('real login',()=>responses.some(r=>r.path==='/api/auth/login'&&r.status===200));
   await pathIs('/dashboard');
   await wait('workstation',async()=>{const r=await browserAPI('/api/workstation/bootstrap');return r.status===200&&r.body.authenticated&&r.body.workstationId});
   await go('/hub?select=1');await shown('[data-workstation-admin]');
   await captureIsolatedSurface('04-authenticated-hub');
   const initial=await checkMode(null);assert(initial.canManage&&initial.canConfigurePin);
   const cfg=await browserAPI('/api/workstation/owner-pin','POST',{accountPassword:password,newPin:pin});assert.equal(cfg.status,200,'configure synthetic PIN');
   const wrong=await browserAPI('/api/workstation/mode','POST',{mode:'station',ownerPin:'123456'});assert.equal(wrong.status,403);await checkMode(null);
   await mode('control_center');await go('/hub');await pathIs('/control-center');await shown(control);
   await captureIsolatedSurface('05-control-dispatch');
   await mode('cabinet');await go('/hub');await pathIs('/dashboard');await checkMode('cabinet');
   await mode('station');await go('/hub');await pathIs('/station');await shown(station);
   await captureIsolatedSurface('06-station-dispatch');
   for(const route of ['/dashboard','/control-center','/hub?select=1']){
     console.log('LOT00_STATION_DIRECT_ROUTE '+route);await go(route);await pathIs('/station');await shown(station);
   }
   const locked=await browserAPI('/api/patients/');assert.equal(locked.status,423);assert.equal(locked.body.detail,'WORKSTATION_STATION_LOCKED');
   const bad=await browserAPI('/api/workstation/station/escape','POST',{ownerPin:'123456'});assert.equal(bad.status,403);
   const boot=await checkMode('station');assert.equal(boot.stationEscapeAuthorized,false);
   const good=await browserAPI('/api/workstation/station/escape','POST',{ownerPin:pin});assert.equal(good.status,200);
   await go('/hub?select=1');await shown(hub);await checkMode('station');
   await mode('cabinet');await go('/hub');await pathIs('/dashboard');await checkMode('cabinet');
   await go('/hub?select=1');await shown(hub);await captureIsolatedSurface('07-recovered-hub');
   await assertPwa();
   console.log('LOT00_FRESH_DISPATCH_MODES_STATION_NEGATIVES_PASS');
   // Diagnostic baseline: use the real persisted clinic API, never inject CSS/storage.
   const themeA={selected_theme:'emerald',primary_color:'#176B58',secondary_color:'#294C60',accent_color:'#C79452'};
   const themeB={selected_theme:'rose',primary_color:'#852B56',secondary_color:'#59384F',accent_color:'#B77845'};
   const setTheme=async (p)=>{
     const r=await browserAPI('/api/clinics/me','PUT',p);
     assert.equal(r.status,200,'persist synthetic theme');
     const q=await browserAPI('/api/clinics/me');
     assert.equal(q.status,200);
     for(const k of Object.keys(p))assert.equal(String(q.body[k]).toLowerCase(),p[k].toLowerCase(),k);
   };
   const observations=[];
   const tokens=()=>evalPage('(()=>{const e=document.querySelector("main[data-v15-hub],main[data-workstation-experience]")||document.body;const read=x=>{const c=getComputedStyle(x);return Object.fromEntries(["--primary","--secondary","--accent","--bg-medical-pearl","--card-bg","--text-main","--border-color"].map(k=>[k,c.getPropertyValue(k).trim().toLowerCase()]))};const p=e.querySelector(".text-primary");return {root:read(document.documentElement),surface:read(e),rootTheme:document.documentElement.dataset.theme||"",bodyTheme:document.body.dataset.theme||"",primaryText:p?getComputedStyle(p).color:null,viewport:[innerWidth,innerHeight]}})()');
   const matches=(o,p)=>o.rootTheme===p.selected_theme&&o.bodyTheme===p.selected_theme&&['root','surface'].every(k=>o[k]['--primary']===p.primary_color.toLowerCase()&&o[k]['--secondary']===p.secondary_color.toLowerCase()&&o[k]['--accent']===p.accent_color.toLowerCase());
   const observe=async(name,p)=>{await sleep(2000);const o=await tokens();const pass=matches(o,p);observations.push({name,pass,...o});console.log('LOT00_THEME_OBSERVATION '+JSON.stringify({name,pass,...o}));await capture(name);return pass};
   await setTheme(themeA);
   await go('/hub?select=1');await shown(hub);await observe('theme-a-hub-direct',themeA);
   await call('Emulation.setDeviceMetricsOverride',{width:768,height:900,deviceScaleFactor:1,mobile:false});
   await observe('theme-a-hub-768',themeA);await call('Emulation.clearDeviceMetricsOverride');
   await go('/control-center');await shown(control);await observe('theme-a-control-direct',themeA);
   await go('/dashboard');await pathIs('/dashboard');
   // Allow the existing MainLayout profile request to complete; record if absent.
   try{await wait('cabinet theme A',async()=>matches(await tokens(),themeA),10000)}catch{}
   await observe('theme-a-cabinet',themeA);
   await go('/hub?select=1');await shown(hub);await observe('theme-a-hub-reload',themeA);
   await mode('station');await go('/station');await shown(station);
   await observe('theme-a-station-locked',themeA);
   const clinicDenied=await browserAPI('/api/clinics/me');assert.equal(clinicDenied.status,423);
   const bound=await browserAPI('/api/workstation/bootstrap');assert.equal(bound.status,200);assert.deepEqual(Object.keys(bound.body.theme).sort(),['accent_color','app_accent_color','primary_color','secondary_color','selected_theme']);
   const anonymous=await api('/api/workstation/bootstrap');assert.equal(anonymous.status,200);assert.equal(anonymous.body.authenticated,false);assert.equal(anonymous.body.theme??null,null);
   const other=await login('ci-other@example.com');const mismatched=await api('/api/workstation/bootstrap',{headers:withWorkstation(other.access_token,await workstationCookie())});assert.equal(mismatched.status,200);assert.equal(mismatched.body.theme??null,null);
   console.log('LOT00_THEME_PROJECTION_BOUNDARY_PASS');
   const exit=await browserAPI('/api/workstation/station/escape','POST',{ownerPin:pin});assert.equal(exit.status,200);
   await go('/hub?select=1');await shown(hub);await mode('cabinet');
   await setTheme(themeB);
   await go('/hub?select=1');await shown(hub);await observe('theme-b-hub-direct',themeB);
   await go('/control-center');await shown(control);await observe('theme-b-control-direct',themeB);
   await go('/dashboard');await pathIs('/dashboard');try{await wait('cabinet theme B',async()=>matches(await tokens(),themeB),10000)}catch{}
   await observe('theme-b-cabinet',themeB);
   await go('/hub?select=1');await shown(hub);await observe('theme-b-hub-reload',themeB);
   for(const width of [390,430,768,1280])await responsiveHub(width,900,'r8-custom-'+width);
   for(const width of [390,768,1280])await auditHub('custom',width);
   fs.writeFileSync(evidence+'/hub-a11y.json',JSON.stringify(a11yResults,null,2));
   console.log('LOT00_HUB_A11Y_MATCHED '+a11yResults.filter(x=>x.pass).length+'/'+a11yResults.length);
   assert(a11yResults.every(x=>x.pass),'Hub contrast or text enlargement divergence');
   await call('Emulation.clearDeviceMetricsOverride');
   fs.writeFileSync(evidence+'/theme-baseline.json',JSON.stringify(observations,null,2));
   console.log('LOT00_THEME_BASELINE_MATCHED '+observations.filter(o=>o.pass).length+'/'+observations.length);
   // Station is deliberately reported separately: locked clinic API remains forbidden.
   // Baseline is diagnostic; workflow gate below will fail on authenticated divergence.
   assert(observations.every(o=>o.pass),'Authenticated theme inheritance divergence');

 }
}finally{ws.close()}
