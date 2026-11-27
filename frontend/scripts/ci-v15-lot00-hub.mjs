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
 if(process.argv.includes('--offline')){
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
   const fresh=await browserAPI('/api/workstation/bootstrap');
   assert.equal(fresh.status,200);assert.equal(fresh.body.authenticated,false);assert.equal(fresh.body.workstationId,null);assert.equal(fresh.body.defaultExperience,null);
   assert.equal((await api('/api/patients/')).status,401);
   await captureIsolatedSurface('01-fresh-hub-1440');
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
   const exit=await browserAPI('/api/workstation/station/escape','POST',{ownerPin:pin});assert.equal(exit.status,200);
   await go('/hub?select=1');await shown(hub);await mode('cabinet');
   await setTheme(themeB);
   await go('/hub?select=1');await shown(hub);await observe('theme-b-hub-direct',themeB);
   await go('/control-center');await shown(control);await observe('theme-b-control-direct',themeB);
   await go('/dashboard');await pathIs('/dashboard');try{await wait('cabinet theme B',async()=>matches(await tokens(),themeB),10000)}catch{}
   await observe('theme-b-cabinet',themeB);
   await go('/hub?select=1');await shown(hub);await observe('theme-b-hub-reload',themeB);
   fs.writeFileSync(evidence+'/theme-baseline.json',JSON.stringify(observations,null,2));
   console.log('LOT00_THEME_BASELINE_MATCHED '+observations.filter(o=>o.pass).length+'/'+observations.length);
   // Station is deliberately reported separately: locked clinic API remains forbidden.
   // Baseline is diagnostic; workflow gate below will fail on authenticated divergence.
   assert(observations.filter(o=>o.name!=='theme-a-station-locked').every(o=>o.pass),'Authenticated theme inheritance divergence');

 }
}finally{ws.close()}
