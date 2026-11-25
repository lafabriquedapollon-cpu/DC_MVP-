// CI-only real Chromium + local API; no auth storage injection or request mocks.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {setTimeout as sleep} from 'node:timers/promises';
const base = 'http://127.0.0.1:8008';
const web = 'http://127.0.0.1:5173';
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
const target=await wait('CDP',async()=>{
  const list=await (await fetch('http://127.0.0.1:9222/json/list')).json();
  return list.find(t=>t.type==='page' && t.url.startsWith(web));
});
const ws=new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
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
    if(r.url.startsWith(base+'/api/')) responses.push({path:new URL(r.url).pathname,status:r.status,method:requests.get(m.params.requestId)});
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
try {
  await call('Network.enable');await call('Page.enable');
  if(process.argv.includes('--verify-restart')){
    const id=Number(fs.readFileSync(process.env.DC_LAB_ROOT+'/synthetic-patient-id','utf8'));
    assert(Number.isSafeInteger(id)&&id>0);
    const cookie=await workstationCookie();
    const owner=await login('ci-owner@example.com');
    const noStation=await api('/api/patients/'+id,{headers:bearer(owner.access_token)});
    assert.equal(noStation.status,423,'Restart still requires workstation identity');
    assert.equal(noStation.body?.detail,'WORKSTATION_IDENTITY_REQUIRED');
    const result=await api('/api/patients/'+id,{headers:withWorkstation(owner.access_token,cookie)});
    assert.equal(result.status,200,'Restart authenticated patient read');
    assert.equal(result.body.nom,'CI-SYNTHETIC');
    assert.equal(result.body.prenom,'Fixture');
    console.log('BACKEND_RESTART_API_READ_PASS');
    // WorkstationModeGate deliberately redirects to the data-free Hub when
    // backend authority is temporarily unavailable. Reloading the current
    // location can therefore reload /hub instead of the intended dossier.
    const before = await pagePath();
    console.log('RESTART_BROWSER_ROUTE', /^\/(hub|dashboard|cabinet|login|patients\/\d+)$/.test(before) ? before : 'other');
    if(before==='/hub'){
      await wait('cabinet recovery entry',()=>visible('[data-hub-experience="cabinet"]'));
      await capture('05-recovery-hub');
      assert(await evalPage('(()=>{const b=document.querySelector(\'[data-hub-experience="cabinet"]\');if(!b||b.disabled)return false;b.click();return true})()'));
      await wait('recovered dashboard',async()=>await pagePath()==='/dashboard');
    }
    // Explicitly reopen the known synthetic record via ordinary routing.
    // Do not alter storage, session cookies, mode, or any authorization gate.
    await call('Page.navigate',{url:web+'/patients/'+id});
    await wait('restart patient route',async()=>await pagePath()==='/patients/'+id);
    await wait('restart patient GET',()=>responses.some(r=>r.path==='/api/patients/'+id&&r.method==='GET'&&r.status===200));
    await wait('restart patient identity',verifyIdentity);
    await capture('06-patient-restarted');
    console.log('BACKEND_RESTART_PATIENT_READ_PASS');
  } else {
  await wait('login form',()=>visible('input[type=email]'));
  await capture('01-login');
  assert.equal((await api('/api/patients/')).status,401);
  await setField('input[type=email]','ci-owner@example.com');
  await setField('input[type=password]',password);
  assert(await clickSubmit());
  await wait('real login API',()=>responses.some(r=>r.path==='/api/auth/login'&&r.method==='POST'&&r.status===200));
  await wait('dashboard',async()=>await pagePath()==='/dashboard');
  console.log('BROWSER_DASHBOARD_ROUTE_REACHED');
  await wait('authenticated profile GET',()=>responses.some(r=>r.path==='/api/auth/me'&&r.method==='GET'&&r.status===200));
  const me=await evalPage('fetch('+JSON.stringify(base+'/api/auth/me')+',{credentials:"include"}).then(async r=>({status:r.status,email:(await r.json()).email}))');
  assert.equal(me.status,200);assert.equal(me.email,'ci-owner@example.com');
  await capture('02-dashboard');
  console.log('BROWSER_LOGIN_SESSION_PASS');
  // Isolated synthetic member, provisioned via actual API using the real browser workstation.
  const teamOwner=await login('ci-owner@example.com');
  const teamHeaders={...withWorkstation(teamOwner.access_token,await workstationCookie()),'Content-Type':'application/json'};
  const teamEmail='ci-fue-team-ui@example.com';
  const created=await api('/api/team/',{method:'POST',headers:teamHeaders,body:JSON.stringify({
    email:teamEmail,password:'CI-Synthetic!Archive-2026',nom_complet:'CI Synthetic Archive UI',role:'SECRETAIRE'
  })});
  assert.equal(created.status,201,'Synthetic member creation');
  const memberId=created.body.id;
  assert(Number.isSafeInteger(memberId)&&memberId>0);
  assert.equal((await api('/api/team/'+memberId+'/approve',{method:'POST',headers:teamHeaders})).status,200);
  const quotaBefore=await api('/api/team/quota',{headers:teamHeaders});
  assert.equal(quotaBefore.status,200);
  await call('Page.navigate',{url:web+'/settings'});
  await wait('team settings tab',()=>evalPage('Array.from(document.querySelectorAll("nav button")).some(b=>b.innerText.includes("Mon Équipe"))'));
  assert(await evalPage('(()=>{const b=Array.from(document.querySelectorAll("nav button")).find(b=>b.innerText.includes("Mon Équipe"));if(!b)return false;b.click();return true})()'));
  const readCard=()=>evalPage('('+(() => {
    const c=Array.from(document.querySelectorAll(".settings-team-surface .group")).find(x=>x.innerText.includes("ci-fue-team-ui@example.com")&&x.querySelector('button[title="Archiver le compte"]'));
    if(!c)return null;
    const archive=c.querySelector('button[title="Archiver le compte"]');
    const perms=c.querySelector('button[title="Gérer les permissions"]');
    return {text:c.innerText,archiveDisabled:archive.disabled,permsDisabled:perms?.disabled,activationButton:Array.from(c.querySelectorAll("button")).some(b=>/^(Réactiver|Suspendre)/.test(b.title))};
  }).toString()+')()');
  await wait('active member UI',async()=>{const c=await readCard();return c&&!c.archiveDisabled&&c.text.includes('Actif')});
  const widths=[390,430,768,1280];
  const viewport=async width=>{await call('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});await sleep(350);};
  for(const width of widths){await viewport(width);await capture('team-before-'+width);}
  let dialog=false;
  ws.addEventListener('message',e=>{const msg=JSON.parse(e.data);if(msg.method==='Page.javascriptDialogOpening'){dialog=msg.params.type==='confirm'&&msg.params.message.includes('Archiver le compte');void call('Page.handleJavaScriptDialog',{accept:dialog});}});
  assert(await evalPage('('+(() => {
    const c=Array.from(document.querySelectorAll(".settings-team-surface .group")).find(x=>x.innerText.includes("ci-fue-team-ui@example.com")&&x.querySelector('button[title="Archiver le compte"]'));
    if(!c)return false;
    c.querySelector('button[title="Archiver le compte"]').click();
    return true;
  }).toString()+')()'));
  await wait('archive API DELETE',()=>responses.some(r=>r.path==='/api/team/'+memberId&&r.method==='DELETE'&&r.status===204));
  assert(dialog,'Expected archive confirmation');
  await wait('archived member UI',async()=>{const c=await readCard();return c&&c.archiveDisabled&&c.permsDisabled&&c.text.includes('Archivé')&&!c.activationButton;});
  for(const width of widths){await viewport(width);await capture('team-after-'+width);}
  const teamRows=await api('/api/team/',{headers:teamHeaders});
  assert.equal(teamRows.status,200);
  const archived=teamRows.body.find(x=>x.id===memberId);
  assert(archived?.is_archived===true&&archived?.is_active===false&&archived?.approval_status==='rejected');
  const quotaAfter=await api('/api/team/quota',{headers:teamHeaders});
  assert.equal(quotaAfter.status,200);
  assert.equal(quotaBefore.body.secretaires_used-quotaAfter.body.secretaires_used,1);
  await call('Page.reload');
  await wait('team settings tab after reload',()=>evalPage('Array.from(document.querySelectorAll("nav button")).some(b=>b.innerText.includes("Mon Équipe"))'));
  await evalPage('(()=>{const b=Array.from(document.querySelectorAll("nav button")).find(b=>b.innerText.includes("Mon Équipe"));if(!b)return false;b.click();return true})()');
  await wait('archived member persisted',async()=>{const c=await readCard();return c&&c.archiveDisabled&&c.permsDisabled&&c.text.includes('Archivé')&&!c.activationButton;});
  await capture('team-reloaded-1280');
  console.log('FUE_TEAM_UI_ARCHIVE_BEFORE_AFTER_PASS widths=390,430,768,1280');
  await call('Emulation.clearDeviceMetricsOverride');
  await call('Page.navigate',{url:web+'/patients/new'});
  await wait('patient form',()=>visible('input[name=nom]'));
  await setField('input[name=nom]','CI-SYNTHETIC');
  await setField('input[name=prenom]','Fixture');
  await setField('input[name=date_naissance]','2000-01-01');
  await setField('select[name=sexe]','F');
  await capture('03-patient-form');
  assert(await clickSubmit());
  await wait('patient POST',()=>responses.some(r=>r.path==='/api/patients/'&&r.method==='POST'&&r.status>=200&&r.status<300));
  const path=await wait('patient detail',async()=>{const p=await pagePath();return /^\/patients\/\d+$/.test(p)?p:false;});
  const id=Number(path.split('/').pop());
  assert(Number.isSafeInteger(id)&&id>0);
  await wait('patient detail API',()=>responses.some(r=>r.path==='/api/patients/'+id&&r.method==='GET'&&r.status===200));
  await wait('rendered patient identity',verifyIdentity);
  await capture('04-patient-detail');
  const result=await evalPage('fetch('+JSON.stringify(base+'/api/patients/'+id)+',{credentials:"include"}).then(async r=>({status:r.status,data:await r.json()}))');
  assert.equal(result.status,200);assert.equal(result.data.nom,'CI-SYNTHETIC');assert.equal(result.data.prenom,'Fixture');
  fs.writeFileSync(process.env.DC_LAB_ROOT+'/synthetic-patient-id',String(id));
  console.log('BROWSER_PATIENT_CREATE_READ_PASS');
  const ownerCookie=await workstationCookie();
  const other=await login('ci-other@example.com');
  // A different tenant receives its own first workstation through the real API.
  const otherState=await api('/api/workstation/state',{headers:bearer(other.access_token)});
  assert.equal(otherState.status,200,'Other tenant workstation registration');
  const otherCookie=otherState.cookies.find(c=>c.startsWith('dc_workstation=')&&/httponly/i.test(c))?.split(';')[0];
  assert(Boolean(otherCookie),'Other server workstation cookie missing');
  assert(otherCookie!==ownerCookie,'Tenant workstation identities must differ');
  const otherHeaders=withWorkstation(other.access_token,otherCookie);
  await denied('/api/patients/'+id,withWorkstation(other.access_token,ownerCookie),423,'WORKSTATION_IDENTITY_REQUIRED','Cross-tenant workstation');
  await denied('/api/patients/'+id,otherHeaders,403,'Accès refusé','Cross-tenant patient');
  const otherList=await api('/api/patients/',{headers:otherHeaders});
  assert.equal(otherList.status,200,'Other tenant list');assert(Array.isArray(otherList.body)&&otherList.body.length===0,'Other tenant list leaked data');
  const restricted=await login('ci-restricted@example.com');
  await denied('/api/patients/'+id,bearer(restricted.access_token),423,'WORKSTATION_IDENTITY_REQUIRED','Unidentified workstation');
  // Same tenant, existing legitimate workstation identity; independently test RBAC.
  const restrictedHeaders=withWorkstation(restricted.access_token,ownerCookie);
  const state=await api('/api/workstation/bootstrap',{headers:restrictedHeaders});
  assert.equal(state.status,200);assert(state.body.authenticated===true && state.body.enrollmentRequired===false && Boolean(state.body.workstationId),'Restricted user valid workstation');
  await denied('/api/patients/'+id,restrictedHeaders,403,null,'Restricted patient detail');
  await denied('/api/patients/',restrictedHeaders,403,null,'Restricted patient list');
  console.log('API_WORKSTATION_DENIAL_PASS');
  console.log('API_TENANT_AND_PERMISSION_DENIAL_PASS');
  const rotated=await api('/api/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:other.refresh_token})});
  assert.equal(rotated.status,200);assert(rotated.body.access_token);
  const replay=await api('/api/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:other.refresh_token})});
  assert.equal(replay.status,401);
  const logout=await api('/api/auth/logout',{method:'POST',headers:{...bearer(rotated.body.access_token),'Content-Type':'application/json'},body:JSON.stringify({refresh_token:rotated.body.refresh_token})});
  assert.equal(logout.status,204);
  assert.equal((await api('/api/auth/me',{headers:bearer(rotated.body.access_token)})).status,401);
  console.log('API_REFRESH_REPLAY_LOGOUT_PASS');
  }
} catch(error) {
  await capture('failure').catch(()=>{});
  console.log('API_STATUS_EVIDENCE',JSON.stringify(responses.slice(-35)));
  // Do not emit CDP expressions, credentials, cookies or response bodies.
  console.log('INTEGRATION_ERROR',String(error.message).slice(0,220));
  process.exitCode=1;
} finally { ws.close(); }
