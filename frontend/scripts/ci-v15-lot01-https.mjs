// Real Chromium/WebAuthn PRF and actual FastAPI through a loopback-only TLS proxy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import {createRequire} from 'node:module';
import {setTimeout as sleep} from 'node:timers/promises';
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.DC_TEST_SCOPE==='ui-before'&&process.env.DC_UI_TARGET==='https'&&process.env.ENVIRONMENT==='e2e_install_rehearsal');
const lab=process.env.DC_LAB_ROOT,evidence=process.env.DC_EVIDENCE;
assert(lab&&evidence&&process.env.DC_TLS_SPKI&&process.env.DC_CHROME&&process.env.DC_SYNTH_PASSWORD);
const req=createRequire(path.join(process.env.DC_BROWSER_TOOLS,'package.json'));
assert.equal(req('playwright-core/package.json').version,'1.61.0');
const {chromium}=req('playwright-core');
const origin='https://digitalcrown.local:8005',api='http://127.0.0.1:8008';
const rows=[];let stage='startup',browser,desktop,pocket,d,p,cdp;
const mark=label=>{rows.push({label,pass:true});console.log('LOT01_HTTPS_CASE '+JSON.stringify(rows.at(-1)))};
const allowedPaths=new Set(['/api/auth/login','/api/auth/me','/api/mobile/bridge-pairing','/api/mobile/claim-token','/api/mobile/passkey/status','/api/mobile/passkey/registration/options','/api/mobile/passkey/registration/verify','/api/mobile/passkey/authentication/options','/api/mobile/passkey/authentication/verify','/api/mobile/passkey/enable','/api/mobile/passkey/platform-devices','/api/mobile/passkey/platform-approval','/api/mobile/passkey/platform-approval/claim','/api/mobile/passkey/platform-eligibility','/api/mobile/superadmin/clients','/api/mobile/superadmin/trial-codes','/api/mobile/superadmin/marketplace/overview']);
const observed=[];
const proxy=https.createServer({key:fs.readFileSync(path.join(lab,'tls.key')),cert:fs.readFileSync(path.join(lab,'tls.crt'))},(incoming,out)=>{
  if(incoming.headers.host!=='digitalcrown.local:8005'||!incoming.url?.startsWith('/')||incoming.url.startsWith('//')){out.writeHead(400).end();return;}
  const pathname=new URL(incoming.url,origin).pathname;
  const backend=pathname.startsWith('/api/')||pathname==='/health'||pathname.startsWith('/media/');
  const upstream=http.request({hostname:'127.0.0.1',port:backend?8008:5173,path:incoming.url,method:incoming.method,headers:{...incoming.headers,'x-forwarded-proto':'https','x-forwarded-host':'digitalcrown.local:8005'}},res=>{
    if(allowedPaths.has(pathname))observed.push({method:incoming.method,path:pathname,status:res.statusCode,cacheNoStore:String(res.headers['cache-control']||'').includes('no-store'),originPresent:typeof incoming.headers.origin==='string',originMatches:incoming.headers.origin===origin});
    out.writeHead(res.statusCode,res.headers);res.pipe(out);
  });
  upstream.on('error',()=>{if(!out.headersSent)out.writeHead(502);out.end();});
  incoming.on('aborted',()=>upstream.destroy());incoming.pipe(upstream);
});
const waitState=(state)=>p.locator('[data-r5-pocket-platform][data-r5-platform-state="'+state+'"]').waitFor({timeout:30000});
const noData=async()=>assert.equal(await p.getByRole('region',{name:'Consultation plateforme'}).count(),0);
const shot=async(page,name)=>{await page.screenshot({path:path.join(evidence,name+'.png'),animations:'disabled',mask:[page.locator('input,textarea')]});mark(name)};
const response=async(page,path,method,status,action)=>{
  const pending=page.waitForResponse(r=>new URL(r.url()).pathname===path&&r.request().method()===method,{timeout:30000});
  await action();const r=await pending;assert.equal(r.status(),status,path);return r;
};
try{
  let ready=false;
  for(let i=0;i<45;i++){try{if((await fetch('http://127.0.0.1:5173',{signal:AbortSignal.timeout(1500)})).ok){ready=true;break}}catch{}await sleep(1000)}
  assert(ready,'Vite readiness');
  await new Promise((resolve,reject)=>{proxy.once('error',reject);proxy.listen(8005,'127.0.0.1',resolve)});
  browser=await chromium.launch({headless:true,executablePath:process.env.DC_CHROME,args:[
    '--disable-background-networking','--disable-sync','--disable-quic','--no-proxy-server',
    '--host-resolver-rules=MAP digitalcrown.local 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
    '--ignore-certificate-errors-spki-list='+process.env.DC_TLS_SPKI]});
  const context=async()=>{const c=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block'});
    await c.route('**/*',r=>new URL(r.request().url()).origin===origin?r.continue():r.abort());return c};
  desktop=await context();d=await desktop.newPage();stage='desktop-login';
  await d.goto(origin+'/login');assert(await d.evaluate(()=>window.isSecureContext&&location.origin==='https://digitalcrown.local:8005'));
  await d.locator('input[type=email]').fill('ci-platform-admin@example.com');
  await d.locator('input[type=password]').fill(process.env.DC_SYNTH_PASSWORD);
  await response(d,'/api/auth/login','POST',200,()=>d.locator('button[type=submit]').first().click());
  await d.waitForURL(u=>u.pathname==='/dashboard',{timeout:60000});
  await d.waitForFunction(()=>JSON.parse(localStorage.getItem('auth-storage')||'null')?.state?.user?.is_superadmin===true,null,{timeout:45000});
  await d.goto(origin+'/super-admin');const panel=d.locator('[data-r5-desktop-authorization]');await panel.waitFor({timeout:30000});
  mark('actual HTTPS Desktop login and platform panel');
  stage='pairing';
  const pairing=await d.evaluate(async()=>{
    const me=await fetch('/api/auth/me',{credentials:'include'});if(!me.ok)throw Error('identity');
    const u=await me.json();if(u.is_superadmin!==true)throw Error('role');
    const r=await fetch('/api/mobile/bridge-pairing',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({target_user_id:u.id,destination:'agenda'})});
    if(!r.ok)throw Error('pairing');return (await r.json()).token_code;
  });
  assert(pairing);
  pocket=await context();p=await pocket.newPage();await p.goto(origin+'/mobile/onboarding');
  assert(await p.evaluate(()=>window.isSecureContext&&location.origin==='https://digitalcrown.local:8005'));
  const paired=await p.evaluate(async token=>{
    const {generateClientKeyPair,deriveMasterKey}=await import('/src/services/zka/ecdhPairing.ts');
    const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');
    const {privateKey,publicKeyHex}=await generateClientKeyPair();
    const r=await fetch('/api/mobile/claim-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,client_public_key_hex:publicKeyHex}),credentials:'omit'});
    if(!r.ok)return false;const data=await r.json();
    const masterKey=await deriveMasterKey(privateKey,data.server_public_key_hex,data.encrypted_master_key_hex);
    await MobileStorage.saveCredentials({publicId:data.publicId,masterKey,access_token:data.access_token,refresh_token:data.refresh_token,device_id:data.device_id,api_base_url:location.origin});
    return MobileStorage.isPaired();
  },pairing);assert(paired);mark('real HTTPS ECDH pairing');
  stage='prf-enrollment';
  cdp=await pocket.newCDPSession(p);await cdp.send('WebAuthn.enable');
  const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',ctap2Version:'ctap2_1',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true,hasPrf:true,hasHmacSecret:true}});
  await p.bringToFront();
  await p.goto(origin+'/mobile/dashboard?tab=securite');
  const capability=await p.evaluate(async()=>{
    const {getMobilePasskeyStatus,isStablePasskeyOrigin,hasPlatformUserVerification}=await import('/src/services/zka/mobilePasskey.ts');
    const status=await getMobilePasskeyStatus();
    return {state:status.state,originReady:status.origin_ready,stable:isStablePasskeyOrigin(),
      platformUV:await hasPlatformUserVerification()};
  });
  console.log('LOT01_HTTPS_PRF_CAPABILITY '+JSON.stringify(capability));
  assert.deepEqual(capability,{state:'disabled',originReady:true,stable:true,platformUV:true});
  const activate=p.locator('[data-m6i-activate]');
  await activate.waitFor({timeout:15000});
  await response(p,'/api/mobile/passkey/enable','POST',200,()=>activate.click());
  await p.getByText('Activé',{exact:true}).first().waitFor({timeout:15000});
  mark('real browser virtual authenticator PRF enrollment and server enable');
  stage='pocket-before-approval';
  await p.goto(origin+'/mobile/superadmin');await waitState('locked');await noData();
  await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ticket');await noData();
  mark('active UV alone cannot display platform data');
  // Only the manual ticket is transferred between isolated contexts; never log it.
  stage='desktop-issue';
  await d.bringToFront();await panel.getByRole('button',{name:'Autoriser un appareil'}).click();
  await panel.locator('select').waitFor({timeout:15000});
  const select=panel.locator('select');assert(await select.inputValue());
  await panel.locator('input[type=password]').fill(process.env.DC_SYNTH_PASSWORD);
  await panel.locator('input[type=checkbox]').check();
  await response(d,'/api/mobile/passkey/platform-approval','POST',200,()=>panel.getByRole('button',{name:'Générer le ticket temporaire'}).click());
  const field=panel.locator('textarea');await field.waitFor();const transfer=await field.inputValue();assert.equal(transfer.length,80);
  await panel.getByRole('button',{name:'Masquer le ticket'}).click();assert.equal(await field.count(),0);
  mark('Desktop issues independent one-use ticket via real UI and clears it');
  stage='pocket-claim';await p.bringToFront();
  // Foreground switch intentionally locks Pocket. Fresh UV is required again.
  await p.reload();await waitState('locked');await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ticket');
  await p.getByLabel('Ticket temporaire').fill(transfer);
  await response(p,'/api/mobile/passkey/platform-approval/claim','POST',200,()=>p.getByRole('button',{name:'Valider le ticket'}).click());
  await waitState('ready');
  const readRegion=p.getByRole('region',{name:'Consultation plateforme'});await readRegion.waitFor();
  assert.equal(await p.locator('input[type=password]').count(),0);
  mark('real ticket claim and encrypted vault read with server authorization');
  stage='read-only';
  for(const width of [390,430,768,1280]){
    await p.setViewportSize({width,height:900});await waitState('ready');
    const reflow=await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1);assert(reflow,'Pocket horizontal overflow');
    await shot(p,'https-pocket-clients-'+width);
  }
  for(const [name,endpoint] of [['Essais','trial-codes'],['Marketplace','marketplace/overview'],['Clients','clients']]){
    await response(p,'/api/mobile/superadmin/'+endpoint,'GET',200,()=>p.getByRole('button',{name,exact:true}).click());await waitState('ready');
    assert.equal(await readRegion.locator('input,textarea,form').count(),0);
    await shot(p,'https-pocket-'+endpoint.replace('/','-')+'-1280');
  }
  stage='offline-lock';
  await pocket.setOffline(true);await waitState('offline');await noData();mark('offline immediately clears platform data');
  await pocket.setOffline(false);await p.getByRole('button',{name:'Réessayer'}).click();await waitState('ready');
  await p.getByRole('button',{name:'Verrouiller'}).click();await waitState('locked');await noData();mark('explicit lock clears platform data');
  await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ready');mark('fresh real UV reopens encrypted approval');
  stage='transport-check';
  const platform=observed.filter(x=>x.path.startsWith('/api/mobile/superadmin/'));
  const ceremonies=observed.filter(x=>x.method==='POST'&&x.path.startsWith('/api/mobile/passkey/')&&!x.path.includes('platform-'));
  assert(ceremonies.length>=5&&ceremonies.every(x=>x.originMatches&&x.status===200),'actual ceremony origin enforcement');
  assert(platform.length>=4&&platform.every(x=>x.method==='GET'&&x.status===200&&x.cacheNoStore));
  assert(observed.some(x=>x.path==='/api/mobile/passkey/platform-approval/claim'&&x.status===200&&x.cacheNoStore));
  mark('all observed platform reads GET and no-store');
  // Revoke only this synthetic device through existing canonical Desktop endpoint in follow-up;
  // no server-side authority is mocked here. Browser context cleanup is mandatory.
  stage='cleanup';
  await p.evaluate(async()=>{const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');await MobileStorage.clearAll()});
  await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId});await pocket.close();await desktop.close();
  mark('synthetic browser vault and virtual authenticator removed');
}catch(err){console.log('LOT01_HTTPS_DIAGNOSTIC '+JSON.stringify({stage,type:err?.name==='TimeoutError'?'TimeoutError':'Other',observed:observed.slice(-40)}));throw Error('HTTPS_E2E_FAILED_'+stage)}
finally{
  if(browser)await browser.close();
  proxy.closeAllConnections();await new Promise(resolve=>proxy.close(resolve));
  fs.writeFileSync(path.join(evidence,'https-status.json'),JSON.stringify(rows));
}
assert.equal(rows.length,18);
