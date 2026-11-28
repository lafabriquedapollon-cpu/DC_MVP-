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
const rows=[];let stage='startup',browser,pocketBrowser,desktop,pocket,d,p,cdp;
const mark=label=>{rows.push({label,pass:true});console.log('LOT01_HTTPS_CASE '+JSON.stringify(rows.at(-1)))};
const allowedPaths=new Set(['/api/auth/login','/api/auth/me','/api/mobile/bridge-pairing','/api/mobile/claim-token','/api/mobile/passkey/status','/api/mobile/passkey/registration/options','/api/mobile/passkey/registration/verify','/api/mobile/passkey/authentication/options','/api/mobile/passkey/authentication/verify','/api/mobile/passkey/enable','/api/mobile/passkey/platform-devices','/api/mobile/passkey/platform-approval','/api/mobile/passkey/platform-approval/claim','/api/mobile/passkey/platform-eligibility','/api/mobile/superadmin/clients','/api/mobile/superadmin/trial-codes','/api/mobile/superadmin/marketplace/overview']);
const observed=[];
const proxy=https.createServer({key:fs.readFileSync(path.join(lab,'tls.key')),cert:fs.readFileSync(path.join(lab,'tls.crt'))},(incoming,out)=>{
  if(incoming.headers.host!=='digitalcrown.local:8005'||!incoming.url?.startsWith('/')||incoming.url.startsWith('//')){out.writeHead(400).end();return;}
  const pathname=new URL(incoming.url,origin).pathname;
  const backend=pathname.startsWith('/api/')||pathname==='/health'||pathname.startsWith('/media/');
  const upstream=http.request({hostname:'127.0.0.1',port:backend?8008:5173,path:incoming.url,method:incoming.method,headers:{...incoming.headers,'x-forwarded-proto':'https','x-forwarded-host':'digitalcrown.local:8005'}},res=>{
    if(allowedPaths.has(pathname)||/^\/api\/mobile\/superadmin\/(?:trial-codes\/\d+\/(?:revocation-request|revocation-status|revoke)|revocation-requests(?:\/[0-9a-f-]+\/approve)?)$/.test(pathname))observed.push({method:incoming.method,path:pathname,status:res.statusCode,cacheNoStore:String(res.headers['cache-control']||'').includes('no-store'),originPresent:typeof incoming.headers.origin==='string',originMatches:incoming.headers.origin===origin});
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
  const context=async(instance=browser)=>{const c=await instance.newContext({viewport:{width:1280,height:900},serviceWorkers:'block'});
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
  stage='synthetic-trial-fixture';
  const fixture=await d.evaluate(async()=>{
    const r=await fetch('/api/superadmin/trial-codes',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({email:'ci-trial@example.com',trial_days:14,cabinet_name:'CI SYNTHETIC',notes:'CI PRIVATE MARKER'})});
    if(!r.ok)return {status:r.status};
    const x=await r.json();return {status:r.status,idPresent:typeof x.id==='number',codePresent:typeof x.code==='string'&&x.code.length>0};
  });
  assert.deepEqual(fixture,{status:200,idPresent:true,codePresent:true});
  mark('actual Desktop creates isolated synthetic trial fixture');
  stage='pairing';
  const pairing=await d.evaluate(async()=>{
    const me=await fetch('/api/auth/me',{credentials:'include'});if(!me.ok)throw Error('identity');
    const u=await me.json();if(u.is_superadmin!==true)throw Error('role');
    const r=await fetch('/api/mobile/bridge-pairing',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({target_user_id:u.id,destination:'agenda'})});
    if(!r.ok)throw Error('pairing');return (await r.json()).token_code;
  });
  assert(pairing);
  // Independent real Chromium processes from initial pairing, with no second Desktop login.
  pocketBrowser=await chromium.launch({headless:true,executablePath:process.env.DC_CHROME,args:[
    '--disable-background-networking','--disable-sync','--disable-quic','--no-proxy-server',
    '--host-resolver-rules=MAP digitalcrown.local 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
    '--ignore-certificate-errors-spki-list='+process.env.DC_TLS_SPKI]});
  pocket=await context(pocketBrowser);p=await pocket.newPage();await p.goto(origin+'/mobile/onboarding');
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
  // Native link state from an entirely contained veth pair, not a JS or CDP
  // online-state override. Both endpoints live in the isolated namespace.
  await p.goto(origin+'/mobile/superadmin');
  const initial=await p.locator('[data-r5-pocket-platform]').getAttribute('data-r5-platform-state');
  const native=await p.evaluate(()=>({online:navigator.onLine,hidden:document.hidden,secure:window.isSecureContext}));
  console.log('LOT01_HTTPS_POCKET_INITIAL '+JSON.stringify({initial,...native}));
  const onlineNetwork=async()=>{
    await p.waitForFunction(()=>navigator.onLine===true,null,{timeout:10000});
    const health=await p.evaluate(async()=>{const r=await fetch('/api/health',{cache:'no-store'});return r.status});
    assert.equal(health,200,'actual local TLS health');
  };
  stage='native-isolated-link';await onlineNetwork();
  if(!native.online)await p.reload();
  stage='pocket-locked-before-approval';await waitState('locked');await noData();
  stage='pocket-uv-before-approval';
  await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ticket');await noData();
  mark('active UV alone cannot display platform data');
  // Only the manual ticket is transferred between isolated contexts; never log it.
  stage='desktop-issue';
  await d.bringToFront();await panel.getByRole('button',{name:'Autoriser un appareil'}).click();
  await panel.locator('select').waitFor({timeout:15000});
  const select=panel.locator('select');assert(await select.inputValue());
  await shot(d,'https-desktop-authorization-1280');
  await panel.locator('input[type=password]').fill(process.env.DC_SYNTH_PASSWORD);
  await panel.locator('input[type=checkbox]').check();
  await response(d,'/api/mobile/passkey/platform-approval','POST',200,()=>panel.getByRole('button',{name:'Générer le ticket temporaire'}).click());
  const field=panel.locator('textarea');await field.waitFor();const transfer=await field.inputValue();assert.equal(transfer.length,80);
  await panel.getByRole('button',{name:'Masquer le ticket'}).click();assert.equal(await field.count(),0);
  mark('Desktop issues independent one-use ticket via real UI and clears it');
  stage='pocket-claim';await p.bringToFront();
  // Foreground switch intentionally locks Pocket. Fresh UV is required again.
  await p.reload();if(!await p.evaluate(()=>navigator.onLine))await onlineNetwork();await waitState('locked');stage='pocket-uv-for-claim';await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ticket');
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
    if(endpoint==='trial-codes'){
      assert.equal(await readRegion.getByText('ci-trial@example.com',{exact:true}).count(),1);
      assert.equal(await readRegion.getByText('CI SYNTHETIC',{exact:true}).count(),1);
      assert.equal(await readRegion.getByText('CI PRIVATE MARKER',{exact:false}).count(),0);
      mark('real nonempty trial projection rendered without private marker');
    }
    await shot(p,'https-pocket-tab-'+endpoint.replace('/','-')+'-1280');
  }
  stage='offline-lock';
  await pocket.setOffline(true);await p.waitForFunction(()=>navigator.onLine===false,null,{timeout:10000});await waitState('offline');await noData();mark('offline immediately clears platform data');
  await pocket.setOffline(false);await onlineNetwork();await p.getByRole('button',{name:'Réessayer'}).click();await waitState('ready');
  await p.getByRole('button',{name:'Verrouiller'}).click();await waitState('locked');await noData();mark('explicit lock clears platform data');
  await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ready');mark('fresh real UV reopens encrypted approval');
  stage='transport-check';
  const platform=observed.filter(x=>x.path.startsWith('/api/mobile/superadmin/'));
  const ceremonies=observed.filter(x=>x.method==='POST'&&x.path.startsWith('/api/mobile/passkey/')&&!x.path.includes('platform-'));
  assert(ceremonies.length>=5&&ceremonies.every(x=>x.originMatches&&x.status===200),'actual ceremony origin enforcement');
  assert(platform.length>=4&&platform.every(x=>x.method==='GET'&&x.status===200&&x.cacheNoStore));
  assert(observed.some(x=>x.path==='/api/mobile/passkey/platform-approval/claim'&&x.status===200&&x.cacheNoStore));
  mark('all observed platform reads GET and no-store');
  // Separate assertions; preserve both diagnostics and continue the security
  // tests if accessibility fails, without ever granting a GREEN verdict.
  stage='contrast-and-labels';
  await p.setViewportSize({width:390,height:900});
  const contrast=await p.evaluate(()=>{
    const root=document.querySelector('[data-r5-pocket-platform]');
    const rgba=x=>{const m=x.match(/^rgba?\(([^)]+)\)$/);if(!m)return null;const a=m[1].split(/[, ]+/).filter(Boolean).map(Number);return [a[0],a[1],a[2],a.length>3?a[3]:1]};
    const blend=(f,b)=>[0,1,2].map(i=>f[i]*f[3]+b[i]*(1-f[3])).concat(1);
    const luminance=c=>[.2126,.7152,.0722].reduce((sum,k,i)=>{let v=c[i]/255;return sum+k*(v<=.04045?v/12.92:((v+.055)/1.055)**2.4)},0);
    let checked=0,unsupported=0;const failures=[];
    for(const el of root.querySelectorAll('*')){
      if(el.closest('button:disabled')||!Array.from(el.childNodes).some(n=>n.nodeType===3&&n.textContent.trim())||el.getBoundingClientRect().width===0)continue;
      const style=getComputedStyle(el);const fg=rgba(style.color);let bg=[255,255,255,1],layers=[],supported=!!fg;
      for(let a=el;a;a=a.parentElement){const css=getComputedStyle(a),c=rgba(css.backgroundColor);if(css.backgroundImage!=='none'||css.opacity!=='1'||!c){supported=false;break;}layers.push(c);if(c[3]===1)break;}
      if(!supported){unsupported++;continue;}
      for(const layer of layers.reverse())bg=blend(layer,bg);
      const f=luminance(blend(fg,bg)),b=luminance(bg),ratio=(Math.max(f,b)+.05)/(Math.min(f,b)+.05);
      const size=parseFloat(style.fontSize),weight=parseInt(style.fontWeight),minimum=size>=24||(size>=18.66&&weight>=700)?3:4.5;
      checked++;if(ratio+1e-6<minimum)failures.push({tag:el.tagName,ratio:Number(ratio.toFixed(2)),minimum});
    }
    const labels=[...root.querySelectorAll('nav button span')].map(el=>{const range=document.createRange();range.selectNodeContents(el);return {lines:range.getClientRects().length,fits:range.getBoundingClientRect().width<=el.closest('button').clientWidth-8+1}});
    return {checked,unsupported,failures,labels};
  });
  console.log('LOT01_HTTPS_CONTRAST '+JSON.stringify(contrast));
  const contrastOK=contrast.checked>=10&&contrast.unsupported===0&&contrast.failures.length===0&&contrast.labels.length===3&&contrast.labels.every(x=>x.lines===1&&x.fits);
  rows.push({label:'Pocket ready text contrast and unbroken navigation labels at 390',pass:contrastOK});
  stage='keyboard-focus';
  await p.setViewportSize({width:390,height:900});
  const clients=p.getByRole('button',{name:'Clients',exact:true});
  await clients.focus();
  await p.keyboard.press('Tab');
  const focus=await p.getByRole('button',{name:'Essais',exact:true}).evaluate(el=>{
    const css=getComputedStyle(el);
    return {active:el===document.activeElement,focusVisible:el.matches(':focus-visible'),outline:css.outlineStyle,width:parseFloat(css.outlineWidth),shadow:css.boxShadow!=='none'};
  });
  console.log('LOT01_HTTPS_A11Y_FOCUS '+JSON.stringify(focus));
  const focusOK=focus.active&&focus.focusVisible&&((focus.outline!=='none'&&focus.width>=2)||focus.shadow);
  stage='text-reflow';
  await p.evaluate(()=>{document.documentElement.style.fontSize='200%'});
  let reflowOK=false;
  try{
    const reflow=await p.evaluate(()=>{
      const width=innerWidth,scroll=document.documentElement.scrollWidth;
      return {width,scroll,overflow:[...document.querySelectorAll('[data-r5-pocket-platform] *')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&(r.right>width+1||r.left< -1)}).slice(0,10).map(e=>({tag:e.tagName,w:Math.round(e.getBoundingClientRect().width)}))};
    });
    console.log('LOT01_HTTPS_A11Y_REFLOW '+JSON.stringify(reflow));
    reflowOK=reflow.scroll<=reflow.width+1&&reflow.overflow.length===0;
    await p.screenshot({path:path.join(evidence,'https-pocket-text-200-390.png'),animations:'disabled',mask:[p.locator('input,textarea')]});
    if(reflowOK)mark('https-pocket-text-200-390');
    else rows.push({label:'https-pocket-text-200-390',pass:false});
  }finally{await p.evaluate(()=>{document.documentElement.style.fontSize=''})}
  if(focusOK&&reflowOK)mark('keyboard focus visible and 200 percent root text reflow at 390');
  else rows.push({label:'keyboard focus visible and 200 percent root text reflow at 390',pass:false});
  stage='multi-tab-open';
  const second=await pocket.newPage();
  await second.bringToFront();await second.goto(origin+'/mobile/superadmin');
  await second.locator('[data-r5-platform-state="locked"]').waitFor({timeout:30000});
  assert.equal(await second.getByRole('region',{name:'Consultation plateforme'}).count(),0);
  stage='multi-tab-peer-lock';
  await waitState('locked');await noData();
  const retired=await p.evaluate(async()=>{
    const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');
    let ctxDenied=false;try{await MobileStorage.capturePlatformVaultContext()}catch{ctxDenied=true}
    return {ctxDenied,unlocked:await MobileStorage.isBiometricVaultUnlocked(),tokenPresent:!!MobileStorage.getBiometricAccessToken(),hidden:document.hidden};
  });
  console.log('LOT01_HTTPS_PEER_LOCK '+JSON.stringify(retired));
  assert(retired.ctxDenied&&!retired.unlocked&&!retired.tokenPresent,'peer must retire in-memory authority');
  await second.close();await p.bringToFront();
  stage='multi-tab-reauth';
  await p.getByRole('button',{name:'Vérifier ma biométrie'}).click();await waitState('ready');
  mark('second tab requires UV and peer tab clears data and in-memory authority');
  stage='mutation-existing-authorized-desktop';
  const md=d;
  await md.bringToFront();
  const inbox=md.locator('[data-lot01-revocation-inbox]');await inbox.waitFor({timeout:15000});
  const desktopIdentity=await md.evaluate(async()=>{const r=await fetch('/api/auth/me',{credentials:'include',cache:'no-store'});return {status:r.status,superadmin:r.ok&&(await r.json()).is_superadmin===true};});
  assert.deepEqual(desktopIdentity,{status:200,superadmin:true});
  await p.bringToFront();
  assert(await p.evaluate(()=>!document.hidden));assert(await md.evaluate(()=>!document.hidden));
  stage='mutation-pocket-prepare';
  await response(p,'/api/mobile/superadmin/trial-codes','GET',200,()=>p.getByRole('button',{name:'Essais',exact:true}).click());
  await waitState('ready');await p.setViewportSize({width:390,height:900});
  const trialCard=p.locator('article').filter({hasText:'ci-trial@example.com'});
  await trialCard.getByRole('button',{name:'Demander la révocation'}).waitFor();
  const pendingResponse=p.waitForResponse(r=>/\/api\/mobile\/superadmin\/trial-codes\/\d+\/revocation-request$/.test(new URL(r.url()).pathname)&&r.request().method()==='POST');
  await trialCard.getByRole('button',{name:'Demander la révocation'}).click();
  const pendingResult=await pendingResponse;assert.equal(pendingResult.status(),200);assert(pendingResult.headers()['cache-control'].includes('no-store'));
  await trialCard.getByText('En attente de confirmation Desktop',{exact:false}).waitFor();
  assert.equal(await trialCard.getByRole('button',{name:'Confirmer la révocation définitive'}).count(),0);
  await shot(p,'https-pocket-revocation-pending-390');
  stage='mutation-desktop-inbox';
  await response(md,'/api/mobile/superadmin/revocation-requests','GET',200,()=>inbox.getByRole('button',{name:'Actualiser les demandes'}).click());
  await inbox.getByText('ci-trial@example.com',{exact:true}).waitFor();
  await inbox.getByRole('button',{name:'Examiner cette demande'}).click();
  const confirmButton=inbox.getByRole('button',{name:'Approuver la révocation ciblée'});
  assert(await confirmButton.isDisabled());
  await shot(md,'https-desktop-revocation-review-1280');
  await inbox.getByLabel('Mot de passe de confirmation').fill(process.env.DC_SYNTH_PASSWORD);
  await inbox.locator('input[type=checkbox]').check();
  stage='mutation-desktop-approve';
  const approvalResponse=md.waitForResponse(r=>/\/api\/mobile\/superadmin\/revocation-requests\/[0-9a-f-]+\/approve$/.test(new URL(r.url()).pathname)&&r.request().method()==='POST');
  await confirmButton.click();const approvalResult=await approvalResponse;assert.equal(approvalResult.status(),200);
  await inbox.getByText('Accord donné.',{exact:false}).waitFor();
  assert.equal(await inbox.locator('input[type=password]').count(),0);
  assert(await p.evaluate(()=>!document.hidden));
  mark('independent real Desktop confirms exact request with explicit password and checkbox');
  stage='mutation-pocket-status';
  const statusResponse=p.waitForResponse(r=>/\/api\/mobile\/superadmin\/trial-codes\/\d+\/revocation-status$/.test(new URL(r.url()).pathname)&&r.request().method()==='POST');
  await trialCard.getByRole('button',{name:'Vérifier l’accord Desktop'}).click();
  assert.equal((await statusResponse).status(),200);
  await trialCard.getByRole('button',{name:'Confirmer la révocation définitive'}).waitFor();
  await shot(p,'https-pocket-revocation-approved-390');
  stage='mutation-pocket-execute';
  const executionResponse=p.waitForResponse(r=>/\/api\/mobile\/superadmin\/trial-codes\/\d+\/revoke$/.test(new URL(r.url()).pathname)&&r.request().method()==='POST');
  await trialCard.getByRole('button',{name:'Confirmer la révocation définitive'}).click();
  const mutationResult=await executionResponse;assert.equal(mutationResult.status(),200);assert(mutationResult.headers()['cache-control'].includes('no-store'));
  await waitState('ready');await trialCard.getByText('Révoqué · 14 jours',{exact:true}).waitFor();
  assert.equal(await trialCard.getByRole('button',{name:'Demander la révocation'}).count(),0);
  await shot(p,'https-pocket-revocation-complete-390');
  mark('actual HTTPS UI mutation refreshed persisted revoked status; no automatic replay');
  // Keep the original authenticated Desktop for the following device-revocation gate.
  stage='revoke-device';
  const device=await p.evaluate(async()=>{const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');return (await MobileStorage.capturePlatformVaultContext()).deviceId});
  assert(typeof device==='string'&&device.length===36);
  const status=await d.evaluate(async id=>(await fetch('/api/admin/mobile-devices/'+encodeURIComponent(id)+'/revoke',{method:'POST',credentials:'include'})).status,device);
  assert.equal(status,200,'actual Desktop device revoke');
  const rejected=await p.evaluate(async()=>{
    const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');
    const ctx=await MobileStorage.capturePlatformVaultContext();
    const proof=await MobileStorage.getPlatformApproval(ctx);
    if(!proof)throw Error('expected encrypted approval before rejection');
    return (await fetch('/api/mobile/superadmin/clients',{headers:{Authorization:'Bearer '+ctx.token,'X-Platform-Approval':proof},credentials:'omit',cache:'no-store',redirect:'error'})).status;
  });
  assert.equal(rejected,401,'revoked UV and approval refused by actual server');
  await p.getByRole('button',{name:'Actualiser'}).click();await waitState('locked');await noData();
  mark('Desktop revocation rejects existing UV and approval and clears Pocket UI');
  // Browser context cleanup is mandatory. Audit and device persistence are
  // separately verified in a new database session by the LAB workflow.
  stage='cleanup';
  await p.evaluate(async()=>{const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');await MobileStorage.clearAll()});
  await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId});await pocket.close();await desktop.close();
  mark('synthetic browser vault and virtual authenticator removed');
}catch(err){
  const pocketState=p&&!p.isClosed()?await p.evaluate(()=>({state:document.querySelector('[data-r5-pocket-platform]')?.getAttribute('data-r5-platform-state')||'absent',online:navigator.onLine,hidden:document.hidden,secure:window.isSecureContext})).catch(()=>null):null;
  console.log('LOT01_HTTPS_DIAGNOSTIC '+JSON.stringify({stage,type:err?.name==='TimeoutError'?'TimeoutError':'Other',pocketState,observed:observed.slice(-40)}));
  throw Error('HTTPS_E2E_FAILED_'+stage);
}
finally{
  if(pocketBrowser)await pocketBrowser.close();
  if(browser)await browser.close();
  proxy.closeAllConnections();await new Promise(resolve=>proxy.close(resolve));
  fs.writeFileSync(path.join(evidence,'https-status.json'),JSON.stringify(rows));
}
assert.equal(rows.length,32);
assert(rows.every(r=>r.pass===true),'accessibility gate failed; see explicit focus and reflow diagnostics');
