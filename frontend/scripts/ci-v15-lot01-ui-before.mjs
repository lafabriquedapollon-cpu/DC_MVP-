// R5 visual baseline: actual application, backend and login/pairing; no patient fixtures or mock authorization.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {setTimeout as sleep} from 'node:timers/promises';
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.DC_TEST_SCOPE==='ui-before'&&process.env.ENVIRONMENT==='e2e_install_rehearsal');
const evidence=process.env.DC_EVIDENCE,tools=process.env.DC_BROWSER_TOOLS;
assert(evidence&&tools&&process.env.DC_CHROME&&process.env.DC_SYNTH_PASSWORD);
const requireTool=createRequire(path.join(tools,'package.json'));
assert.equal(requireTool('playwright-core/package.json').version,'1.61.0');
const {chromium}=requireTool('playwright-core');
const web='http://127.0.0.1:5173',api='http://127.0.0.1:8008';
const rows=[];
let browser, desktopPage, pocketPage, stage='startup';
const mark=(label)=>{rows.push({label,pass:true});console.log('LOT01_UI_BEFORE_CASE '+JSON.stringify(rows.at(-1)))};
const shot=async(page,name)=>{await page.screenshot({path:path.join(evidence,name+'.png'),animations:'disabled'});mark(name)};
try {
  let ready=false;
  for(let i=0;i<45;i++){try{if((await fetch(web,{signal:AbortSignal.timeout(1500)})).ok){ready=true;break}}catch{}await sleep(1000)}
  assert(ready,'Vite not ready');
  browser=await chromium.launch({headless:true,executablePath:process.env.DC_CHROME,
    args:['--disable-background-networking','--disable-sync','--disable-quic','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'],
    proxy:{server:'http://127.0.0.1:1',bypass:'127.0.0.1,localhost'}});
  const newContext=async()=>{const ctx=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block'});await ctx.route('**/*',r=>{const u=new URL(r.request().url());return [web,api].includes(u.origin)?r.continue():r.abort()});return ctx};
  const desktop=await newContext(), d=await desktop.newPage();
  desktopPage=d;stage='desktop-login';
  const observed=[];
  d.on('response',r=>{const u=new URL(r.url());if(u.origin===api&&/^\/api\/(auth\/me|auth\/login|workstation\/(state|bootstrap)|config\/[^/]+|superadmin\/(clients|trial-codes))$/.test(u.pathname))observed.push({path:u.pathname,status:r.status()})});
  await d.goto(web+'/login');
  await d.locator('input[type=email]').fill('ci-platform-admin@example.com');
  await d.locator('input[type=password]').fill(process.env.DC_SYNTH_PASSWORD);
  const login=d.waitForResponse(r=>new URL(r.url()).pathname==='/api/auth/login'&&r.request().method()==='POST'&&r.status()===200);
  await d.locator('button[type=submit]').first().click();
  await login;
  await d.waitForURL(u=>u.pathname==='/dashboard',{timeout:60000});
  stage='desktop-authority';
  await d.waitForFunction(()=>{try{const p=JSON.parse(localStorage.getItem('auth-storage')||'null');return p?.state?.user?.is_superadmin===true}catch{return false}},null,{timeout:45000});
  const profile=await d.evaluate(async api=>{const r=await fetch(api+'/api/auth/me',{credentials:'include'});const body=await r.json().catch(()=>null);return {status:r.status,superadmin:body?.is_superadmin===true}},api);
  assert.deepEqual(profile,{status:200,superadmin:true},'actual Desktop platform identity');
  stage='desktop-superadmin';
  await d.goto(web+'/super-admin');
  try {
    await d.getByRole('heading',{name:/Digital Crown\\s*SuperAdmin/i}).waitFor({timeout:60000});
  } catch (error) {
    console.log('LOT01_UI_AUTH_DIAGNOSTIC '+JSON.stringify({responses:observed.slice(-20)}));
    throw error;
  }
  for(const width of [390,430,768,1280]){
    await d.setViewportSize({width,height:900});
    await shot(d,'before-desktop-'+width);
  }
  // Legitimate API pairing using real credentials and canonical workstation cookie.
  const result=await fetch(api+'/api/auth/login',{method:'POST',body:new URLSearchParams({username:'ci-platform-admin@example.com',password:process.env.DC_SYNTH_PASSWORD})});
  assert.equal(result.status,200);const auth=await result.json();
  const headers={Authorization:'Bearer '+auth.access_token};
  const station=await fetch(api+'/api/workstation/state',{headers});assert.equal(station.status,200);
  const cookie=station.headers.getSetCookie().find(x=>x.startsWith('dc_workstation='));assert(cookie);
  const desktopHeaders={...headers,Cookie:cookie.split(';')[0]};
  const me=await fetch(api+'/api/auth/me',{headers:desktopHeaders});assert.equal(me.status,200);
  const identity=await me.json();assert.equal(identity.is_superadmin,true);
  const issue=await fetch(api+'/api/mobile/bridge-pairing',{method:'POST',headers:{...desktopHeaders,'Content-Type':'application/json'},body:JSON.stringify({target_user_id:identity.id,destination:'agenda'})});
  assert.equal(issue.status,200);const {token_code}=await issue.json();assert(token_code);
  const pocket=await newContext(),p=await pocket.newPage();
  pocketPage=p;stage='pocket-pairing';
  // Pair via the actual application's ECDH and vault storage modules.
  // The ticket is never written to a URL, evidence file, or log.
  await p.goto(web+'/mobile/onboarding');
  const paired=await p.evaluate(async({token,api})=>{
    const {generateClientKeyPair,deriveMasterKey}=await import('/src/services/zka/ecdhPairing.ts');
    const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');
    const {privateKey,publicKeyHex}=await generateClientKeyPair();
    const response=await fetch(api+'/api/mobile/claim-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,client_public_key_hex:publicKeyHex})});
    if(!response.ok)return false;
    const data=await response.json();
    const masterKey=await deriveMasterKey(privateKey,data.server_public_key_hex,data.encrypted_master_key_hex);
    await MobileStorage.saveCredentials({publicId:data.publicId,masterKey,access_token:data.access_token,refresh_token:data.refresh_token,device_id:data.device_id,api_base_url:api});
    return MobileStorage.isPaired();
  },{token:token_code,api});
  assert.equal(paired,true);mark('real Pocket ECDH pairing');
  stage='pocket-route';
  await p.goto(web+'/mobile/superadmin');
  await p.waitForURL(u=>u.pathname==='/mobile/dashboard',{timeout:60000});
  await p.locator('[data-dc-mobile-shell]').waitFor({timeout:60000});
  await p.locator('[data-pocket-read-status="ready"]').waitFor({timeout:60000});
  mark('actual previous SuperAdmin route redirects to Pocket dashboard');
  for(const width of [390,430,768,1280]){
    await p.setViewportSize({width,height:900});
    await shot(p,'before-pocket-route-'+width);
  }
  stage='pocket-security';
  await p.goto(web+'/mobile/dashboard?tab=securite');
  await p.locator('[data-m6i-biometric]').waitFor({timeout:60000});
  for(const width of [390,430,768,1280]){
    await p.setViewportSize({width,height:900});
    await shot(p,'before-pocket-security-'+width);
  }
  await p.evaluate(async()=>{const {MobileStorage}=await import('/src/services/zka/MobileStorage.ts');await MobileStorage.clearAll()});
  await pocket.close();await desktop.close();
}catch(error){
  // Only fixed route names and boolean state: never emit raw URL, DOM, tokens or credentials.
  const known=['/login','/dashboard','/super-admin','/hub','/setup','/station','/mobile/onboarding','/mobile/dashboard','/mobile/superadmin'];
  const diagnostic={stage,errorType:error?.name==='TimeoutError'?'TimeoutError':'Other'};
  for(const [label,page] of [['desktop',desktopPage],['pocket',pocketPage]]){
    if(!page||page.isClosed())continue;
    const pathname=new URL(page.url()).pathname;
    diagnostic[label]={path:known.includes(pathname)?pathname:'other'};
    if(label==='desktop')diagnostic[label].profile=await page.evaluate(()=>{try{const u=JSON.parse(localStorage.getItem('auth-storage')||'null')?.state?.user;return {present:!!u,superadmin:u?.is_superadmin===true}}catch{return {present:false,superadmin:false}}}).catch(()=>null);
  }
  console.log('LOT01_UI_BEFORE_DIAGNOSTIC '+JSON.stringify(diagnostic));
  throw Error('UI_BEFORE_FAILED_'+stage);
}finally{
  if(browser)await browser.close();
  fs.writeFileSync(path.join(evidence,'ui-before-status.json'),JSON.stringify(rows));
}
assert.equal(rows.length,14);
