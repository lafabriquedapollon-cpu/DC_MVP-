// Actual Chromium IndexedDB + WebCrypto. Synthetic local tokens/PRF bytes ONLY;
// no network API authentication, no mocked storage/crypto, no patient data.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import ts from 'typescript';
const root=process.env.DC_VAULT_LAB, tools=process.env.DC_BROWSER_TOOLS;
assert(process.env.GITHUB_ACTIONS==='true' && root && tools && process.env.DC_VAULT_EVIDENCE);
assert(path.dirname(root)===process.env.RUNNER_TEMP && path.basename(root).startsWith('dc-pocket-vault.'));
const req=createRequire(path.join(tools,'package.json'));
assert.equal(req('playwright-core/package.json').version,'1.61.0');
const {chromium}=req('playwright-core');
const source=fs.readFileSync(new URL('../src/services/zka/MobileStorage.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},reportDiagnostics:true});
assert.equal(compiled.diagnostics?.length||0,0);
const js=compiled.outputText.replace("from 'localforage'", "from '/localforage.mjs'").replaceAll('import.meta.env','({})');
const library=fs.readFileSync(new URL('../node_modules/localforage/dist/localforage.js',import.meta.url));
const html='<!doctype html><title>Isolated Pocket vault</title><script src="/localforage.js"></script>';
const server=http.createServer((r,w)=>{
  const entry={'/':['text/html',html],'/storage.mjs':['text/javascript',js],
    '/localforage.js':['text/javascript',library],'/localforage.mjs':['text/javascript','export default window.localforage;']}[r.url];
  if(!entry){w.writeHead(404);return w.end()}
  w.writeHead(200,{'Content-Type':entry[0],'Cache-Control':'no-store'});w.end(entry[1]);
});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
const origin='http://127.0.0.1:'+server.address().port;
let browser;
const rows=[];
const mark=(label)=>{rows.push({label,pass:true});console.log('LOT01_VAULT_CASE '+JSON.stringify(rows.at(-1)))};
try {
  browser=await chromium.launchPersistentContext(path.join(root,'profile'),{
    executablePath:process.env.DC_CHROME,headless:true,timeout:30000,
    proxy:{server:'http://127.0.0.1:1',bypass:'127.0.0.1,localhost'},
    args:['--disable-background-networking','--disable-sync','--disable-quic','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'],
  });
  const page=browser.pages()[0]||await browser.newPage();
  await page.goto(origin);
  const setup=async()=>page.evaluate(async()=>{
    const {MobileStorage:s}=await import('/storage.mjs');
    const device='00000000-0000-4000-8000-000000000001';
    const b64=x=>btoa(JSON.stringify(x)).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
    const jwt=(type,extra={})=>'fixture.'+b64({type,sub:'1',tenant_id:1,device_id:device,exp:Math.floor(Date.now()/1000)+600,...extra})+'.local-fixture';
    const uv=jwt('mobile',{biometric_uv:true});
    // Stable offline-only proof fixture across page reload; never sent to any API.
    const proof=jwt('mobile_platform_approval',{exp:4102444800});
    const creds={publicId:'a'.repeat(16),masterKey:'b'.repeat(64),access_token:'LOCAL-NOT-AUTH',refresh_token:'LOCAL-NOT-AUTH',device_id:device,api_base_url:'https://digitalcrown.local:8005'};
    window.lab={s,device,jwt,uv,proof,creds,prf:new Uint8Array(32).fill(42),check:(v)=>{if(!v)throw Error('assertion failed')},
      denied:async(fn)=>{try{await fn();return false}catch{return true}}};
  });
  await setup();
  await page.evaluate(async()=>{
    const {s,creds,prf,uv,proof,check,denied}=window.lab;
    await s.clearAll();await s.saveCredentials(creds);
    check(await denied(()=>s.capturePlatformVaultContext()));
    await s.sealBiometricVault({credentialId:'ci-credential',prfSalt:'ci-salt',prfOutput:prf});
    check(await denied(()=>s.capturePlatformVaultContext()));
    s.setBiometricAccessToken(uv);const ctx=await s.capturePlatformVaultContext();
    check(await s.getPlatformApproval(ctx)===null);
    check(await denied(()=>s.savePlatformApproval('not-a-proof',ctx)));
    await s.savePlatformApproval(proof,ctx);check(await s.getPlatformApproval(ctx)===proof);
    const all=[];await window.localforage.iterate((value,key)=>{all.push([key,value])});
    const env=all.find(([k])=>k==='zka_platform_approval_v1')[1];
    check(env.version===1 && Object.keys(env).sort().join(',')==='ciphertext,iv,version');
    check(!JSON.stringify(all).includes(proof) && !JSON.stringify(localStorage).includes(proof) && !JSON.stringify(sessionStorage).includes(proof));
    const before=env.iv;await s.savePlatformApproval(proof,ctx);
    const next=await window.localforage.getItem('zka_platform_approval_v1');check(next.iv!==before);
    s.lockBiometricVault();check(await denied(()=>s.getPlatformApproval(ctx)));
    check(await denied(()=>s.savePlatformApproval(proof,ctx)));
    check(await denied(()=>s.capturePlatformVaultContext()));
  });
  mark('actual AES-GCM and IndexedDB ciphertext, no plaintext, IV rotation, stale context denied');
  await page.reload();await setup();
  await page.evaluate(async()=>{
    const {s,prf,uv,proof,check,denied}=window.lab;
    check(await denied(()=>s.capturePlatformVaultContext()));
    check(await denied(()=>s.unlockBiometricVault(new Uint8Array(32).fill(1))));
    await s.unlockBiometricVault(prf);
    check(await denied(()=>s.capturePlatformVaultContext()));
    s.setBiometricAccessToken(uv);let ctx=await s.capturePlatformVaultContext();
    check(await s.getPlatformApproval(ctx)===proof);
    const env=await window.localforage.getItem('zka_platform_approval_v1');
    const tampered={...env,ciphertext:(env.ciphertext[0]==='A'?'B':'A')+env.ciphertext.slice(1)};
    await window.localforage.setItem('zka_platform_approval_v1',tampered);
    check(await denied(()=>s.getPlatformApproval(ctx)));
    await window.localforage.setItem('zka_platform_approval_v1',env);
    s.setBiometricAccessToken(window.lab.jwt('mobile',{biometric_uv:true,exp:1}));
    check(await denied(()=>s.capturePlatformVaultContext()));
    s.setBiometricAccessToken(uv);ctx=await s.capturePlatformVaultContext();
    check(await s.getPlatformApproval(ctx)===proof);
    await s.disableBiometricVault();check(await window.localforage.getItem('zka_platform_approval_v1')===null);
    check(await denied(()=>s.getPlatformApproval(ctx)));
  });
  mark('reload, wrong PRF, offline unlock, tamper, UV expiry and biometric disable');
  await page.evaluate(async()=>{
    const {s,creds,prf,uv,proof,check,denied}=window.lab;
    await s.sealBiometricVault({credentialId:'ci-credential',prfSalt:'ci-salt',prfOutput:prf});
    s.setBiometricAccessToken(uv);let ctx=await s.capturePlatformVaultContext();
    await s.savePlatformApproval(proof,ctx);
    const old=await window.localforage.getItem('zka_platform_approval_v1');
    await s.saveCredentials({...creds,publicId:'c'.repeat(16)});
    check(await window.localforage.getItem('zka_platform_approval_v1')===null);
    check(await denied(()=>s.getPlatformApproval(ctx)));
    await s.sealBiometricVault({credentialId:'ci-replacement',prfSalt:'ci-salt',prfOutput:prf});
    s.setBiometricAccessToken(uv);ctx=await s.capturePlatformVaultContext();
    await window.localforage.setItem('zka_platform_approval_v1',old);
    check(await denied(()=>s.getPlatformApproval(ctx)));
    await s.savePlatformApproval(proof,ctx);
    const pending=s.savePlatformApproval(proof,ctx).catch(()=>undefined);
    await s.clearAll();await pending;
    check(await window.localforage.getItem('zka_platform_approval_v1')===null);
    check(await denied(()=>s.capturePlatformVaultContext()));
  });
  mark('cabinet change, copied ciphertext rejected by AAD, concurrent logout cleanup');
} finally {
  if(browser)await browser.close();
  server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
  fs.writeFileSync(path.join(process.env.DC_VAULT_EVIDENCE,'vault-status.json'),JSON.stringify(rows));
}
assert.equal(rows.length,3);
