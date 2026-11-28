// Chromium software WebCrypto/IndexedDB evidence only, no hardware claims.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
assert(process.env.GITHUB_ACTIONS==='true' && process.env.DC_LAB_ROOT && process.env.DC_EVIDENCE);
const root=await mkdtemp(join(process.env.DC_LAB_ROOT,'browser-'));
const source=await readFile(new URL('../src/features/mobile/security/externalLabDeviceKeyCandidate.mjs',import.meta.url));
const rows=[];
function check(label,pass){rows.push({label,pass:!!pass});console.log(JSON.stringify(rows.at(-1)));assert(pass,label);}
const servers=[];
let browser;
async function serve(){
  const server=createServer((req,res)=>{
    res.setHeader('Cache-Control','no-store');
    if(req.url==='/key.mjs'){res.setHeader('Content-Type','text/javascript');res.end(source);}
    else {res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Synthetic key LAB</title>');}
  });
  servers.push(server);server.listen(0,'127.0.0.1');await once(server,'listening');
  return 'http://127.0.0.1:'+server.address().port;
}
async function start(){
  browser=spawn('google-chrome',['--headless','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--remote-debugging-port=0','--user-data-dir='+root,'about:blank'],{stdio:'ignore'});
  for(let i=0;i<100;i++){
    try{const p=(await readFile(join(root,'DevToolsActivePort'),'utf8')).split('\n')[0];const r=await fetch('http://127.0.0.1:'+p+'/json/version');if(r.ok)return 'http://127.0.0.1:'+p;}catch{}
    if(browser.exitCode!==null)throw Error('browser exited');
    await delay(100);
  }
  throw Error('browser unavailable');
}
async function stop(){
  if(browser&&browser.exitCode===null){const exited=once(browser,'exit');browser.kill('SIGTERM');await Promise.race([exited,delay(5000)]);if(browser.exitCode===null&&browser.signalCode===null){browser.kill('SIGKILL');await exited;}}
  browser=null;
  await rm(join(root,'DevToolsActivePort'),{force:true});
}
async function page(endpoint,origin){
  const target=await (await fetch(endpoint+'/json/new?'+encodeURIComponent(origin),{method:'PUT'})).json();
  const ws=new WebSocket(target.webSocketDebuggerUrl);await once(ws,'open');
  let sequence=0;
  const pending=new Map();
  ws.addEventListener('message',e=>{const m=JSON.parse(e.data);const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}});
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{
    const r=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
    if(r.exceptionDetails)throw Error('Browser evaluation failed');
    return r.result.value;
  };
  for(let i=0;i<100;i++){if(await evaluate('location.origin')===origin)break;await delay(100);}
  assert.equal(await evaluate('location.origin'),origin);
  await evaluate("globalThis.k=await import('/key.mjs'); true");
  return {evaluate,close:()=>ws.close()};
}
let a,b;
const call=(p,expr)=>p.evaluate('(async()=>{'+expr+'})()');
const denied=expr=>"try{await "+expr+";return false;}catch{return true;}";
const bytes="new TextEncoder().encode(JSON.stringify(['dc/external-lab-session/v1','synthetic']))";
try{
  const origin=await serve(),other=await serve();
  let endpoint=await start();
  a=await page(endpoint,origin);b=await page(endpoint,other);
  check('secure loopback browser context',await a.evaluate('isSecureContext'));
  check('missing key fails closed',await call(a,denied("k.getDevicePublicKey('missing')")));
  const pub=await call(a,"return await k.createDeviceKey('deviceA')");
  check('public Ed25519 raw key only',/^[0-9a-f]{64}$/.test(pub));
  check('stored public key stable',await call(a,"return await k.getDevicePublicKey('deviceA')")===pub);
  check('duplicate create refuses replacement',await call(a,denied("k.createDeviceKey('deviceA')")));
  check('wrong fingerprint refuses signing',await call(a,denied("k.signDeviceProof('deviceA',"+bytes+",'0'.repeat(64))")));
  check('unrecognized signing domain refused',await call(a,denied("k.signDeviceProof('deviceA',new TextEncoder().encode('[\"other\"]'),"+JSON.stringify(pub)+")")));
  const signature=await call(a,"return await k.signDeviceProof('deviceA',"+bytes+","+JSON.stringify(pub)+")");
  check('signature verifies under public key',await call(a,`const key=await crypto.subtle.importKey('raw',Uint8Array.from(${JSON.stringify(pub)}.match(/../g),x=>parseInt(x,16)),'Ed25519',false,['verify']);return await crypto.subtle.verify('Ed25519',key,Uint8Array.from(${JSON.stringify(signature)}.match(/../g),x=>parseInt(x,16)),${bytes});`));
  check('private CryptoKey cannot be exported or wrapped',await call(a,`const db=await new Promise((r,j)=>{const q=indexedDB.open('dc-external-lab-key-v1',1);q.onsuccess=()=>r(q.result);q.onerror=j;});const pair=await new Promise((r,j)=>{const q=db.transaction('device-keys').objectStore('device-keys').get('deviceA');q.onsuccess=()=>r(q.result);q.onerror=j;});db.close();if(pair.privateKey.extractable)return false;let denied=0;for(const format of ['pkcs8','jwk','raw']){try{await crypto.subtle.exportKey(format,pair.privateKey);}catch{denied++;}}const wrap=await crypto.subtle.generateKey({name:'AES-KW',length:256},false,['wrapKey']);try{await crypto.subtle.wrapKey('pkcs8',pair.privateKey,wrap,'AES-KW');}catch{denied++;}return denied===4;`));
  check('distinct origin has no key',await call(b,denied("k.getDevicePublicKey('deviceA')")));
  check('concurrent create only one winner',await call(a,"return (await Promise.allSettled([k.createDeviceKey('race'),k.createDeviceKey('race')])).filter(x=>x.status==='fulfilled').length===1"));
  a.close();b.close();a=b=null;await stop();
  endpoint=await start();a=await page(endpoint,origin);
  check('key persists across browser process restart',await call(a,"return await k.getDevicePublicKey('deviceA')")===pub);
  check('persisted key still signs',await call(a,"return (await k.signDeviceProof('deviceA',"+bytes+","+JSON.stringify(pub)+")).length===128"));
  await call(a,"await k.deleteDeviceKey('deviceA');return true");
  check('deleted key fails closed',await call(a,denied("k.signDeviceProof('deviceA',"+bytes+","+JSON.stringify(pub)+")")));
  a.close();a=null;await stop();endpoint=await start();a=await page(endpoint,origin);
  check('deletion persists across restart',await call(a,denied("k.getDevicePublicKey('deviceA')")));
  assert.equal(rows.length,15);
}finally{
  a?.close();b?.close();await stop();
  for(const server of servers)await new Promise(r=>server.close(r));
  await rm(root,{recursive:true,force:true});
  await writeFile(join(process.env.DC_EVIDENCE,'external-lab-browser-key.json'),JSON.stringify(rows,null,2));
}
