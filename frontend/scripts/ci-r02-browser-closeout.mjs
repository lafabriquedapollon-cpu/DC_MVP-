// Focused real Windows Chromium teardown regression, no backend or patient data.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {setTimeout as sleep} from 'node:timers/promises';
import {certifyCompanionVault,closeVaultFixture} from './ci-r02-vault.mjs';
import {bounded,detachSession,closeContext} from './ci-r02-browser-lifecycle.mjs';
const root=process.env.DC_CLOSEOUT_ROOT,tools=process.env.DC_BROWSER_TOOLS;
assert(process.platform==='win32'&&process.env.GITHUB_ACTIONS==='true'&&root&&tools);
assert(path.dirname(root).toLowerCase()===process.env.RUNNER_TEMP.toLowerCase());
assert(path.basename(root).startsWith('dc-closeout-'));
const requireTool=createRequire(path.join(tools,'package.json'));
assert.equal(requireTool('playwright-core/package.json').version,'1.61.0');
const {chromium}=requireTool('playwright-core');
// Negative case: a real incomplete HTTP request must not block close.
const server=http.createServer((req,res)=>res.end('synthetic'));
const sockets=new Set();
server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket))});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
const client=net.connect(server.address().port,'127.0.0.1');
client.on('error',()=>{});
try{
  await bounded(new Promise((resolve,reject)=>{client.once('connect',resolve);client.once('error',reject)}),3000,'TCP_CONNECT_TIMEOUT');
  client.write('GET / HTTP/1.1\r\nHost: localhost\r\n');
  for(let i=0;i<30&&!sockets.size;i++)await sleep(100);
  assert.equal(sockets.size,1);
  await closeVaultFixture(server,sockets);
  assert.equal(server.listening,false);
  console.log('R02_CLOSEOUT_HELD_HTTP_CONNECTION_PASS');
}finally{client.destroy();if(server.listening)await closeVaultFixture(server,sockets)}
const profile=path.join(root,'chrome-pipe');
assert(!fs.existsSync(profile));
const browserEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>
  ['SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS',
   'SYSTEMDRIVE','PATH','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP',
   'PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMDATA','PUBLIC','HOMEDRIVE','HOMEPATH'].includes(key.toUpperCase())));
let context;
try{
  context=await chromium.launchPersistentContext(profile,{
    headless:true,channel:'chromium',timeout:30000,viewport:{width:1440,height:900},env:browserEnv,
    proxy:{server:'http://127.0.0.1:1',bypass:'127.0.0.1,localhost,[::1]'},
    args:['--disable-background-networking','--disable-sync','--disable-quic',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1']
  });
  const page=context.pages()[0]??await context.newPage();
  const first=await context.newCDPSession(page);
  await first.send('Page.enable');
  await detachSession(first);
  const session=await context.newCDPSession(page);
  const call=(method,params={})=>bounded(session.send(method,params),10000,'CDP_CALL_TIMEOUT');
  const evalPage=async expression=>{
    const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(r.exceptionDetails)throw Error('PAGE_EVAL_FAILED');
    return r.result.value;
  };
  const wait=async(label,fn)=>{
    const end=Date.now()+10000;
    while(Date.now()<end){try{const v=await fn();if(v)return v}catch{}await sleep(100)}
    throw Error('VAULT_NAVIGATION_TIMEOUT');
  };
  await certifyCompanionVault(call,evalPage,wait);
  await detachSession(session);
  await closeContext(context);
  context=null;
  await fs.promises.rm(profile,{recursive:true,force:false,maxRetries:10,retryDelay:200});
  assert(!fs.existsSync(profile));
  console.log('R02_CLOSEOUT_PROFILE_REMOVAL_PASS');
}finally{if(context)await closeContext(context)}
console.log('R02_CLOSEOUT_REAL_BROWSER_TEARDOWN_PASS');
