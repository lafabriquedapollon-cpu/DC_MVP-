// CI-only persistent Chromium via Playwright's private debugging pipe.
// The real CDP test driver remains unchanged in its assertions.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {setTimeout as sleep} from 'node:timers/promises';

const root=process.env.DC_LAB_ROOT;
const tools=process.env.DC_BROWSER_TOOLS;
assert(process.platform==='win32' && process.env.GITHUB_ACTIONS==='true' &&
  process.env.DC_PACKAGED_DESKTOP==='true' && root && tools);
assert(path.dirname(root).toLowerCase()===process.env.RUNNER_TEMP.toLowerCase());
assert(path.basename(root).startsWith('dc-backend-rehearsal-'));
const requireTool=createRequire(path.join(tools,'package.json'));
assert.equal(requireTool('playwright-core/package.json').version,'1.61.0');
const {chromium}=requireTool('playwright-core');
const profile=path.join(root,'chrome-pipe');
assert(!fs.existsSync(profile));
const browserEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>
  ['SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS',
   'SYSTEMDRIVE','PATH','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP',
   'PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMDATA','PUBLIC','HOMEDRIVE','HOMEPATH'].includes(key.toUpperCase())));
let context,phase='LAUNCH';
async function runDriver(page,restart){
  const session=await context.newCDPSession(page);
  globalThis.__dcDesktopCDP=session;
  const old=process.argv;
  try{
    process.argv=restart?[...old,'--verify-restart']:old;
    process.exitCode=0;
    await import('./ci-desktop-integration.mjs?phase='+(restart?'restart':'first'));
    assert.equal(process.exitCode,0,'DESKTOP_DRIVER_FAILED');
  }finally{
    process.argv=old;
    delete globalThis.__dcDesktopCDP;
    await session.detach().catch(()=>{});
  }
}
try{
  context=await chromium.launchPersistentContext(profile,{
    headless:true,channel:'chromium',timeout:30000,
    viewport:{width:1440,height:900},env:browserEnv,
    proxy:{server:'http://127.0.0.1:1',bypass:'127.0.0.1,localhost,[::1]'},
    args:['--disable-background-networking','--disable-sync','--disable-quic',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1'],
  });
  const page=context.pages()[0]??await context.newPage();
  console.log('R02_DESKTOP_PIPE_BROWSER_LAUNCH_PASS');
  phase='FIRST';
  await runDriver(page,false);
  fs.writeFileSync(path.join(root,'browser-first-pass'),'',{flag:'wx'});
  phase='WAIT_RESTART';
  const signal=path.join(root,'browser-restart-ready');
  const deadline=Date.now()+90000;
  while(!fs.existsSync(signal)&&Date.now()<deadline)await sleep(250);
  assert(fs.existsSync(signal),'RESTART_SIGNAL_TIMEOUT');
  phase='RESTART';
  await runDriver(page,true);
  fs.writeFileSync(path.join(root,'browser-restart-pass'),'',{flag:'wx'});
  console.log('R02_DESKTOP_PIPE_BROWSER_RESTART_PASS');
}catch(error){
  const type=/^[A-Za-z0-9_]+$/.test(error?.name??'')?error.name:'Unknown';
  console.log('R02_DESKTOP_PIPE_FAILURE phase='+phase+' type='+type);
  process.exitCode=1;
}finally{
  if(context)await context.close();
}
