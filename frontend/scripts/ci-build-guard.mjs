// CI-only contract test. All subprocesses use a disposable tree and fake compilers;
// the real rehearsal compiler is exercised separately by the workflow.
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,copyFileSync,rmSync,existsSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createServer} from 'node:net';
assert.equal(process.env.GITHUB_ACTIONS,'true');
const root=mkdtempSync(path.join(tmpdir(),'dc-build-guard-'));
const guard=path.join(root,'scripts','build-guard.mjs');
const bin=path.join(root,'bin');
mkdirSync(path.dirname(guard));mkdirSync(bin);
copyFileSync(fileURLToPath(new URL('./build-guard.mjs',import.meta.url)),guard);
const marker=path.join(root,'calls');
for(const tool of ['tsc','vite']){
  writeFileSync(path.join(bin,tool),'#!/bin/sh\nprintf "%s|%s|%s\\n" "$(basename "$0")" "$*" "${VITE_API_URL-unset}" >> "$DC_CALLS"\n',{mode:0o700});
}
const env={...process.env,PATH:bin+path.delimiter+process.env.PATH,DC_CALLS:marker,VITE_API_URL:'http://127.0.0.1:8008'};
delete env.CONFIRM_REAL_BUILD;
const invoke=(mode,extra={})=>spawnSync(process.execPath,[guard,mode],{cwd:root,env:{...env,...extra},encoding:'utf8',timeout:20000});
const blocked=(mode,extra={})=>{const r=invoke(mode,extra);assert.equal(r.status,1,r.stdout+r.stderr);assert(!existsSync(marker));};
const ok=(mode,out,extra={})=>{const r=invoke(mode,extra);assert.equal(r.status,0,r.stdout+r.stderr);const m=JSON.parse(readFileSync(path.join(root,out,'build-manifest.json')));assert.equal(m.mode,mode);assert.equal(m.outputDir,out);const calls=readFileSync(marker,'utf8');assert(calls.includes('vite|build --outDir '+out+'|'));rmSync(marker);return calls;};
const server=createServer(s=>s.end());
try{
  mkdirSync(path.join(root,'dist'));writeFileSync(path.join(root,'dist','sentinel'),'preserve');
  blocked('constructor');blocked('invalid');blocked('real');
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(8005,'127.0.0.1',resolve);});
  blocked('safe');blocked('real',{CONFIRM_REAL_BUILD:'yes'});
  ok('rehearsal','dist-rehearsal');ok('test','dist-test');
  assert.equal(readFileSync(path.join(root,'dist','sentinel'),'utf8'),'preserve');
  await new Promise(resolve=>server.close(resolve));
  rmSync(path.join(root,'dist-test'),{recursive:true});symlinkSync(path.join(root,'dist'),path.join(root,'dist-test'),'dir');
  blocked('test');rmSync(path.join(root,'dist-test'));
  assert.equal(readFileSync(path.join(root,'dist','sentinel'),'utf8'),'preserve');
  // Fake compiler only: real-mode environment contract, never a real cabinet build.
  const calls=ok('real','dist',{CONFIRM_REAL_BUILD:'yes'});
  assert(calls.includes('vite|build --outDir dist|\n'));
  console.log('BUILD_GUARD_CONTRACT_PASS');
}finally{if(server.listening)await new Promise(resolve=>server.close(resolve));rmSync(root,{recursive:true,force:true});}
