// Real Chromium + isolated origin: transpile the exact standalone storage module.
// No application session is injected; these synthetic fixtures are never used to authenticate.
import http from 'node:http';
import fs from 'node:fs';
import ts from 'typescript';
import assert from 'node:assert/strict';
export async function certifyCompanionVault(call,evalPage,wait){
  const source=fs.readFileSync(new URL('../src/features/patient-companion/PatientCompanionStorage.ts',import.meta.url),'utf8');
  const result=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},reportDiagnostics:true});
  assert.equal(result.diagnostics?.length||0,0);
  const server=http.createServer((req,res)=>{
    if(req.url==='/vault.mjs'){res.writeHead(200,{'Content-Type':'text/javascript','Cache-Control':'no-store'});return res.end(result.outputText)}
    if(req.url==='/'){res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});return res.end('<!doctype html><title>Synthetic vault lab</title>')}
    res.writeHead(404);res.end();
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
  const origin='http://127.0.0.1:'+server.address().port;
  const open=async()=>{await call('Page.navigate',{url:origin+'/'});await wait('isolated vault origin',()=>evalPage('location.origin==='+JSON.stringify(origin)+' && document.title==="Synthetic vault lab"'))};
  try{
    await open();
    const initial=await evalPage(`(async()=>{
      const {PatientCompanionStorage:s}=await import('/vault.mjs');
      const check=(c)=>{if(!c)throw Error('vault check failed')};
      const id='ci-vault',upload='ci-photo',when='2030-01-01T00:00:00Z';
      await s.clear();
      check((await s.load()).pairings.length===0);
      await s.savePairing({accessToken:'SYNTHETIC-NOT-AUTH',context:{access_id:id,relationship_type:'SELF',patient:{display_name:'CI SYNTHETIC'}},pairedAt:when,expiresAt:'2030-01-02T00:00:00Z'});
      await s.saveEmergencyPhotoBytes(id,upload,new Uint8Array([7,42,99,11]));
      await s.saveEmergencyPhotoQueue(id,[{uploadId:upload,state:'local_pending',byteSize:4,capturedAt:when,createdAt:when,updatedAt:when}]);
      const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('digital-crown-patient-companion',2);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)});
      const read=(store,key)=>new Promise((resolve,reject)=>{const r=db.transaction(store).objectStore(store).get(key);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)});
      try{
        const key=await read('vault','device-aes-key'),env=await read('vault','companion-state'),media=await read('media','pc07:ci-photo');
        check(key.extractable===false&&key.algorithm.name==='AES-GCM'&&key.algorithm.length===256);
        check(env.version===1&&typeof env.ciphertext==='string'&&!JSON.stringify(env).includes('SYNTHETIC'));
        check(media.version===1&&media.iv.byteLength===12&&media.ciphertext.byteLength>4);
      }finally{db.close()}
      let denied=false;try{await s.readEmergencyPhotoBytes('wrong-context',upload)}catch{denied=true}
      check(denied);return true;
    })()`);
    assert.equal(initial,true);console.log('COMPANION_REAL_VAULT_ENCRYPTION_AAD_PASS');
    await open();
    const reloaded=await evalPage(`(async()=>{
      const {PatientCompanionStorage:s}=await import('/vault.mjs');const state=await s.load();
      const b=await s.readEmergencyPhotoBytes('ci-vault','ci-photo');
      if(state.activeAccessId!=='ci-vault'||state.cache['ci-vault'].emergencyPhotos[0].state!=='local_pending'||String(b)!=='7,42,99,11')throw Error('reload mismatch');
      await s.deleteEmergencyPhotoBytes('ci-photo');if(await s.readEmergencyPhotoBytes('ci-vault','ci-photo')!==null)throw Error('media retained');
      await s.clear();if((await s.load()).pairings.length!==0)throw Error('vault retained');return true;
    })()`);
    assert.equal(reloaded,true);console.log('COMPANION_REAL_VAULT_RELOAD_DELETE_CLEAR_PASS');
  }finally{await new Promise(resolve=>server.close(resolve))}
}
