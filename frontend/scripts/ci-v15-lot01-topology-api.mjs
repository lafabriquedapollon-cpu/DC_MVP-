// Isolated CI-only, real FastAPI/SQLCipher, real desktop sessions and ECDH pairing.
// No patient fixtures, token minting, credential logging or mocked authorization.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createECDH} from 'node:crypto';
const base='http://127.0.0.1:8008';
assert(process.env.GITHUB_ACTIONS==='true'&&process.env.DC_SYNTH_PASSWORD&&process.env.DC_EVIDENCE);
const evidence=[];
const scope=process.env.DC_TEST_SCOPE;assert(['stock-session','platform-desktop'].includes(scope),'explicit isolated test scope required');
const request=async(label,path,{method='GET',headers={},body,status}={})=>{
 const r=await fetch(base+path,{method,headers:{...headers,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
 const row={label,method,status:r.status,expected:status,pass:r.status===status};evidence.push(row);console.log('LOT01_STOCK_CASE '+JSON.stringify(row));
 assert.equal(r.status,status,label);
 return {body:await r.json().catch(()=>null),cookies:r.headers.getSetCookie(),retryAfter:r.headers.get('Retry-After')};
};
const bearer=t=>({Authorization:'Bearer '+t});
const login=async email=>{
 const r=await fetch(base+'/api/auth/login',{method:'POST',body:new URLSearchParams({username:email,password:process.env.DC_SYNTH_PASSWORD})});
 assert.equal(r.status,200,'synthetic login');const b=await r.json();assert(b.access_token&&b.refresh_token);return b;
};
const register=async t=>{
 const state=await request('desktop workstation registration','/api/workstation/state',{headers:bearer(t),status:200});
 const c=state.cookies.find(c=>c.startsWith('dc_workstation=')&&/httponly/i.test(c));assert(c);
 return {...bearer(t),Cookie:c.split(';')[0]};
};
const staff=async(email,cookie)=>{
 const token=await login(email);const headers={...bearer(token.access_token),Cookie:cookie};
 const me=await request('staff identity','/api/auth/me',{headers,status:200});assert(Number.isInteger(me.body.id));
 return {headers,id:me.body.id,token};
};
const pair=async(owner,target,replayStatus=404)=>{
 const issue=await request('owner issues authorized Pocket pairing','/api/mobile/bridge-pairing',{method:'POST',headers:owner,body:{target_user_id:target,destination:'agenda'},status:200});
 assert(issue.body.token_code&&issue.body.target_user_id===target&&issue.body.contains_patient_data===false);
 const key=createECDH('prime256v1');key.generateKeys();
 const claim={token:issue.body.token_code,client_public_key_hex:key.getPublicKey('hex','uncompressed')};
 const paired=await request('real ECDH Pocket claim','/api/mobile/claim-token',{method:'POST',body:claim,status:200});
 assert(paired.body.access_token&&paired.body.refresh_token&&paired.body.user_id===target&&paired.body.server_public_key_hex&&paired.body.encrypted_master_key_hex);
 // Same real loopback client: first two replays prove one-shot consumption (404).
 // The sixth claim attempt must trigger the unmodified server's five-attempt limit.
 const replay=await request(replayStatus===429?'sixth pairing request rate limited':'one-shot pairing replay refused','/api/mobile/claim-token',{method:'POST',body:claim,status:replayStatus});
 if(replayStatus===429){const seconds=Number(replay.retryAfter);assert(Number.isInteger(seconds)&&seconds>=1&&seconds<=600,'Retry-After contract');console.log('LOT01_PAIRING_RATE_LIMIT_PASS');}
 assert(!replay.body?.access_token&&!replay.body?.refresh_token,'refusal must not issue credentials');
 return paired.body;
};
// Actual FastAPI/SQLCipher topology and annex workstation contract; not physical LAN.
const W='/api/workstation';
try{
 const health=await request('actual topology diagnostic','/api/health/topology',{status:200});
 assert.equal(health.body.status,'ok');assert.equal(health.body.lanExposed,false);
 assert.equal(health.body.connectionUrl,null);assert.equal(health.body.remediation,'LAN_DISABLED_LOOPBACK_ONLY');
 const owner=await login('ci-owner@example.com'),other=await login('ci-other@example.com');
 const A=await register(owner.access_token),B=await register(other.access_token);
 const pin=String(100000+Math.floor(Math.random()*900000));
 await request('owner PIN setup',W+'/owner-pin',{method:'POST',headers:A,body:{accountPassword:process.env.DC_SYNTH_PASSWORD,newPin:pin},status:200});
 const issue=await request('single-use annex code issue',W+'/pairing-code',{method:'POST',headers:A,body:{ownerPin:pin},status:200});
 const fresh=await login('ci-owner@example.com');
 const F=bearer(fresh.access_token);
 const bootstrap=await request('unregistered annex bootstrap',W+'/bootstrap',{headers:F,status:200});
 assert.equal(bootstrap.body.workstationId,null);
 const claimed=await request('annex claims code',W+'/pair',{method:'POST',headers:F,body:{code:issue.body.code,displayName:'CI Synthetic Annex'},status:200});
 const cookie=claimed.cookies.find(c=>c.startsWith('dc_workstation='));assert(cookie);
 const H={...F,Cookie:cookie.split(';')[0]};
 const registered=await request('annex registered state',W+'/state',{headers:H,status:200});
 assert(registered.body.workstationId);const id=registered.body.workstationId;
 const duplicate=await login('ci-owner@example.com');
 await request('used annex code replay denied',W+'/pair',{method:'POST',headers:bearer(duplicate.access_token),body:{code:issue.body.code,displayName:'CI Replay'},status:403});
 const own=await request('owner registry',W+'/registry',{headers:A,status:200});assert(own.body.some(x=>x.workstationId===id));
 const oth=await request('other tenant registry isolated',W+'/registry',{headers:B,status:200});assert(!oth.body.some(x=>x.workstationId===id));
 await request('annex revoke',W+'/'+id+'/revoke',{method:'POST',headers:A,body:{ownerPin:pin},status:200});
 const after=await request('revocation persisted in registry',W+'/registry',{headers:A,status:200});assert(after.body.some(x=>x.workstationId===id&&x.revoked===true));
 await request('other tenant remains operational','/api/auth/me',{headers:B,status:200});
}finally{fs.writeFileSync(process.env.DC_EVIDENCE+'/topology-api.json',JSON.stringify(evidence,null,2))}
