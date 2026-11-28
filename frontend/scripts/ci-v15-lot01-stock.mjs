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
const D='/api/stock/items',M='/api/mobile/stock/items';
const item={nom:'CI-SYNTHETIC-STOCK',categorie:'CONSOMMABLE',quantite:10,seuil_alerte:2,unite:'unité'};
try{
 if(scope==='stock-session'){
 const owner=await login('ci-owner@example.com'),other=await login('ci-other@example.com');
 const A=await register(owner.access_token),B=await register(other.access_token);
 const reader=await staff('ci-stock-reader@example.com',A.Cookie),writer=await staff('ci-stock-writer@example.com',A.Cookie),restricted=await staff('ci-restricted@example.com',A.Cookie);
 const own=await request('owner identity','/api/auth/me',{headers:A,status:200});const oth=await request('other owner identity','/api/auth/me',{headers:B,status:200});
 await request('anonymous desktop list denied',D,{status:401});
 await request('restricted desktop list denied',D,{headers:restricted.headers,status:403});
 await request('reader desktop list',D,{headers:reader.headers,status:200});
 await request('reader desktop creation refused',D,{method:'POST',headers:reader.headers,body:item,status:403});
 const created=await request('writer desktop creation allowed',D,{method:'POST',headers:writer.headers,body:item,status:201});const id=created.body.id;assert(Number.isInteger(id));
 await request('reader desktop patch denied',D+'/'+id,{method:'PATCH',headers:reader.headers,body:{quantite:99},status:403});
 await request('reader desktop deletion denied',D+'/'+id,{method:'DELETE',headers:reader.headers,status:403});
 const otherList=await request('other cabinet stock isolated',D,{headers:B,status:200});assert(!otherList.body.some(x=>x.id===id));
 await request('cross-tenant desktop mutation denied',D+'/'+id,{method:'PATCH',headers:B,body:{quantite:99},status:404});
 await request('cross-tenant desktop deletion denied',D+'/'+id,{method:'DELETE',headers:B,status:404});
 // Validate actual paired identities and authorization, not manufactured JWTs.
 const readerPocket=await pair(A,reader.id),writerPocket=await pair(A,writer.id),otherPocket=await pair(B,oth.body.id,429);
 const R=bearer(readerPocket.access_token),W=bearer(writerPocket.access_token),O=bearer(otherPocket.access_token);
 await request('desktop JWT cannot enter Pocket stock',M,{headers:A,status:401});
 await request('Pocket JWT cannot enter desktop stock',D,{headers:R,status:401});
 const readAccess=await request('reader Pocket capability','/api/mobile/stock/access',{headers:R,status:200});assert.equal(readAccess.body.can_write,false);
 const writeAccess=await request('writer Pocket capability','/api/mobile/stock/access',{headers:W,status:200});assert.equal(writeAccess.body.can_write,true);
 await request('reader Pocket read',M,{headers:R,status:200});
 await request('reader Pocket POST denied',M,{method:'POST',headers:R,body:item,status:403});
 await request('reader Pocket PATCH denied',M+'/'+id,{method:'PATCH',headers:R,body:{quantite:99},status:403});
 const isolated=await request('other Pocket list isolated',M,{headers:O,status:200});assert(!isolated.body.some(x=>x.id===id));
 await request('other Pocket mutation denied',M+'/'+id,{method:'PATCH',headers:O,body:{quantite:99},status:404});
 const unchanged=await request('denied operations preserved exact quantity',D,{headers:A,status:200});assert.equal(unchanged.body.length,1);assert.equal(unchanged.body.find(x=>x.id===id).quantite,10);
 const changed=await request('writer Pocket mutation allowed',M+'/'+id,{method:'PATCH',headers:W,body:{quantite:12},status:200});assert.equal(changed.body.quantite,12);
 const persisted=await request('desktop reads actual Pocket mutation',D,{headers:A,status:200});assert.equal(persisted.body.find(x=>x.id===id).quantite,12);
 await request('revoke reader paired device','/api/mobile/revoke-device',{method:'POST',headers:R,status:200});
 await request('revoked Pocket token denied',M,{headers:R,status:401});
 await request('revoked Pocket refresh denied','/api/mobile/refresh-token',{method:'POST',body:{refresh_token:readerPocket.refresh_token},status:401});
 await request('writer device unaffected',M,{headers:W,status:200});
 await request('writer desktop cleanup',D+'/'+id,{method:'DELETE',headers:writer.headers,status:204});
 const empty=await request('stock empty after cleanup',D,{headers:A,status:200});assert.equal(empty.body.length,0);
 console.log('LOT01_STOCK_CONTRACT_PASS '+evidence.length);
 // Additional R2 scope: actual desktop session lifecycle and team authority.
 const T='/api/team', S='/api/superadmin/clients';
 const team=await request('owner may read own team',T+'/',{headers:A,status:200});
 assert(team.body.some(x=>x.id===reader.id)&&team.body.some(x=>x.id===writer.id));
 const otherTeam=await request('other owner team isolated',T+'/',{headers:B,status:200});
 assert(!otherTeam.body.some(x=>x.id===reader.id||x.id===writer.id));
 await request('anonymous team access denied',T+'/',{status:401});
 await request('staff team access denied',T+'/',{headers:reader.headers,status:403});
 await request('staff self escalation denied',T+'/'+reader.id,{method:'PUT',headers:reader.headers,body:{permissions:{patients:true,stock_write:true,admin:true}},status:403});
 await request('other owner cannot change staff rights',T+'/'+reader.id,{method:'PUT',headers:B,body:{permissions:{patients:true,stock_write:true}},status:404});
 await request('other owner cannot archive staff',T+'/'+reader.id,{method:'DELETE',headers:B,status:404});
 await request('owner cannot inject privileged role',T+'/'+reader.id,{method:'PUT',headers:A,body:{role:'ADMIN',is_superadmin:true},status:422});
 // Parallel B: unknown identity labels cannot be introduced as clinical staff roles.
 for(const role of ['TECHNIQUE','LABO','PROTHESISTE','PATIENT','SUPERADMIN']){
   await request('B owner cannot inject role '+role,T+'/'+reader.id,{method:'PUT',headers:A,body:{role},status:422});
 }
 const unchangedReader=await request('reader privileges unchanged','/api/auth/me',{headers:reader.headers,status:200});
 assert.equal(unchangedReader.body.role,'SECRETAIRE');assert.equal(unchangedReader.body.is_superadmin,false);assert.equal(unchangedReader.body.permissions.stock_write,false);
 await request('ordinary owner not SuperAdmin',S,{headers:A,status:403});
 await request('staff not SuperAdmin',S,{headers:reader.headers,status:403});
 await request('Pocket JWT not Desktop SuperAdmin',S,{headers:W,status:401});
 await request('refresh JWT not desktop access','/api/auth/me',{headers:bearer(reader.token.refresh_token),status:401});
 await request('access JWT not refresh','/api/auth/refresh',{method:'POST',body:{refresh_token:reader.token.access_token},status:401});
 const rotated=await request('desktop refresh rotation','/api/auth/refresh',{method:'POST',body:{refresh_token:reader.token.refresh_token},status:200});
 assert(rotated.body.access_token!==reader.token.access_token&&rotated.body.refresh_token!==reader.token.refresh_token);
 const rotatedHeaders={...bearer(rotated.body.access_token),Cookie:A.Cookie};
 const rotatedIdentity=await request('rotated session same staff','/api/auth/me',{headers:rotatedHeaders,status:200});assert.equal(rotatedIdentity.body.id,reader.id);
 await request('used refresh replay refused','/api/auth/refresh',{method:'POST',body:{refresh_token:reader.token.refresh_token},status:401});
 await request('desktop explicit logout','/api/auth/logout',{method:'POST',headers:rotatedHeaders,body:{refresh_token:rotated.body.refresh_token},status:204});
 await request('logged out access token revoked','/api/auth/me',{headers:rotatedHeaders,status:401});
 await request('logged out refresh token revoked','/api/auth/refresh',{method:'POST',body:{refresh_token:rotated.body.refresh_token},status:401});
 // Authorization is re-evaluated server-side for existing, not reissued, tokens.
 const lowered=await request('owner removes Stock mutation grant',T+'/'+writer.id,{method:'PUT',headers:A,body:{permissions:{agenda:true,patients:true,stock_write:false}},status:200});assert.equal(lowered.body.permissions.stock_write,false);
 await request('existing Desktop session loses write',D,{method:'POST',headers:writer.headers,body:item,status:403});
 const loweredMobile=await request('existing Pocket capability changes','/api/mobile/stock/access',{headers:W,status:200});assert.equal(loweredMobile.body.can_write,false);
 await request('existing Pocket session loses write',M,{method:'POST',headers:W,body:item,status:403});
 const stillEmpty=await request('denied writes left inventory empty',D,{headers:A,status:200});assert.equal(stillEmpty.body.length,0);
 await request('owner archives synthetic staff',T+'/'+writer.id,{method:'DELETE',headers:A,status:204});
 await request('archived Desktop access refused','/api/auth/me',{headers:writer.headers,status:401});
 await request('archived Desktop refresh refused','/api/auth/refresh',{method:'POST',body:{refresh_token:writer.token.refresh_token},status:401});
 await request('archived Pocket access refused',M,{headers:W,status:401});
 await request('archived Pocket refresh refused','/api/mobile/refresh-token',{method:'POST',body:{refresh_token:writerPocket.refresh_token},status:401});
 const finalTeam=await request('owner team remains accessible',T+'/',{headers:A,status:200});assert(finalTeam.body.some(x=>x.id===reader.id));assert(!finalTeam.body.some(x=>x.id===writer.id&&!x.is_archived));
 await request('other cabinet unaffected',D,{headers:B,status:200});
 console.log('LOT01_SESSION_TEAM_CONTRACT_PASS '+evidence.length);
 assert.equal(evidence.length,81);
 }else{
 // Fresh independent runner, database, rate-limit store and credentials.
 const owner=await login('ci-owner@example.com'), other=await login('ci-other@example.com');
 const A=await register(owner.access_token), B=await register(other.access_token);
 const reader=await staff('ci-stock-reader@example.com',A.Cookie), writer=await staff('ci-stock-writer@example.com',A.Cookie);
 const own=await request('owner identity','/api/auth/me',{headers:A,status:200});const oth=await request('other owner identity','/api/auth/me',{headers:B,status:200});
 const ordinaryPocket=await pair(B,oth.body.id), O=bearer(ordinaryPocket.access_token);
 const S='/api/superadmin/clients';
 // Platform identity is a synthetic LAB-only configuration, never the real operator.
 const platform=await login('ci-platform-admin@example.com'), P=await register(platform.access_token);
 const identity=await request('configured platform identity','/api/auth/me',{headers:P,status:200});
 assert.equal(identity.body.is_superadmin,true);assert.equal(identity.body.role,'ADMIN');
 const clients=await request('real platform client directory',S,{headers:P,status:200});
 assert(clients.body.some(x=>x.id===own.body.id)&&clients.body.some(x=>x.id===oth.body.id));
 assert(!clients.body.some(x=>x.id===reader.id||x.id===writer.id));
 assert(clients.body.every(x=>x.stats?.total_patients===0));
 await request('platform trial codes read','/api/superadmin/trial-codes',{headers:P,status:200});
 const overview='/api/superadmin/marketplace/overview';
 await request('platform marketplace read',overview,{headers:P,status:200});
 await request('owner marketplace read denied',overview,{headers:A,status:403});
 await request('ordinary paired staff marketplace denied',overview,{headers:O,status:403});
 await request('anonymous platform directory denied',S,{status:401});
 // R5 characterization: verify actual route availability on the recovered runtime.
 // These are baseline observations, not qualification of WebAuthn or Pocket SuperAdmin.
 await request('R5 baseline paired Pocket cannot read desktop directory',S,{headers:O,status:401});
 await request('R5 baseline paired Pocket cannot read desktop trials','/api/superadmin/trial-codes',{headers:O,status:401});
 await request('R5 baseline passkey status route mounted','/api/mobile/passkey/status',{headers:O,status:200});
 await request('R5 baseline passkey authentication rejects missing origin','/api/mobile/passkey/authentication/options',{method:'POST',headers:O,status:409});
 await request('R5 baseline anonymous passkey status missing credentials','/api/mobile/passkey/status',{status:422});
 // No license activation, supplier mutation, real OTP, Firebase or email calls.
 await request('platform logout','/api/auth/logout',{method:'POST',headers:P,body:{refresh_token:platform.refresh_token},status:204});
 await request('revoked platform directory access denied',S,{headers:P,status:401});
 await request('revoked platform refresh denied','/api/auth/refresh',{method:'POST',body:{refresh_token:platform.refresh_token},status:401});
 console.log('LOT01_PLATFORM_DESKTOP_CONTRACT_PASS '+evidence.length);
 assert.equal(evidence.length,25);
 console.log('LOT01_R5_BASELINE_CHARACTERIZATION_PASS cases=5');
 }
}finally{fs.writeFileSync(process.env.DC_EVIDENCE+'/stock-r0-status.json',JSON.stringify(evidence,null,2))}
