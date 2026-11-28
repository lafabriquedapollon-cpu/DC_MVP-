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
// Synthetic API-only theme persistence and tenant isolation. Key never logged.
import {createDecipheriv} from 'node:crypto';
const P='/api/clinics/me',M='/api/clinics/mobile-theme';
function decrypt(b){
 assert.deepEqual(Object.keys(b),['payload']);
 const raw=Buffer.from(b.payload,'base64');
 const key=Buffer.from(process.env.MOBILE_PAIRING_KEY_HEX,'hex');
 assert.equal(key.length,32);
 const d=createDecipheriv('aes-256-gcm',key,raw.subarray(0,12));d.setAuthTag(raw.subarray(-16));
 return JSON.parse(Buffer.concat([d.update(raw.subarray(12,-16)),d.final()]));
}
try{
 const owner=await login('ci-owner@example.com'),other=await login('ci-other@example.com');
 const A=await register(owner.access_token),B=await register(other.access_token);
 const restricted=await staff('ci-restricted@example.com',A.Cookie);
 const own=await request('owner identity','/api/auth/me',{headers:A,status:200});
 const oth=await request('other owner identity','/api/auth/me',{headers:B,status:200});
 const initialA=await request('initial A profile',P,{headers:A,status:200});
 const initialB=await request('initial B profile',P,{headers:B,status:200});
 const a=await pair(A,own.body.id),b=await pair(B,oth.body.id);
 const R=bearer(a.access_token),S=bearer(b.access_token);
 const colorsA={selected_theme:'rose',primary_color:'#777777',secondary_color:'#123456',accent_color:'#ff0099'};
 const colorsB={selected_theme:'ocean',primary_color:'#0080ff',secondary_color:'#654321',accent_color:'#808080'};
 const match=(actual,expected)=>{for(const [k,v] of Object.entries(expected))assert.equal(actual[k],v,k)};
 await request('anonymous theme write denied',P,{method:'PUT',body:colorsA,status:401});
 await request('restricted theme write denied',P,{method:'PUT',headers:restricted.headers,body:colorsA,status:403});
 await request('Pocket token cannot update Desktop organization',P,{method:'PUT',headers:R,body:colorsA,status:401});
 match((await request('A organization saves theme',P,{method:'PUT',headers:A,body:colorsA,status:200})).body,colorsA);
 match((await request('A organization rereads theme',P,{headers:A,status:200})).body,colorsA);
 match((await request('B unchanged after A write',P,{headers:B,status:200})).body,{selected_theme:initialB.body.selected_theme,primary_color:initialB.body.primary_color});
 match((await request('B organization saves theme',P,{method:'PUT',headers:B,body:colorsB,status:200})).body,colorsB);
 match(decrypt((await request('Pocket A receives encrypted A theme',M,{headers:R,status:200})).body),colorsA);
 match(decrypt((await request('Pocket B receives encrypted B theme',M,{headers:S,status:200})).body),colorsB);
 await request('Desktop JWT denied mobile theme',M,{headers:A,status:401});
 await request('anonymous mobile theme denied',M,{status:422});
 await request('A paired device revoke','/api/mobile/revoke-device',{method:'POST',headers:R,status:200});
 await request('A revoked device theme denied',M,{headers:R,status:401});
 match(decrypt((await request('B device still receives B theme',M,{headers:S,status:200})).body),colorsB);
 match((await request('A theme still persisted',P,{headers:A,status:200})).body,colorsA);
 // LAB is ephemeral; restore initial organization values before disposal.
 for(const [headers,init] of [[A,initialA.body],[B,initialB.body]]){
  const original=Object.fromEntries(Object.keys(colorsA).map(k=>[k,init[k]]));
  await request('restore synthetic original theme',P,{method:'PUT',headers,body:original,status:200});
 }
}finally{fs.writeFileSync(process.env.DC_EVIDENCE+'/theme-api.json',JSON.stringify(evidence,null,2))}
