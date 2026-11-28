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
// Real synthetic patient local pairing and cross-channel JWT refusals.
const P='/api/patient-companion';
try{
 const owner=await login('ci-owner@example.com'),other=await login('ci-other@example.com');
 const A=await register(owner.access_token),B=await register(other.access_token);
 const staffUser=await staff('ci-stock-reader@example.com',A.Cookie);
 const own=await request('B owner identity','/api/auth/me',{headers:A,status:200});
 const paired=await pair(A,staffUser.id);
 const M=bearer(paired.access_token);
 const create=async(headers,name)=>(await request('create synthetic patient','/api/patients/',{method:'POST',headers,body:{nom:'CI-SYNTHETIC',prenom:name,date_naissance:'2000-01-01',sexe:'M'},status:200})).body;
 const a=await create(A,'FixtureA'),b=await create(B,'FixtureB');
 assert(a.employer_id!==b.employer_id);
 const invite=async(headers,id)=>(await request('authorized local patient invitation',P+'/admin/patients/'+id+'/local-invitation',{method:'POST',headers,body:{relationship_type:'SELF'},status:201})).body;
 await request('cross tenant invitation denied',P+'/admin/patients/'+b.id+'/local-invitation',{method:'POST',headers:A,body:{relationship_type:'SELF'},status:404});
 const ia=await invite(A,a.id),ib=await invite(B,b.id);
 const claim=async(i)=>(await request('real local patient pairing',P+'/pair',{method:'POST',body:{manual_code:i.manual_code},status:201})).body;
 const pa=await claim(ia),pb=await claim(ib);
 const R=bearer(pa.access_token),S=bearer(pb.access_token),x=pa.context.access_id,y=pb.context.access_id;
 assert(x!==y&&pa.remote_transport.status==='not_enrolled'&&pb.remote_transport.status==='not_enrolled');
 await request('used patient invitation denied',P+'/pair',{method:'POST',body:{manual_code:ia.manual_code},status:400});
 for(const [headers,id] of [[R,x],[S,y]]){
  const me=await request('patient own context',P+'/me',{headers,status:200});assert.equal(me.body.contexts.length,1);assert.equal(me.body.contexts[0].access_id,id);
  await request('patient own capability',P+'/contexts/'+id+'/capabilities',{headers,status:200});
 }
 await request('patient A denied B context',P+'/contexts/'+y+'/capabilities',{headers:R,status:404});
 await request('patient B denied A context',P+'/contexts/'+x+'/capabilities',{headers:S,status:404});
 await request('Desktop JWT cannot become patient',P+'/me',{headers:A,status:401});
 await request('Pocket staff JWT cannot become patient',P+'/me',{headers:M,status:401});
 await request('patient JWT cannot enter Desktop','/api/auth/me',{headers:R,status:401});
 await request('patient JWT cannot enter Pocket staff stock','/api/mobile/stock/items',{headers:R,status:401});
 await request('patient JWT cannot enter platform','/api/mobile/superadmin/clients',{headers:R,status:401});
 await request('patient A still has own access',P+'/me',{headers:R,status:200});
}finally{fs.writeFileSync(process.env.DC_EVIDENCE+'/patient-boundary.json',JSON.stringify(evidence,null,2))}
