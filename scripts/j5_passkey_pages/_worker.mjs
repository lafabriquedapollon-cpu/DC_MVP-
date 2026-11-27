// Isolated synthetic laboratory only. No real authority, storage or release access.
const html = `<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Passkey LAB</title><style nonce="NONCE">body{font:17px system-ui;max-width:560px;margin:36px auto;padding:20px;background:#f4f5f7;color:#172136}main{background:white;padding:24px;border:1px solid #ddd;border-radius:18px}button{display:block;margin:16px 0;padding:14px;width:100%;border:0;border-radius:10px;background:#183f68;color:white;font:inherit}button:disabled{opacity:.5}#status{overflow-wrap:anywhere}small{color:#526071}</style><main><small>LAB ISOLÉ · AUCUNE AUTORITÉ</small><h1>Test Passkey</h1><p>Test fictif de création et de signature. Aucune donnée patient, aucun compte GitHub, aucune release réelle.</p><button id="create">1. Créer une passkey de test</button><button id="sign" disabled>2. Signer le défi fictif</button><button id="export" disabled>3. Exporter la preuve publique</button><p id="status" role="status">Prêt.</p></main><script nonce="NONCE">
const el=id=>document.getElementById(id), enc=new TextEncoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const rand=()=>crypto.getRandomValues(new Uint8Array(32));
let reg,auth,regChallenge,authChallenge;
const rp=location.hostname;
const serialize=c=>({id:c.id,rawId:b64(c.rawId),type:c.type,response:Object.fromEntries(['clientDataJSON','attestationObject','authenticatorData','signature','userHandle'].filter(k=>c.response[k]!=null).map(k=>[k,b64(c.response[k])]))});
function fail(){el('status').textContent='Échec ou annulation. Rechargez la page pour recommencer.';el('create').disabled=true;el('sign').disabled=true;el('export').disabled=true;}
el('create').onclick=async()=>{el('create').disabled=true;try{
if(!isSecureContext||!PublicKeyCredential)throw Error();
regChallenge=rand();
reg=await navigator.credentials.create({publicKey:{challenge:regChallenge,rp:{id:rp,name:'Passkey LAB fictif'},user:{id:rand(),name:'fixture-'+b64(rand()).slice(0,12),displayName:'Test fictif'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'preferred',userVerification:'required'},attestation:'none',timeout:60000}});
if(!reg)throw Error();
el('status').textContent='Passkey de test créée. Pas encore de vérification indépendante.';el('sign').disabled=false;
}catch(e){console.warn('LAB_BROWSER_ERROR',e?.name||'Error');fail();}};
el('sign').onclick=async()=>{el('sign').disabled=true;try{
authChallenge=rand();auth=await navigator.credentials.get({publicKey:{challenge:authChallenge,rpId:rp,allowCredentials:[{type:'public-key',id:reg.rawId}],userVerification:'required',timeout:60000}});
if(!auth||auth.id!==reg.id)throw Error();
el('status').textContent='Preuve produite. Vérification indépendante requise.';el('export').disabled=false;
}catch(e){console.warn('LAB_BROWSER_ERROR',e?.name||'Error');fail();}};
el('export').onclick=()=>{const proof={domain:'DIGITAL-CROWN/PASSKEY-BROWSER-LAB/NOT-A-RELEASE/v1',rp,origin:location.origin,registrationChallenge:b64(regChallenge),authenticationChallenge:b64(authChallenge),registration:serialize(reg),authentication:serialize(auth)};const url=URL.createObjectURL(new Blob([JSON.stringify(proof)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='passkey-lab-proof.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
</script></html>`;
const headers={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Robots-Tag":"noindex, nofollow, noarchive","X-Frame-Options":"DENY","Permissions-Policy":"publickey-credentials-create=(self), publickey-credentials-get=(self)"};
function reply(status,text,extra={}){return new Response(text,{status,headers:{...headers,"Content-Type":"text/plain; charset=utf-8",...extra}});}
async function eq(a,b){const hash=async v=>new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v)));const [x,y]=await Promise.all([hash(a),hash(b)]);let n=0;for(let i=0;i<32;i++)n|=x[i]^y[i];return n===0;}
export default {async fetch(req,env){
 const url=new URL(req.url);
 if(typeof env.LAB_ORIGIN!=="string"||url.origin!==env.LAB_ORIGIN||!/^([a-f0-9]{64})$/.test(env.LAB_ACCESS_TOKEN||""))return reply(503,"LAB CLOSED");
 if(req.method!=="GET"||url.pathname!=="/"||url.search)return reply(404,"Not found");
 const expected="Basic "+btoa("lab:"+env.LAB_ACCESS_TOKEN);
 const received=req.headers.get("Authorization")||"";
 if(received.length>256||!(await eq(received,expected)))return reply(401,"Authorization required",{"WWW-Authenticate":'Basic realm="Private synthetic lab", charset="UTF-8"'});
 const nonce=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))));
 return new Response(html.replaceAll("NONCE",nonce),{headers:{...headers,"Content-Type":"text/html; charset=utf-8","Content-Security-Policy":"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}});
}};
