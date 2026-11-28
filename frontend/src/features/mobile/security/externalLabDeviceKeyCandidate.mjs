// Unmounted LAB candidate. Browser-origin isolation, not a hardware keystore.
// No raw private key or token export, no fallback to JS keys/localStorage.
// Same-origin script execution can still invoke signing; XSS is a separate gate.
const DB = 'dc-external-lab-key-v1';
const STORE = 'device-keys';
const refuse = () => { throw new Error('Device key unavailable'); };
const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,'0')).join('');
function guard(id) {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle || !globalThis.indexedDB ||
      typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(id)) refuse();
}
function open() {
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(DB,1);
    req.onupgradeneeded=()=>req.result.createObjectStore(STORE);
    req.onerror=()=>reject(new Error('Device key unavailable'));
    req.onblocked=()=>reject(new Error('Device key unavailable'));
    req.onsuccess=()=>resolve(req.result);
  });
}
async function operation(mode, fn) {
  const db=await open();
  try {
    return await new Promise((resolve,reject)=>{
      const tx=db.transaction(STORE,mode);
      let result;
      tx.oncomplete=()=>resolve(result);
      tx.onabort=tx.onerror=()=>reject(new Error('Device key unavailable'));
      try {
        const request=fn(tx.objectStore(STORE));
        request.onsuccess=()=>{result=request.result;};
      } catch {tx.abort();}
    });
  } finally {db.close();}
}
function valid(pair) {
  return pair?.privateKey instanceof CryptoKey && pair.publicKey instanceof CryptoKey &&
    pair.privateKey.type==='private' && pair.privateKey.algorithm.name==='Ed25519' &&
    pair.privateKey.extractable===false && pair.privateKey.usages.length===1 &&
    pair.privateKey.usages[0]==='sign' && pair.publicKey.type==='public' &&
    pair.publicKey.algorithm.name==='Ed25519' && pair.publicKey.usages.length===1 &&
    pair.publicKey.usages[0]==='verify';
}
async function load(id) {
  guard(id);
  const pair=await operation('readonly',s=>s.get(id));
  if (!valid(pair)) refuse();
  return pair;
}
async function publicHex(pair) {
  return hex(await crypto.subtle.exportKey('raw',pair.publicKey));
}
export async function createDeviceKey(id) {
  guard(id);
  const pair=await crypto.subtle.generateKey('Ed25519',false,['sign','verify']);
  if (!valid(pair)) refuse();
  // add rather than put: no silent replacement even in concurrent tabs.
  await operation('readwrite',s=>s.add(pair,id));
  return publicHex(await load(id));
}
export async function getDevicePublicKey(id) {
  return publicHex(await load(id));
}
export async function signDeviceProof(id, messageBytes, expectedPublicKey) {
  const pair=await load(id);
  if (typeof expectedPublicKey!=='string'||! /^[0-9a-f]{64}$/.test(expectedPublicKey)||
      await publicHex(pair)!==expectedPublicKey) refuse();
  if (!(messageBytes instanceof Uint8Array)||messageBytes.length<1||messageBytes.length>2048) refuse();
  let data;
  try {data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(messageBytes));} catch {refuse();}
  if (!Array.isArray(data)||!['dc/external-lab-enrollment/v1','dc/external-lab-session/v1','dc/external-device-read/v1'].includes(data[0])) refuse();
  // The enrollment message includes the approved public key.
  if (data[0]==='dc/external-lab-enrollment/v1' && data[4]!==expectedPublicKey) refuse();
  const signature=await crypto.subtle.sign('Ed25519',pair.privateKey,messageBytes);
  if (!await crypto.subtle.verify('Ed25519',pair.publicKey,signature,messageBytes)) refuse();
  return hex(signature);
}
export async function deleteDeviceKey(id) {
  guard(id);
  await operation('readwrite',s=>s.delete(id));
}
