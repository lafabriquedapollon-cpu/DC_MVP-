import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const dist='dist-rehearsal';
const manifest=JSON.parse(fs.readFileSync(dist+'/manifest.json','utf8'));
assert.equal(manifest.start_url,'/?source=pwa');
assert.equal(manifest.display,'standalone');
for(const icon of manifest.icons){
  const b=fs.readFileSync(dist+icon.src);
  assert.equal(b.subarray(0,8).toString('hex'),'89504e470d0a1a0a');
  assert.equal(icon.sizes,b.readUInt32BE(16)+'x'+b.readUInt32BE(20));
}
for(const name of ['logo.svg','logo.png','push-sw.js','pwa-sw.js'])assert(fs.existsSync(dist+'/'+name),name);
const sw=fs.readFileSync(dist+'/pwa-sw.js','utf8');
assert(sw.includes('push-sw.js'));
const callbacks=new Map(),shown=[],opened=[];
let focused=0,closed=0,windows=[];
const self={location:{origin:'http://127.0.0.1:5173'},addEventListener:(n,fn)=>callbacks.set(n,fn),
  registration:{showNotification:async (...args)=>shown.push(args)},
  clients:{matchAll:async()=>windows,openWindow:async url=>opened.push(url)}};
vm.runInNewContext(fs.readFileSync(dist+'/push-sw.js','utf8'),{self,URL});
assert.deepEqual([...callbacks.keys()].sort(),['notificationclick','push']);
const fire=async (type,event)=>{let pending;callbacks.get(type)({...event,waitUntil:p=>{pending=p}});await pending;};
for(const value of [null,{}, {kind:'other'}, {kind:'alerts',patient:'SYNTHETIC'}, {kind:'alerts',url:'https://invalid.example/'}, []]){
  await fire('push',{data:{json:()=>value}});
}
await fire('push',{data:{json:()=>{throw Error('malformed')}}});
assert.equal(shown.length,0);
await fire('push',{data:{json:()=>({kind:'alerts'})}});
assert.equal(shown.length,1);
assert.equal(shown[0][0],'Digital Crown');
assert.equal(shown[0][1].tag,'dc-pocket-alerts');
assert(!JSON.stringify(shown).includes('SYNTHETIC'));
await fire('notificationclick',{notification:{tag:'unrelated',close:()=>closed++}});
assert.equal(closed,0);assert.equal(opened.length,0);
windows=[{url:'https://invalid.example/mobile/dashboard',focus:async()=>{throw Error('foreign origin')}}];
await fire('notificationclick',{notification:{tag:'dc-pocket-alerts',close:()=>closed++}});
assert.deepEqual(opened,['http://127.0.0.1:5173/mobile/dashboard']);
windows=[{url:opened[0],focus:async()=>focused++}];
await fire('notificationclick',{notification:{tag:'dc-pocket-alerts',close:()=>closed++}});
assert.equal(focused,1);assert.equal(opened.length,1);assert.equal(closed,2);
console.log('PWA_ASSET_AND_GENERIC_PUSH_CONTRACT_PASS');
