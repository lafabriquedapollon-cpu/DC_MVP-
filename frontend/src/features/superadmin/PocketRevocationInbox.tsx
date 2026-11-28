import { useEffect,useRef,useState,type FormEvent } from 'react';
import { API_BASE,getRuntimeAuthToken } from '../../services/api';

type Pending={request_id:string;target_id:number;email:string;cabinet_name:string|null;device_id:string;expires_in:number};
const btn='min-h-12 max-w-full whitespace-normal rounded-xl border border-border-main px-4 py-2 text-sm font-bold break-words focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-50';
function isPending(v:unknown):v is Pending{
  if(!v||typeof v!=='object')return false;const x=v as Partial<Pending>;
  return Object.keys(v).length===6&&typeof x.request_id==='string'&&/^[0-9a-f-]{36}$/.test(x.request_id)&&Number.isSafeInteger(x.target_id)&&Number(x.target_id)>0&&typeof x.email==='string'&&(x.cabinet_name===null||typeof x.cabinet_name==='string')&&typeof x.device_id==='string'&&x.device_id.length===36&&typeof x.expires_in==='number'&&Number.isSafeInteger(x.expires_in)&&x.expires_in>0&&x.expires_in<=300;
}
async function call(path:string,signal:AbortSignal,body?:object){
  if(!window.isSecureContext||location.protocol!=='https:'||new URL(API_BASE).origin!==location.origin||document.hidden||!navigator.onLine||signal.aborted)throw Error('secure Desktop required');
  const headers:Record<string,string>={Accept:'application/json'},token=getRuntimeAuthToken();
  if(token)headers.Authorization='Bearer '+token;
  if(body)headers['Content-Type']='application/json';
  const r=await fetch(API_BASE+'/api/mobile/superadmin/revocation-requests'+path,{method:body?'POST':'GET',headers,body:body?JSON.stringify(body):undefined,credentials:'include',cache:'no-store',redirect:'error',signal});
  if(!r.ok||signal.aborted||document.hidden)throw Error('request unavailable');return r.json();
}
export function PocketRevocationInbox(){
  const [items,setItems]=useState<Pending[]>([]),[chosen,setChosen]=useState<Pending|null>(null),[confirm,setConfirm]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState('');
  const password=useRef<HTMLInputElement>(null),op=useRef<AbortController|null>(null),gen=useRef(0),deadline=useRef(0);
  function clear(msg=''){
    gen.current++;op.current?.abort();op.current=null;deadline.current=0;if(password.current)password.current.value='';
    setItems([]);setChosen(null);setConfirm(false);setBusy(false);setMessage(msg);
  }
  useEffect(()=>{
    const hide=()=>{if(document.hidden)clear();};const offline=()=>clear();
    document.addEventListener('visibilitychange',hide);window.addEventListener('offline',offline);
    const timer=window.setInterval(()=>{if(deadline.current&&Date.now()>=deadline.current)clear('Demande expirée. Actualisez la liste.');},1000);
    return()=>{gen.current++;op.current?.abort();window.clearInterval(timer);document.removeEventListener('visibilitychange',hide);window.removeEventListener('offline',offline);};
  },[]);
  async function run(item?:Pending){
    if(op.current)return;
    const secret=item?password.current?.value??'':'';
    if(item&&(!confirm||!secret||Date.now()>=deadline.current))return;
    if(password.current)password.current.value='';
    const ctl=new AbortController();op.current=ctl;const seq=++gen.current;setBusy(true);setMessage('');setConfirm(false);
    const timer=window.setTimeout(()=>ctl.abort(),10000);
    try{
      if(item){
        const result=await call('/'+item.request_id+'/approve',ctl.signal,{target_id:item.target_id,password:secret,confirm:true});
        if(!result||Object.keys(result).length!==1||result.approved!==true)throw Error('invalid reply');
        if(seq===gen.current&&!ctl.signal.aborted)clear('Accord donné. La révocation doit encore être confirmée sur Pocket.');
      }else{
        setItems([]);setChosen(null);deadline.current=0;
        const start=Date.now(),v=await call('',ctl.signal);
        if(!Array.isArray(v)||v.length>50||!v.every(isPending))throw Error('invalid list');
        if(seq===gen.current&&!ctl.signal.aborted){setItems(v);if(v.length)deadline.current=start+Math.min(...v.map(x=>x.expires_in))*1000;else setMessage('Aucune demande en attente.');}
      }
    }catch{if(seq===gen.current)clear('Demande indisponible. Actualisez avant toute nouvelle confirmation.');}
    finally{window.clearTimeout(timer);if(seq===gen.current){op.current=null;setBusy(false);}}
  }
  function submit(e:FormEvent){e.preventDefault();if(chosen)void run(chosen);}
  return <section data-lot01-revocation-inbox aria-labelledby="lot01-revocation-title" className="rounded-[24px] border border-border-main bg-card p-4 sm:p-6 space-y-3">
    <h2 id="lot01-revocation-title" className="text-lg font-bold">Demandes de révocation Pocket</h2>
    <p className="text-sm text-text-muted">Vérifiez le cabinet et l’essai avant d’accorder une révocation unique.</p>
    <button className={btn} disabled={busy} onClick={()=>void run()}>Actualiser les demandes</button>
    {message&&<p role="status" className="text-sm">{message}</p>}
    {items.map(item=><article key={item.request_id} className="rounded-xl border border-border-main p-3 space-y-2"><p className="font-bold break-words">{item.cabinet_name||'Cabinet'}</p><p className="text-sm break-all">{item.email}</p><p className="text-sm">Essai #{item.target_id} · appareil {item.device_id.slice(0,8)}</p><button className={btn} disabled={busy} onClick={()=>{if(password.current)password.current.value='';setChosen(item);setConfirm(false);}}>Examiner cette demande</button></article>)}
    {chosen&&<form onSubmit={submit} className="space-y-3 rounded-xl border border-border-main p-3">
      <p className="font-bold break-all">Révoquer l’essai #{chosen.target_id} · {chosen.email}</p>
      <label className="grid gap-1 text-sm font-semibold">Mot de passe de confirmation<input ref={password} type="password" required maxLength={72} autoComplete="current-password" disabled={busy} className="min-h-12 w-full rounded-xl border border-border-main bg-background px-3"/></label>
      <label className="flex gap-2 items-start text-sm"><input type="checkbox" checked={confirm} disabled={busy} onChange={e=>setConfirm(e.target.checked)} className="mt-1 size-5"/>J’autorise uniquement la révocation de cet essai.</label>
      <button className={btn+' bg-primary text-on-primary'} type="submit" disabled={busy||!confirm}>Approuver la révocation ciblée</button>
      <button className={btn+' ml-2'} type="button" disabled={busy} onClick={()=>clear()}>Annuler</button>
    </form>}
  </section>;
}
