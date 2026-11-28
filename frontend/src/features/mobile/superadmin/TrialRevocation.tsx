import { useEffect,useRef,useState } from 'react';
import { MobileStorage,type PlatformVaultContext } from '../../../services/zka/MobileStorage';
import { beginTrialRevocation,checkTrialRevocation,executeTrialRevocation,cancelTrialRevocation,type TrialRevocationRequest } from '../../../services/zka/mobilePlatformApproval';

const control='min-h-12 max-w-full whitespace-normal rounded-xl border border-glass-border bg-card px-3 py-2 text-sm font-bold break-words focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-50';
export function TrialRevocation({id,onRevoked,disabled,onActivity}:{id:number;onRevoked:()=>void;disabled:boolean;onActivity:(id:number,active:boolean)=>boolean}){
  const [phase,setPhase]=useState<'idle'|'pending'|'approved'>('idle');
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState('');
  const [remaining,setRemaining]=useState(0);
  const op=useRef<AbortController|null>(null),ctx=useRef<PlatformVaultContext|null>(null),proof=useRef<TrialRevocationRequest|null>(null),expiry=useRef(0),gen=useRef(0);
  function reset(msg=''){
    gen.current++;op.current?.abort();op.current=null;ctx.current=null;proof.current=null;expiry.current=0;onActivity(id,false);
    setPhase('idle');setBusy(false);setRemaining(0);setMessage(msg);
  }
  useEffect(()=>{
    const hide=()=>{if(document.hidden)reset();};
    const clear=()=>reset();
    document.addEventListener('visibilitychange',hide);window.addEventListener('offline',clear);window.addEventListener('digitalcrown:mobile-biometric-locked',clear);
    const timer=window.setInterval(()=>{if(expiry.current){const seconds=Math.max(0,Math.ceil((expiry.current-Date.now())/1000));setRemaining(seconds);if(!seconds)reset('Demande expirée.');}},1000);
    return()=>{gen.current++;op.current?.abort();ctx.current=null;proof.current=null;onActivity(id,false);window.clearInterval(timer);document.removeEventListener('visibilitychange',hide);window.removeEventListener('offline',clear);window.removeEventListener('digitalcrown:mobile-biometric-locked',clear);};
  },[id,onActivity]);
  async function run(action:'begin'|'check'|'execute'|'cancel'){
    if(op.current||disabled||document.hidden||!navigator.onLine)return;
    if(action==='begin'&&!onActivity(id,true))return;
    const controller=new AbortController();op.current=controller;const seq=++gen.current;setBusy(true);setMessage('');
    const timeout=window.setTimeout(()=>controller.abort(),10000);
    try{
      if(action==='begin'){
        const c=await MobileStorage.capturePlatformVaultContext();const started=Date.now();const r=await beginTrialRevocation(id,c,controller.signal);
        if(seq!==gen.current||controller.signal.aborted)return;
        ctx.current=c;proof.current=r;expiry.current=started+r.expires_in*1000;setRemaining(Math.max(0,Math.floor((expiry.current-Date.now())/1000)));setPhase('pending');
      }else{
        const c=ctx.current,r=proof.current;
        if(!c||!r||expiry.current<=Date.now())throw Error('expired');
        if(action==='check'){
          const state=await checkTrialRevocation(id,r,c,controller.signal);
          if(seq===gen.current&&!controller.signal.aborted)setPhase(state);
        }else if(action==='cancel'){
          await cancelTrialRevocation(id,r,c,controller.signal);
          if(seq===gen.current&&!controller.signal.aborted)reset('Demande annulée sur le serveur.');
        }else{
          await executeTrialRevocation(id,r,c,controller.signal);
          if(seq===gen.current&&!controller.signal.aborted){reset();onRevoked();}
        }
      }
    }catch{if(seq===gen.current)reset(action==='execute'?'Résultat non confirmé. Actualisez les essais avant toute nouvelle demande.':action==='cancel'?'Annulation serveur non confirmée. La demande locale est effacée ; vérifiez son expiration avant de poursuivre.':'Demande indisponible. Recommencez uniquement après vérification.');}
    finally{window.clearTimeout(timeout);if(seq===gen.current){op.current=null;setBusy(false);}}
  }
  return <div data-lot01-trial-revocation className="mt-3 min-w-0 space-y-2 border-t border-glass-border pt-3">
    {phase==='idle'?<button className={control} disabled={busy||disabled} onClick={()=>void run('begin')}>Demander la révocation</button>:<>
      <p role="status" className="text-sm">{phase==='pending'?'En attente de confirmation Desktop':'Accord Desktop vérifié'}</p><p className="text-xs text-text-muted" aria-live="off">Temps restant : {remaining} s</p>
      <p className="text-sm text-text-muted">Gardez Pocket ouvert. Seul cet essai est concerné.</p>
      {phase==='pending'?<button className={control} disabled={busy||remaining===0} onClick={()=>void run('check')}>Vérifier l’accord Desktop</button>:<button className={control+' text-text-main'} disabled={busy||remaining===0} onClick={()=>void run('execute')}>Confirmer la révocation définitive</button>}
      <button className={control} disabled={busy} onClick={()=>void run('cancel')}>Abandonner</button>
    </>}
    {message&&<p role="status" className="text-sm text-text-muted">{message}</p>}
  </div>;
}
