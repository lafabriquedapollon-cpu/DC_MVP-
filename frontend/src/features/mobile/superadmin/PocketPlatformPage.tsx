import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, LockKeyhole, RefreshCw, ChevronLeft, Users, KeyRound, Store } from 'lucide-react';
import { MobileStorage, type PlatformVaultContext } from '../../../services/zka/MobileStorage';
import { isStablePasskeyOrigin, unlockMobilePasskey } from '../../../services/zka/mobilePasskey';
import { checkPocketPlatformEligibility, claimPocketPlatformTicket, readPocketPlatformClients, readPocketPlatformTrials, readPocketPlatformOverview, PocketPlatformError, type PocketPlatformClient, type PocketPlatformTrial, type PocketPlatformOverview } from '../../../services/zka/mobilePlatformApproval';

type Tab = 'clients' | 'trials' | 'marketplace';
type Content = { tab:'clients'; rows:PocketPlatformClient[] } | { tab:'trials'; rows:PocketPlatformTrial[] } | { tab:'marketplace'; overview:PocketPlatformOverview };
type State = 'locked' | 'checking' | 'ticket' | 'ready' | 'denied' | 'offline' | 'error' | 'origin';
const control = 'min-h-12 rounded-2xl border border-glass-border bg-card px-4 py-2 text-sm font-bold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary whitespace-normal break-words min-w-0 max-w-full disabled:opacity-50';
const money = (n:number) => new Intl.NumberFormat('fr-MA',{style:'currency',currency:'MAD'}).format(n);
function date(value:string|null) { if(!value)return '—'; const d=new Date(value);return Number.isNaN(d.getTime())?'—':d.toLocaleDateString('fr-FR'); }
function clientStatus(c:PocketPlatformClient) {
  if(c.is_archived)return 'Archivé'; if(c.is_suspended)return 'Suspendu'; if(!c.is_active)return 'Inactif';
  if(!c.is_licensed || !c.license_expires_at || Date.parse(c.license_expires_at)<=Date.now())return 'Licence expirée';
  return 'Licence active';
}
function trialStatus(t:PocketPlatformTrial) { return t.revoked_at?'Révoqué':t.consumed_at?'Utilisé':Date.parse(t.expires_at)<=Date.now()?'Expiré':'Actif'; }
export function PocketPlatformPage() {
  const [state,setState]=useState<State>('locked');
  const [tab,setTab]=useState<Tab>('clients');
  const [offset,setOffset]=useState(0);
  const [content,setContent]=useState<Content|null>(null);
  const [message,setMessage]=useState('');
  const [busy,setBusy]=useState(false);
  const ticket=useRef<HTMLInputElement>(null);
  const active=useRef<AbortController|null>(null);
  const generation=useRef(0);
  const current=useRef<PlatformVaultContext|null>(null);
  const peerChannel=useRef<BroadcastChannel|null>(null);
  const clear=useCallback((next:State='locked')=>{
    generation.current++; active.current?.abort(); active.current=null; current.current=null;
    if(ticket.current)ticket.current.value='';
    setContent(null);setBusy(false);setMessage('');setState(next);
  },[]);
  const classify=useCallback((error:unknown):State=>{
    if (!navigator.onLine) return 'offline';
    if(error instanceof PocketPlatformError){
      if(error.status===401||error.status===423)return 'locked';
      if(error.code==='PLATFORM_APPROVAL_REQUIRED')return 'ticket';
      if(error.status===403)return 'denied';
    }
    return 'error';
  },[]);
  const run=useCallback(async (mode:'read'|'unlock'|'claim',target:Tab,page:number,code?:string)=>{
    const seq=++generation.current;active.current?.abort();
    const controller=new AbortController();active.current=controller;current.current=null;
    setContent(null);setMessage('');setBusy(true);setState('checking');
    const timeout=window.setTimeout(()=>controller.abort(),mode==='unlock'?120000:15000);
    try{
      if(!isStablePasskeyOrigin()) {if(seq===generation.current)setState('origin');return;}
      if(!navigator.onLine) {if(seq===generation.current)setState('offline');return;}
      // A peer coordination channel carries only a lock notification, never
      // identity, proof, ticket, or platform data. If unavailable, fail closed.
      if(!peerChannel.current){if(seq===generation.current)setState('error');return;}
      if(mode==='unlock'){
        peerChannel.current.postMessage('lock-platform');
        await unlockMobilePasskey();
        // A late authenticator result must not undo a peer/visibility lock.
        if(seq!==generation.current||controller.signal.aborted||document.hidden||!navigator.onLine){
          MobileStorage.lockBiometricVault();
          return;
        }
      }
      if(seq!==generation.current||controller.signal.aborted||document.hidden)return;
      let ctx:PlatformVaultContext;
      try{ctx=await MobileStorage.capturePlatformVaultContext()}catch{if(seq===generation.current)setState('locked');return;}
      await checkPocketPlatformEligibility(controller.signal);
      if(seq!==generation.current||controller.signal.aborted||document.hidden)return;
      if(mode==='claim') await claimPocketPlatformTicket(code||'',controller.signal);
      if(seq!==generation.current||controller.signal.aborted||document.hidden)return;
      const proof=await MobileStorage.getPlatformApproval(ctx);
      if(!proof){if(seq===generation.current)setState('ticket');return;}
      let value:Content;
      if(target==='clients')value={tab:target,rows:await readPocketPlatformClients(page,controller.signal)};
      else if(target==='trials')value={tab:target,rows:await readPocketPlatformTrials(page,controller.signal)};
      else value={tab:target,overview:await readPocketPlatformOverview(controller.signal)};
      await MobileStorage.assertPlatformVaultContext(ctx);
      if(seq!==generation.current||controller.signal.aborted||document.hidden||!navigator.onLine)return;
      current.current=ctx;setContent(value);setTab(target);setOffset(page);setState('ready');
    }catch(error){
      if(seq===generation.current){
        const next=classify(error);setState(next);
        setMessage(next==='ticket'?'Une autorisation Desktop indépendante est nécessaire.':next==='denied'?'Cette identité ne dispose pas de l’accès plateforme.':next==='locked'?'Vérification biométrique récente requise.':'Connexion ou vérification indisponible. Aucune donnée conservée à l’écran.');
      }
    }finally{
      window.clearTimeout(timeout);
      if(seq===generation.current){setBusy(false);if(controller.signal.aborted)setState('error');}
    }
  },[classify]);
  useEffect(()=>{
    const hide=()=>{if(document.hidden){MobileStorage.lockBiometricVault();clear();}};
    const lock=()=>clear();
    const offline=()=>clear('offline');
    let peers:BroadcastChannel|null=null;
    if(isStablePasskeyOrigin()){
      try{
        peers=new BroadcastChannel('digitalcrown-pocket-platform-lock-v1');
        peers.onmessage=(event)=>{
          if(event.data!=='lock-platform')return;
          MobileStorage.lockBiometricVault();clear();
        };
        peerChannel.current=peers;
        // Opening a second platform page always retires the first tab's
        // in-memory authority, even if both pages report visible.
        peers.postMessage('lock-platform');
      }catch{
        peers?.close();peers=null;peerChannel.current=null;
      }
    }
    document.addEventListener('visibilitychange',hide);window.addEventListener('offline',offline);
    window.addEventListener('digitalcrown:mobile-biometric-locked',lock);
    void run('read','clients',0);
    return ()=>{
      generation.current++;active.current?.abort();current.current=null;
      if(peerChannel.current===peers)peerChannel.current=null;
      peers?.close();
      document.removeEventListener('visibilitychange',hide);window.removeEventListener('offline',offline);window.removeEventListener('digitalcrown:mobile-biometric-locked',lock);
    };
  },[clear,run]);
  useEffect(()=>{
    if(state!=='ready')return;
    let checking=false;
    const id=window.setInterval(async()=>{
      if(checking)return;checking=true;
      const ctx=current.current;
      try{
        if(!ctx||document.hidden||!navigator.onLine)throw Error('locked');
        await MobileStorage.assertPlatformVaultContext(ctx);
        if(!await MobileStorage.getPlatformApproval(ctx))throw Error('expired');
      }catch{if(current.current===ctx)clear(navigator.onLine?'locked':'offline');}
      finally{checking=false;}
    },1000);
    const recheck=window.setTimeout(()=>{void run('read',tab,offset)},30000);
    return()=>{window.clearInterval(id);window.clearTimeout(recheck)};
  },[state,tab,offset,clear,run]);
  function claim(e:FormEvent){e.preventDefault();const code=ticket.current?.value??'';if(ticket.current)ticket.current.value='';if(code&&!busy)void run('claim','clients',0,code);}
  const select=(t:Tab)=>{setTab(t);setOffset(0);void run('read',t,0);};
  return <main data-r5-pocket-platform data-r5-platform-state={state} className="min-h-[100dvh] bg-background px-4 py-5 text-text-main sm:px-6" style={{backgroundColor:'var(--bg-medical-pearl)'}}>
    <div className="mx-auto max-w-5xl space-y-4">
      <header className="space-y-3">
        <Link to="/mobile/dashboard?tab=securite" className="inline-flex min-h-11 items-center gap-1 text-sm font-bold text-primary"><ChevronLeft size={18}/> Sécurité Pocket</Link>
        <div className="rounded-[24px] bg-primary p-5 text-on-primary sm:p-6"><div className="flex flex-wrap items-center gap-3"><ShieldCheck size={30} className="shrink-0"/><div className="min-w-0 break-words"><p className="text-xs font-semibold uppercase tracking-widest">Digital Crown · Plateforme</p><h1 className="text-2xl font-bold">SuperAdmin Pocket</h1></div></div><p className="mt-3 text-sm">Lecture seule · connexion locale sécurisée</p></div>
      </header>
      {state!=='ready' && <section aria-label="Accès plateforme" className="space-y-4 rounded-[24px] border border-glass-border bg-card p-5 shadow-sm">
        <div className="flex flex-wrap gap-3"><LockKeyhole className="shrink-0 text-primary" size={24}/><div className="min-w-0 break-words"><h2 className="text-lg font-bold">{state==='origin'?'Adresse HTTPS requise':state==='ticket'?'Autorisation Desktop requise':state==='denied'?'Accès refusé':state==='offline'?'Connexion indisponible':state==='checking'?'Vérification en cours…':state==='error'?'Accès indisponible':'Vérification biométrique requise'}</h2><p className="mt-1 text-sm text-text-muted">{state==='origin'?'Ouvrez https://digitalcrown.local:8005 sur le réseau du cabinet.':state==='ticket'?'Générez un ticket sur le poste SuperAdmin Desktop, puis saisissez-le ici.':state==='denied'?'Seule une identité SuperAdmin autorisée peut consulter cette plateforme.':state==='offline'?'Aucune donnée plateforme n’est disponible hors ligne.':'Aucune donnée plateforme n’est affichée sans validation serveur.'}</p></div></div>
        {message&&<p role="status" className="text-sm text-text-muted">{message}</p>}
        {state==='ticket'&&<form onSubmit={claim} className="space-y-3"><label className="grid gap-2 text-sm font-bold">Ticket temporaire<input ref={ticket} type="password" autoComplete="off" spellCheck={false} required minLength={80} maxLength={80} className="min-h-12 w-full rounded-xl border border-border-main bg-background px-3"/></label><button type="submit" disabled={busy} className={control+' w-full bg-primary text-on-primary'}>Valider le ticket</button></form>}
        {state==='locked'&&<button type="button" disabled={busy} onClick={()=>void run('unlock',tab,offset)} className={control+' w-full bg-primary text-on-primary'}>Vérifier ma biométrie</button>}
        {(state==='error'||state==='offline'||state==='ticket')&&<button type="button" disabled={busy} onClick={()=>void run('read',tab,offset)} className={control+' w-full'}>Réessayer</button>}
      </section>}
      {state==='ready'&&content&&<section aria-label="Consultation plateforme" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2"><span className="rounded-full bg-success-surface px-3 py-2 text-xs font-bold text-success">Accès vérifié · lecture seule</span><button type="button" onClick={()=>{MobileStorage.lockBiometricVault();clear()}} className={control}>Verrouiller</button></div>
        <nav aria-label="Sections SuperAdmin" className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,7rem),1fr))] gap-2">{([{id:'clients',label:'Clients',Icon:Users},{id:'trials',label:'Essais',Icon:KeyRound},{id:'marketplace',label:'Marketplace',Icon:Store}] as const).map(({id,label,Icon})=><button key={id} type="button" aria-pressed={tab===id} onClick={()=>select(id)} className={control+' flex min-w-0 flex-col items-center justify-center gap-1 px-1 '+(tab===id?'bg-primary text-on-primary':'')}><Icon size={18}/><span className="max-w-full break-words text-xs">{label}</span></button>)}</nav>
        {content.tab==='clients'&&<div className="grid gap-3 sm:grid-cols-2">{content.rows.length===0?<p className="text-sm text-text-muted">Aucun client sur cette page.</p>:content.rows.map(c=><article key={c.id} className="min-w-0 rounded-[20px] border border-glass-border bg-card p-4"><h3 className="break-words font-bold">{c.nom_complet||'Client'}</h3><p className="break-all text-sm text-text-muted">{c.email}</p><div className="mt-3 flex flex-wrap gap-2 text-xs font-bold"><span className="rounded-lg bg-background px-2 py-1">{clientStatus(c)}</span><span className="rounded-lg bg-background px-2 py-1">{c.subscription_plan||'Sans pack'}</span></div><p className="mt-2 text-sm text-text-muted">Échéance : {date(c.license_expires_at)}</p></article>)}</div>}
        {content.tab==='trials'&&<div className="grid gap-3 sm:grid-cols-2">{content.rows.length===0?<p className="text-sm text-text-muted">Aucun essai sur cette page.</p>:content.rows.map(t=><article key={t.id} className="min-w-0 rounded-[20px] border border-glass-border bg-card p-4"><h3 className="break-words font-bold">{t.cabinet_name||'Cabinet'}</h3><p className="break-all text-sm text-text-muted">{t.email}</p><p className="mt-3 text-sm">{trialStatus(t)} · {t.trial_days} jours</p><p className="text-sm text-text-muted">Échéance : {date(t.expires_at)}</p></article>)}</div>}
        {content.tab==='marketplace'&&<div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,9rem),1fr))] gap-3">{[['Cabinets',content.overview.cabinetsCount],['Fournisseurs actifs',content.overview.activeSuppliersCount],['Produits',content.overview.productsCount],['Commandes',content.overview.ordersCount],['Revenus reconnus',money(content.overview.recognizedRevenueAmount)],['Facturé fournisseurs',money(content.overview.invoicedSupplierAmount)],['Synchronisations dégradées',content.overview.syncDegradedCount],['Synchronisations périmées',content.overview.syncStaleCount],['Accords actifs',content.overview.activeAgreementsCount]].map(([label,value])=><article key={label} className="min-w-0 rounded-[20px] border border-glass-border bg-card p-4"><p className="text-xs font-semibold text-text-muted">{label}</p><p className="mt-2 break-words text-lg font-bold">{value}</p></article>)}</div>}
        <div className="flex flex-wrap items-center justify-between gap-2">{content.tab!=='marketplace'&&<><button type="button" disabled={offset===0} onClick={()=>void run('read',tab,Math.max(0,offset-50))} className={control}>Précédent</button><span className="text-xs text-text-muted">Page {offset/50+1}</span><button type="button" disabled={content.rows.length!==50} onClick={()=>void run('read',tab,offset+50)} className={control}>Suivant</button></>}<button type="button" onClick={()=>void run('read',tab,offset)} className={control}><RefreshCw size={16} className="mr-1 inline"/> Actualiser</button></div>
      </section>}
    </div>
  </main>;
}
