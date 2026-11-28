import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Smartphone, ShieldCheck, RefreshCw } from 'lucide-react';
import { API_BASE, getRuntimeAuthToken } from '../../services/api';

type Device = { device_id: string; credential_id: string; enabled_at: string; last_seen_at: string | null };
const button = 'min-h-12 rounded-xl border border-border-main px-4 py-2 text-sm font-bold focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-50';
function secureDesktop(): boolean {
  try {
    return window.isSecureContext && window.location.protocol === 'https:' &&
      new URL(API_BASE).origin === window.location.origin;
  } catch { return false; }
}
async function request(path: 'platform-devices' | 'platform-approval', signal: AbortSignal, body?: object): Promise<unknown> {
  if (!secureDesktop()) throw new Error('Adresse locale HTTPS requise.');
  const token = getRuntimeAuthToken();
  const headers: Record<string,string> = { Accept: 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(API_BASE + '/api/mobile/passkey/' + path, {
    method: body ? 'POST' : 'GET', headers, body: body ? JSON.stringify(body) : undefined,
    credentials: 'include', cache: 'no-store', redirect: 'error', signal,
  });
  if (!r.ok) throw new Error(r.status === 401 ? 'Authentification refusée.' : r.status === 429 ? 'Trop de tentatives. Réessayez plus tard.' : 'Autorisation indisponible (' + r.status + ').');
  return r.json();
}
function isDevice(v: unknown): v is Device {
  if (!v || typeof v !== 'object') return false;
  const d = v as Partial<Device>;
  return typeof d.device_id === 'string' && d.device_id.length === 36 &&
    typeof d.credential_id === 'string' && d.credential_id.length >= 8 &&
    typeof d.enabled_at === 'string' && (d.last_seen_at === null || typeof d.last_seen_at === 'string');
}
export function PocketPlatformAuthorization() {
  const [open, setOpen] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [ticket, setTicket] = useState('');
  const [expires, setExpires] = useState(0);
  const [remaining, setRemaining] = useState(0);
  const password = useRef<HTMLInputElement>(null);
  const operation = useRef<AbortController | null>(null);
  const generation = useRef(0);
  function reset() {
    generation.current++;
    operation.current?.abort(); operation.current = null;
    if (password.current) password.current.value = '';
    setTicket(''); setExpires(0); setRemaining(0); setConfirm(false); setBusy(false);
    setDevices([]); setSelected(''); setMessage(''); setOpen(false);
  }
  useEffect(() => {
    const hide = () => { if (document.hidden) reset(); };
    const offline = () => reset();
    document.addEventListener('visibilitychange', hide);
    window.addEventListener('offline', offline);
    return () => {
      generation.current++; operation.current?.abort();
      document.removeEventListener('visibilitychange', hide);
      window.removeEventListener('offline', offline);
    };
  }, []);
  useEffect(() => {
    if (!expires) return;
    const tick = () => {
      const n = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
      setRemaining(n);
      if (!n) { setTicket(''); setExpires(0); setMessage('Ticket expiré. Générez une nouvelle autorisation.'); }
    };
    tick(); const id = window.setInterval(tick, 500);
    return () => window.clearInterval(id);
  }, [expires]);
  async function refresh() {
    const seq = ++generation.current; operation.current?.abort();
    const controller = new AbortController(); operation.current = controller;
    setOpen(true); setBusy(true); setMessage(''); setTicket(''); setExpires(0);
    setDevices([]); setSelected(''); setConfirm(false);
    if (password.current) password.current.value = '';
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const value = await request('platform-devices', controller.signal);
      if (!Array.isArray(value) || !value.every(isDevice)) throw Error('Réponse appareils invalide.');
      if (seq !== generation.current || controller.signal.aborted) return;
      setDevices(value); if (value.length === 1) setSelected(value[0].device_id);
      if (!value.length) setMessage('Aucun appareil personnel avec biométrie active. Activez-la d’abord dans Pocket.');
    } catch (e) {
      if (seq === generation.current) setMessage(e instanceof Error && !controller.signal.aborted ? e.message : 'Connexion indisponible.');
    } finally { window.clearTimeout(timeout); if (seq === generation.current) setBusy(false); }
  }
  async function issue(e: FormEvent) {
    e.preventDefault();
    const device = devices.find(d => d.device_id === selected);
    const secret = password.current?.value ?? '';
    if (!device || !secret || !confirm || busy) return;
    if (password.current) password.current.value = '';
    const seq = ++generation.current; operation.current?.abort();
    const controller = new AbortController(); operation.current = controller;
    setBusy(true); setConfirm(false); setMessage(''); setTicket('');
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    const started = Date.now();
    try {
      const value = await request('platform-approval', controller.signal, {device_id:device.device_id,credential_id:device.credential_id,password:secret,confirm:true});
      if (!value || typeof value !== 'object' || !('ticket' in value) || typeof value.ticket !== 'string' ||
          !/^[0-9a-f-]{36}[.][A-Za-z0-9_-]{43}$/.test(value.ticket) ||
          !('expires_in' in value) || value.expires_in !== 180) throw Error('Réponse d’autorisation invalide.');
      if (seq !== generation.current || controller.signal.aborted || document.hidden) return;
      setExpires(started + 180000); setTicket(value.ticket);
    } catch (err) {
      if (seq === generation.current) setMessage(err instanceof Error && !controller.signal.aborted ? err.message : 'Transfert indisponible. Aucun nouvel essai automatique.');
    } finally { window.clearTimeout(timeout); if (seq === generation.current) setBusy(false); }
  }
  return <section data-r5-desktop-authorization aria-labelledby="r5-desktop-title" className="rounded-[24px] border border-border-main bg-card p-4 sm:p-6 shadow-sm">
    <div className="flex flex-wrap items-start gap-3">
      <div className="grid size-12 shrink-0 place-items-center rounded-2xl bg-primary/10 text-primary"><Smartphone size={25}/></div>
      <div className="min-w-0 flex-1"><h2 id="r5-desktop-title" className="text-lg font-bold text-text-main">SuperAdmin Pocket</h2><p className="mt-1 text-sm text-text-muted">Autorisation indépendante · lecture seule</p></div>
      <button type="button" className={button} onClick={open?reset:refresh} disabled={busy&&!open}>{open?'Fermer':'Autoriser un appareil'}</button>
    </div>
    {!secureDesktop() && <p className="mt-3 rounded-xl bg-warning-surface p-3 text-sm text-warning">Utilisez l’adresse locale HTTPS sécurisée pour autoriser un téléphone.</p>}
    {open && <div className="mt-4 space-y-4">
      {message && <p role="status" className="rounded-xl border border-border-main bg-background p-3 text-sm">{message}</p>}
      {busy && <p role="status" className="text-sm text-text-muted">Vérification en cours…</p>}
      {!ticket && devices.length > 0 && <form onSubmit={issue} className="grid gap-3">
        <label className="grid gap-1 text-sm font-semibold">Appareil personnel<select value={selected} onChange={e=>{setSelected(e.target.value);setConfirm(false)}} className="min-h-12 min-w-0 rounded-xl border border-border-main bg-background px-3" required disabled={busy}><option value="">Choisir un appareil</option>{devices.map(d=><option key={d.device_id} value={d.device_id}>Pocket · {d.device_id.slice(0,8)} · {new Date(d.enabled_at).toLocaleDateString('fr-FR')}</option>)}</select></label>
        <label className="grid gap-1 text-sm font-semibold">Mot de passe Desktop<input ref={password} type="password" required maxLength={72} autoComplete="current-password" className="min-h-12 w-full rounded-xl border border-border-main bg-background px-3" disabled={busy}/></label>
        <label className="flex items-start gap-3 text-sm"><input type="checkbox" checked={confirm} onChange={e=>setConfirm(e.target.checked)} disabled={busy} className="mt-1 size-5"/> J’autorise cet appareil à consulter les données plateforme, sans modification.</label>
        <button type="submit" className={button+' bg-primary text-on-primary'} disabled={!selected||!confirm||busy}><ShieldCheck size={17} className="mr-2 inline"/> Générer le ticket temporaire</button>
      </form>}
      {ticket && <div className="space-y-2 rounded-2xl border border-success-border bg-success-surface p-4">
        <p className="font-bold text-success">Ticket à usage unique · {remaining} s</p>
        <p className="text-sm">Saisissez-le dans le Pocket autorisé. Ne l’envoyez pas par messagerie. Il disparaît à la fermeture de ce panneau.</p>
        <label className="grid gap-1 text-sm font-semibold">Ticket temporaire<textarea readOnly value={ticket} rows={3} spellCheck={false} autoComplete="off" className="w-full resize-none break-all rounded-xl border border-border-main bg-card p-3 font-mono text-sm"/></label>
        <button type="button" onClick={reset} className={button}>Masquer le ticket</button>
      </div>}
      {!ticket && <button type="button" className={button} disabled={busy} onClick={refresh}><RefreshCw size={16} className="mr-2 inline"/> Actualiser les appareils</button>}
    </div>}
  </section>;
}
