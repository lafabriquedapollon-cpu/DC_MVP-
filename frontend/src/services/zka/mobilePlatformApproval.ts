import { MobileStorage, type PlatformVaultContext } from './MobileStorage';
import { isStablePasskeyOrigin } from './mobilePasskey';

// No redirects, cookies, offline queue, URL tokens, or arbitrary destination.
// The backend remains the sole authority for every request.
function platformOrigin(ctx: PlatformVaultContext): string {
  const expected = 'https://digitalcrown.local:8005';
  if (!isStablePasskeyOrigin(expected) || ctx.apiBaseUrl !== expected) {
    throw new Error('Adresse locale sécurisée SuperAdmin requise.');
  }
  return expected;
}

export class PocketPlatformError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super('Accès plateforme indisponible.');
    this.name = 'PocketPlatformError';
  }
}
async function platformResponse(response: Response): Promise<unknown> {
  if (response.ok) return response.json();
  const data = await response.json().catch(() => null);
  const code = typeof data?.detail?.code === 'string' ? data.detail.code : '';
  throw new PocketPlatformError(response.status, code);
}

export async function checkPocketPlatformEligibility(signal?: AbortSignal): Promise<void> {
  const ctx = await MobileStorage.capturePlatformVaultContext();
  const origin = platformOrigin(ctx);
  const response = await fetch(origin + '/api/mobile/passkey/platform-eligibility', {
    method: 'GET', headers: { Authorization: 'Bearer ' + ctx.token },
    credentials: 'omit', cache: 'no-store', redirect: 'error', signal,
  });
  const payload = await platformResponse(response);
  await MobileStorage.assertPlatformVaultContext(ctx);
  if (!payload || typeof payload !== 'object' || !('eligible' in payload) || payload.eligible !== true) {
    throw new PocketPlatformError(403, 'PLATFORM_ELIGIBILITY_REQUIRED');
  }
}

export interface PocketPlatformClient {
  id: number;
  email: string;
  nom_complet: string | null;
  role: string;
  is_active: boolean;
  is_licensed: boolean;
  license_expires_at: string | null;
  is_archived: boolean;
  is_suspended: boolean;
  subscription_plan: string | null;
}
export interface PocketPlatformTrial {
  id: number;
  email: string;
  cabinet_name: string | null;
  trial_days: number;
  expires_at: string;
  consumed_at: string | null;
  revoked_at: string | null;
  created_at: string;
}
export interface PocketPlatformOverview {
  cabinetsCount: number;
  suppliersCount: number;
  activeSuppliersCount: number;
  productsCount: number;
  ordersCount: number;
  ordersByStatus: Record<string, number>;
  recognizedRevenueAmount: number;
  invoicedSupplierAmount: number;
  syncDegradedCount: number;
  syncStaleCount: number;
  activeAgreementsCount: number;
}
const textOrNull = (v: unknown): v is string | null => v === null || typeof v === 'string';
const finite = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}
function exactKeys(v: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(v).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(v, key));
}
function parseClient(v: unknown): PocketPlatformClient {
  const keys = ['id','email','nom_complet','role','is_active','is_licensed','license_expires_at','is_archived','is_suspended','subscription_plan'];
  if (!isRecord(v) || !exactKeys(v, keys) || !Number.isInteger(v.id) || typeof v.email !== 'string'
      || typeof v.role !== 'string' || !textOrNull(v.nom_complet) || !textOrNull(v.subscription_plan)
      || !textOrNull(v.license_expires_at) || ['is_active','is_licensed','is_archived','is_suspended'].some(k => typeof v[k] !== 'boolean')) {
    throw new PocketPlatformError(502, 'PLATFORM_RESPONSE_INVALID');
  }
  return v as unknown as PocketPlatformClient;
}
function parseTrial(v: unknown): PocketPlatformTrial {
  const keys = ['id','email','cabinet_name','trial_days','expires_at','consumed_at','revoked_at','created_at'];
  if (!isRecord(v) || !exactKeys(v, keys) || !Number.isInteger(v.id) || typeof v.email !== 'string'
      || !textOrNull(v.cabinet_name) || !Number.isInteger(v.trial_days) || typeof v.expires_at !== 'string'
      || typeof v.created_at !== 'string' || !textOrNull(v.consumed_at) || !textOrNull(v.revoked_at)) {
    throw new PocketPlatformError(502, 'PLATFORM_RESPONSE_INVALID');
  }
  return v as unknown as PocketPlatformTrial;
}
function parseOverview(v: unknown): PocketPlatformOverview {
  const keys = ['cabinetsCount','suppliersCount','activeSuppliersCount','productsCount','ordersCount',
    'recognizedRevenueAmount','invoicedSupplierAmount','syncDegradedCount','syncStaleCount','activeAgreementsCount'];
  if (!isRecord(v) || !exactKeys(v, [...keys,'ordersByStatus']) || keys.some(k => !finite(v[k]))
      || !isRecord(v.ordersByStatus) || Object.values(v.ordersByStatus).some(n => !finite(n))) {
    throw new PocketPlatformError(502, 'PLATFORM_RESPONSE_INVALID');
  }
  return v as unknown as PocketPlatformOverview;
}

type ReadEndpoint = 'clients' | 'trial-codes' | 'marketplace/overview';
async function readPlatform(endpoint: ReadEndpoint, offset: number, signal?: AbortSignal): Promise<unknown> {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new PocketPlatformError(422, 'PLATFORM_PAGE_INVALID');
  const ctx = await MobileStorage.capturePlatformVaultContext();
  const origin = platformOrigin(ctx);
  const approval = await MobileStorage.getPlatformApproval(ctx);
  if (!approval) throw new PocketPlatformError(403, 'PLATFORM_APPROVAL_REQUIRED');
  const suffix = endpoint === 'marketplace/overview' ? '' : '?limit=50&offset=' + offset;
  await MobileStorage.assertPlatformVaultContext(ctx);
  const response = await fetch(origin + '/api/mobile/superadmin/' + endpoint + suffix, {
    method: 'GET', headers: { Authorization: 'Bearer ' + ctx.token, 'X-Platform-Approval': approval },
    credentials: 'omit', cache: 'no-store', redirect: 'error', signal,
  });
  const payload = await platformResponse(response);
  await MobileStorage.assertPlatformVaultContext(ctx);
  if (signal?.aborted) throw new PocketPlatformError(0, 'PLATFORM_REQUEST_ABORTED');
  return payload;
}

export async function readPocketPlatformClients(offset = 0, signal?: AbortSignal): Promise<PocketPlatformClient[]> {
  const value = await readPlatform('clients', offset, signal);
  if (!Array.isArray(value) || value.length > 50) throw new PocketPlatformError(502, 'PLATFORM_RESPONSE_INVALID');
  return value.map(parseClient);
}
export async function readPocketPlatformTrials(offset = 0, signal?: AbortSignal): Promise<PocketPlatformTrial[]> {
  const value = await readPlatform('trial-codes', offset, signal);
  if (!Array.isArray(value) || value.length > 50) throw new PocketPlatformError(502, 'PLATFORM_RESPONSE_INVALID');
  return value.map(parseTrial);
}
export async function readPocketPlatformOverview(signal?: AbortSignal): Promise<PocketPlatformOverview> {
  return parseOverview(await readPlatform('marketplace/overview', 0, signal));
}

export async function claimPocketPlatformTicket(ticket: string, signal?: AbortSignal): Promise<void> {
  const clean = ticket.trim();
  if (!/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(clean)) throw new Error('Ticket SuperAdmin invalide.');
  const ctx = await MobileStorage.capturePlatformVaultContext();
  const origin = platformOrigin(ctx);
  const response = await fetch(origin + '/api/mobile/passkey/platform-approval/claim', {
    method: 'POST', headers: { Authorization: 'Bearer ' + ctx.token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket: clean }), credentials: 'omit', cache: 'no-store', redirect: 'error', signal,
  });
  const result = await platformResponse(response);
  await MobileStorage.assertPlatformVaultContext(ctx);
  if (!result || typeof result !== 'object' || !('approval' in result) || typeof result.approval !== 'string') {
    throw new Error('Réponse SuperAdmin invalide.');
  }
  if (signal?.aborted) throw new PocketPlatformError(0, 'PLATFORM_REQUEST_ABORTED');
  await MobileStorage.savePlatformApproval(result.approval, ctx);
}

export interface TrialRevocationRequest { challenge_id:string; nonce:string; expires_in:number }
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const noncePattern=/^[0-9a-f]{64}$/;
function ttl(v:unknown):v is number {return typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=300;}
async function mutationRequest(id:number, action:'revocation-request'|'revocation-status'|'revoke',ctx:PlatformVaultContext,signal:AbortSignal,body?:object):Promise<unknown>{
  if(!Number.isSafeInteger(id)||id<=0||document.hidden||!navigator.onLine||signal.aborted)throw new PocketPlatformError(0,'PLATFORM_REQUEST_ABORTED');
  const origin=platformOrigin(ctx);
  await MobileStorage.assertPlatformVaultContext(ctx);
  const approval=await MobileStorage.getPlatformApproval(ctx);
  if(!approval)throw new PocketPlatformError(403,'PLATFORM_APPROVAL_REQUIRED');
  await MobileStorage.assertPlatformVaultContext(ctx);
  if(document.hidden||signal.aborted)throw new PocketPlatformError(0,'PLATFORM_REQUEST_ABORTED');
  const response=await fetch(origin+'/api/mobile/superadmin/trial-codes/'+id+'/'+action,{
    method:'POST',headers:{Authorization:'Bearer '+ctx.token,'X-Platform-Approval':approval,'Content-Type':'application/json'},
    body:body?JSON.stringify(body):undefined,credentials:'omit',cache:'no-store',redirect:'error',signal
  });
  const value=await platformResponse(response);
  await MobileStorage.assertPlatformVaultContext(ctx);
  if(document.hidden||signal.aborted)throw new PocketPlatformError(0,'PLATFORM_REQUEST_ABORTED');
  return value;
}
export async function beginTrialRevocation(id:number,ctx:PlatformVaultContext,signal:AbortSignal):Promise<TrialRevocationRequest>{
  const v=await mutationRequest(id,'revocation-request',ctx,signal);
  if(!isRecord(v)||!exactKeys(v,['challenge_id','nonce','expires_in'])||typeof v.challenge_id!=='string'||!uuid.test(v.challenge_id)||typeof v.nonce!=='string'||!noncePattern.test(v.nonce)||!ttl(v.expires_in)||v.expires_in===0)throw new PocketPlatformError(502,'PLATFORM_RESPONSE_INVALID');
  return v as unknown as TrialRevocationRequest;
}
function binding(r:TrialRevocationRequest){return {challenge_id:r.challenge_id,nonce:r.nonce};}
export async function checkTrialRevocation(id:number,r:TrialRevocationRequest,ctx:PlatformVaultContext,signal:AbortSignal):Promise<'pending'|'approved'>{
  const v=await mutationRequest(id,'revocation-status',ctx,signal,binding(r));
  if(!isRecord(v)||!exactKeys(v,['state','expires_in'])||(v.state!=='pending'&&v.state!=='approved')||!ttl(v.expires_in)||v.expires_in===0)throw new PocketPlatformError(502,'PLATFORM_RESPONSE_INVALID');
  return v.state;
}
export async function executeTrialRevocation(id:number,r:TrialRevocationRequest,ctx:PlatformVaultContext,signal:AbortSignal):Promise<void>{
  const v=await mutationRequest(id,'revoke',ctx,signal,{...binding(r),confirm:true});
  if(!isRecord(v)||!exactKeys(v,['revoked'])||v.revoked!==true)throw new PocketPlatformError(502,'PLATFORM_RESPONSE_INVALID');
}
