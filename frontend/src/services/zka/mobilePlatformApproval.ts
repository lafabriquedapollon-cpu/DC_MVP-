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

export async function claimPocketPlatformTicket(ticket: string): Promise<void> {
  const clean = ticket.trim();
  if (!/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(clean)) throw new Error('Ticket SuperAdmin invalide.');
  const ctx = await MobileStorage.capturePlatformVaultContext();
  const origin = platformOrigin(ctx);
  const response = await fetch(origin + '/api/mobile/passkey/platform-approval/claim', {
    method: 'POST', headers: { Authorization: 'Bearer ' + ctx.token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket: clean }), credentials: 'omit', cache: 'no-store', redirect: 'error',
  });
  if (!response.ok) throw new Error('Transfert SuperAdmin refusé (' + response.status + ').');
  const result: unknown = await response.json();
  if (!result || typeof result !== 'object' || !('approval' in result) || typeof result.approval !== 'string') {
    throw new Error('Réponse SuperAdmin invalide.');
  }
  await MobileStorage.savePlatformApproval(result.approval, ctx);
}
