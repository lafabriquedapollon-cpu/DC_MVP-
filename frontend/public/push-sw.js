/* Pocket OS signal only. Never display or persist push payload data. */
'use strict';
const POCKET_PATH = '/mobile/dashboard';
self.addEventListener('push', (event) => {
  let payload;
  try { payload = event.data?.json(); } catch { return; }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      Object.keys(payload).length !== 1 || payload.kind !== 'alerts') return;
  event.waitUntil(self.registration.showNotification('Digital Crown', {
    body: 'Vous avez de nouvelles alertes. Ouvrez Pocket pour les consulter.',
    icon: '/icon-192.png',
    tag: 'dc-pocket-alerts'
  }));
});
self.addEventListener('notificationclick', (event) => {
  if (event.notification.tag !== 'dc-pocket-alerts') return;
  event.notification.close();
  event.waitUntil((async () => {
    const destination = new URL(POCKET_PATH, self.location.origin).href;
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const existing = windows.find(client => client.url === destination);
    if (existing) return existing.focus();
    return self.clients.openWindow(destination);
  })());
});
