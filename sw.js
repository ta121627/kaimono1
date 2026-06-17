/* 買い物チェックリスト サービスワーカー */

self.addEventListener('push', event => {
  if (!event.data) return;
  let data;
  try { data = event.data.json(); }
  catch { data = { title: '買い物チェックリスト', body: event.data.text() }; }

  const opts = {
    body: data.body || '',
    icon: '/apple-touch-icon.png',
    badge: '/favicon-32.png',
    tag: 'kaimono',
    renotify: true,
    vibrate: [200, 100, 200],
    data: { url: self.location.origin + '/' },
  };
  event.waitUntil(
    self.registration.showNotification(data.title || '買い物チェックリスト', opts)
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || self.location.origin + '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if ('focus' in c) { c.focus(); return; }
      }
      return clients.openWindow(url);
    })
  );
});
