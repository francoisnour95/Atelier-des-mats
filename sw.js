/* Atelier des Mâts: lets the installed app open without internet.
   The page is fetched fresh whenever there is a connection, so updates pushed to GitHub arrive on their own.
   Online saving (Supabase) always goes to the network and is never stored here. */
const CACHE = 'atelier-v28';
const CORE = ['./', './manifest.webmanifest', './icons/icon.svg', './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png'];
const LIBS = [
  'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js',
  'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/TransformControls.js'
];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await c.addAll(CORE);
    await Promise.all(LIBS.map(u => fetch(u, { mode: 'no-cors' }).then(r => c.put(u, r)).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.hostname.endsWith('supabase.co')) return;
  if (req.mode === 'navigate') {
    /* the page: newest from the network, the saved copy when offline */
    e.respondWith((async () => {
      try {
        const r = await fetch(req);
        if (r.ok) { const c = await caches.open(CACHE); c.put('./', r.clone()); }
        return r;
      } catch (_) {
        return (await caches.match('./')) || Response.error();
      }
    })());
    return;
  }
  /* libraries, fonts and icons: saved copy first, then fetched and kept */
  e.respondWith((async () => {
    const hit = await caches.match(req);
    if (hit) return hit;
    try {
      const r = await fetch(req);
      if (r.ok || r.type === 'opaque') { const c = await caches.open(CACHE); c.put(req, r.clone()); }
      return r;
    } catch (_) {
      return Response.error();
    }
  })());
});
