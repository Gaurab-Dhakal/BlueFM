/**
 * BlueFM Service Worker
 * Progressive Web App Engine
 */

const CACHE_NAME = 'bluefm-pwa-v1';
const PRECACHE_ASSETS = [
  './',
  'manifest.json',
  'icon-192.png',
  'icon-512.png',
  'icon-maskable-512.png',
  'apple-touch-icon.png',
  'favicon.ico',
  'favicon-32x32.png',
  'favicon-16x16.png'
];

// Precache essential assets on install
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate and remove obsolete caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Intercept fetch requests
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Strictly pass-through for non-GET methods or dynamic file manager actions
  if (request.method !== 'GET' || url.searchParams.has('action')) {
    return;
  }

  // Navigation requests: Network-First with Cache fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response && response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, responseClone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then((cachedResponse) => {
            if (cachedResponse) {
              return cachedResponse;
            }
            return caches.match('./');
          });
        })
    );
    return;
  }

  // Static assets (images, icons, manifest): Cache-First with Stale-While-Revalidate
  const isStaticAsset = url.pathname.match(/\.(png|jpg|jpeg|svg|ico|json|css|js)$/i) ||
                        url.pathname.endsWith('manifest.json');

  if (isStaticAsset) {
    event.respondWith(
      caches.match(request).then((cachedResponse) => {
        const fetchPromise = fetch(request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return networkResponse;
        }).catch(() => null);

        return cachedResponse || fetchPromise;
      })
    );
    return;
  }

  // Default fallback: Network first, fallback to cache
  event.respondWith(
    fetch(request).catch(() => caches.match(request))
  );
});
