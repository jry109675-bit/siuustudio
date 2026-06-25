// SIUU Studio Service Worker
// Strategy: Cache-first for assets, network-first for API calls

const CACHE_NAME = 'siuu-studio-v1';
const STATIC_CACHE = 'siuu-static-v1';
const DYNAMIC_CACHE = 'siuu-dynamic-v1';

// Core app shell - cache on install
const APP_SHELL = [
  '/',
  '/index.html',
  '/siuustudio.html',
  '/siuu-auth.html',
  '/docs.html',
  '/privacy-policy.html',
  '/terms-of-service.html',
  '/password-reset.html',
  '/favicon.svg',
  '/favicon.png',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

// Never cache these - always hit the network
const NETWORK_ONLY = [
  'supabase.co',
  'api.anthropic.com',
  'integrate.api.nvidia.com',
  'api.cerebras.ai',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
];

// ── Install: pre-cache the app shell ──────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then(cache => {
      return cache.addAll(APP_SHELL).catch(err => {
        // Don't fail install if some assets 404 — just skip them
        console.warn('[SW] Some app shell assets failed to cache:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ─────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys
          .filter(key => key !== STATIC_CACHE && key !== DYNAMIC_CACHE)
          .map(key => {
            console.log('[SW] Deleting old cache:', key);
            return caches.delete(key);
          })
      );
    }).then(() => self.clients.claim())
  );
});

// ── Fetch: smart caching strategy ─────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip chrome-extension and other non-http(s) schemes
  if (!url.protocol.startsWith('http')) return;

  // Network-only for API calls and auth
  const isNetworkOnly = NETWORK_ONLY.some(domain => url.hostname.includes(domain));
  if (isNetworkOnly) {
    event.respondWith(fetch(request));
    return;
  }

  // Cache-first for static assets (fonts, images, icons)
  const isStaticAsset = /\.(png|svg|ico|woff2?|ttf|eot)$/i.test(url.pathname);
  if (isStaticAsset) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
    return;
  }

  // Network-first for HTML pages (so updates are always fresh)
  if (request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirst(request, DYNAMIC_CACHE));
    return;
  }

  // Stale-while-revalidate for everything else
  event.respondWith(staleWhileRevalidate(request, DYNAMIC_CACHE));
});

// ── Cache strategies ───────────────────────────────────────

async function cacheFirst(request, cacheName) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return new Response('Offline', { status: 503 });
  }
}

async function networkFirst(request, cacheName) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Fallback to index for navigation requests
    const fallback = await caches.match('/siuustudio.html');
    return fallback || new Response('You are offline. Please check your connection.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  }).catch(() => cached);
  return cached || fetchPromise;
}
