// broker/routes/static.js — public dashboard static assets
// Phase B.2 extraction from server.js.
// HTML: no-cache. JS/CSS: short cache + ETag so repeat visits skip the body.

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { securityHeaders } from '../lib/security-headers.js';

const STATIC_MAP = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/app.js': 'app.js',
  '/style.css': 'style.css',
  '/home.js': 'home.js',
  '/me.html': 'me.html',
  '/me.js': 'me.js',
  '/api-keys.html': 'api-keys.html',
  '/api-keys.js': 'api-keys.js',
  '/admin/secrets.js': 'admin/secrets.js',
  '/admin/services.js': 'admin/services.js',
  '/admin/clients.js': 'admin/clients.js',
  '/admin/audit.js': 'admin/audit.js',
  '/llms.txt': 'llms.txt',
};

// ETag + body cache. Dashboard assets are small and rarely change after deploy,
// so caching the body in memory turns repeat reads into zero-FS-syscall hits.
// We track mtime+size; if the file changes (during config reload, dev mode), we
// drop the body cache. Body is Buffer (not string) so we can compute Content-Length
// without re-encoding.
const metaCache = new Map(); // abs path -> { mtime, size, etag, body: Buffer|null }
const MAX_BODY_CACHE_BYTES = 512 * 1024; // don't bother caching >512KB assets
const BODY_CACHE_TTL_MS = 60_000;        // re-stat every minute in dev mode
let lastStatSweep = 0;

function fileMeta(f) {
  // Throttle stat() to once per minute when not in dev — saves syscalls in prod.
  const now = Date.now();
  const cached = metaCache.get(f);
  if (cached && (now - lastStatSweep) < BODY_CACHE_TTL_MS) return cached;
  lastStatSweep = now;
  const st = statSync(f);
  // File changed (size or mtime) → invalidate body
  if (!cached || cached.mtime !== st.mtimeMs || cached.size !== st.size) {
    const etag = `"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
    const next = { mtime: st.mtimeMs, size: st.size, etag, body: null };
    metaCache.set(f, next);
    return next;
  }
  return cached;
}

function loadBody(f, meta) {
  if (meta.body) return meta.body;
  if (meta.size > MAX_BODY_CACHE_BYTES) {
    // don't cache huge bodies; read fresh each time
    return readFileSync(f);
  }
  const buf = readFileSync(f);
  meta.body = buf; // mutate cached entry to include body
  return buf;
}

function isHtmlPath(pathname) {
  return pathname === '/' || pathname.endsWith('.html');
}

// HTTP allows multiple ETags in If-None-Match (comma-separated, may be `*`).
function clientHasEtag(inm, ourEtag) {
  if (!inm) return false;
  if (inm.trim() === '*') return true;
  // split on commas, trim quotes/whitespace
  const candidates = inm.split(',').map(s => s.trim());
  return candidates.some(c => c === ourEtag);
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ method: string, pathname: string }} route
 * @param {{ dashboardDir: string }} deps
 * @returns {boolean} true if handled
 */
export function handleStatic(req, res, route, deps) {
  if (route.method !== 'GET') return false;
  const name = STATIC_MAP[route.pathname];
  if (!name) return false;
  const f = join(deps.dashboardDir, name);
  if (!existsSync(f)) {
    // Known dashboard path but the file is missing — do NOT fall through to mTLS 401.
    const payload = JSON.stringify({ error: 'dashboard asset missing', path: route.pathname, status: 500 });
    res.writeHead(500, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Length': Buffer.byteLength(payload),
      ...securityHeaders({ kind: 'json' }),
    });
    res.end(payload);
    return true;
  }
  const meta = fileMeta(f);
  const html = isHtmlPath(route.pathname);
  const cacheControl = html
    ? 'no-cache, must-revalidate'
    : 'public, max-age=300, must-revalidate';
  const kind = html ? 'html' : 'static';
  const sec = securityHeaders({ kind });
  const headers = {
    ...sec,
    'ETag': meta.etag,
    'Cache-Control': cacheControl,
  };
  const inm = req?.headers?.['if-none-match'];
  if (clientHasEtag(inm, meta.etag)) {
    // 304 Not Modified: must include ETag + Cache-Control but no body.
    res.writeHead(304, headers);
    res.end();
    return true;
  }
  const body = loadBody(f, meta);
  const ct = route.pathname.endsWith('.js') ? 'application/javascript; charset=utf-8'
           : route.pathname.endsWith('.css') ? 'text/css; charset=utf-8'
           : route.pathname.endsWith('.txt') ? 'text/plain; charset=utf-8'
           : 'text/html; charset=utf-8';
  res.writeHead(200, {
    'Content-Type': ct,
    'Content-Length': body.length,
    ...headers,
  });
  res.end(body);
  return true;
}

export { STATIC_MAP };

// Test-only helpers (not part of public API; imported by tests)
export const _internals = {
  clientHasEtag,
  fileMeta,
  metaCache,
  MAX_BODY_CACHE_BYTES,
};
