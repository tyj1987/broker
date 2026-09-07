// broker/routes/static.js — public dashboard static assets
// Phase B.2 extraction from server.js.
// HTML: no-cache. JS/CSS: short cache + ETag so repeat visits skip the body.

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

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

const etagCache = new Map(); // abs path -> { mtime, size, etag }

function fileMeta(f) {
  const st = statSync(f);
  const prev = etagCache.get(f);
  if (prev && prev.mtime === st.mtimeMs && prev.size === st.size) return prev;
  const etag = `"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
  const rec = { mtime: st.mtimeMs, size: st.size, etag };
  etagCache.set(f, rec);
  return rec;
}

function isHtmlPath(pathname) {
  return pathname === '/' || pathname.endsWith('.html');
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').IncomingMessage} res
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
    });
    res.end(payload);
    return true;
  }
  const meta = fileMeta(f);
  const html = isHtmlPath(route.pathname);
  const cacheControl = html
    ? 'no-cache, must-revalidate'
    : 'public, max-age=300, must-revalidate';
  const headers = {
    'ETag': meta.etag,
    'Cache-Control': cacheControl,
  };
  const inm = req?.headers?.['if-none-match'];
  if (inm && inm === meta.etag) {
    res.writeHead(304, headers);
    res.end();
    return true;
  }
  const body = readFileSync(f);
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
