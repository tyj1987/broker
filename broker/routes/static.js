// broker/routes/static.js — public dashboard static assets
// Phase B.2 extraction from server.js.

import { existsSync, readFileSync } from 'node:fs';
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
};

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
  if (!existsSync(f)) return false;
  const body = readFileSync(f);
  const ct = route.pathname.endsWith('.js') ? 'application/javascript; charset=utf-8'
           : route.pathname.endsWith('.css') ? 'text/css; charset=utf-8'
           : 'text/html; charset=utf-8';
  res.writeHead(200, {
    'Content-Type': ct,
    'Cache-Control': 'no-cache, must-revalidate',
  });
  res.end(body);
  return true;
}

export { STATIC_MAP };
