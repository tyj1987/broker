// broker/routes/index.js — Phase B route registry
// Handlers return true when they handled the request.

export { handleHealth } from './health.js';
export { handleStatic, STATIC_MAP } from './static.js';
export { handleAuth } from './auth.js';
export { handleMe } from './me.js';
export { handleSecrets } from './secrets.js';
export { handleServices } from './services.js';
export { handleClients } from './clients.js';
export { handleProxy } from './proxy.js';

import { handleHealth } from './health.js';
import { handleStatic } from './static.js';
import { handleAuth } from './auth.js';
import { handleMe } from './me.js';
import { handleSecrets } from './secrets.js';
import { handleServices } from './services.js';
import { handleClients } from './clients.js';
import { handleProxy } from './proxy.js';

/** Public routes (no session required). */
export const PUBLIC_HANDLERS = [handleHealth, handleStatic];

/**
 * Authenticated API routes. Call only after deps.ctx is set (or handleAuth which is public).
 * Order matters: auth first, then me, then domain APIs, proxy last among these.
 */
export const API_HANDLERS = [
  handleAuth,
  handleMe,
  handleSecrets,
  handleServices,
  handleClients,
  handleProxy,
];

export const ALL_HANDLERS = [...PUBLIC_HANDLERS, ...API_HANDLERS];

/**
 * Run handlers in order until one returns true.
 * @param {Array<Function>} handlers
 * @param  {...any} args req, res, route, deps
 * @returns {Promise<boolean>}
 */
export async function dispatch(handlers, ...args) {
  for (const h of handlers) {
    const r = await h(...args);
    if (r) return true;
  }
  return false;
}
