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

/**
 * Canonical public + authenticated handler order for early dispatch.
 * Auth-sensitive handlers still require deps.ctx / getIdentity from server.
 */
export function defaultHandlers() {
  return [
    // public
    // handleHealth / handleStatic are often called first without auth ctx
  ];
}

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
