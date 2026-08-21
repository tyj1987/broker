// broker/routes/index.js — Phase B route registry
// Handlers return true when they handled the request.

export { handleHealth } from './health.js';
export { handleStatic, STATIC_MAP } from './static.js';
export { handleAuth } from './auth.js';
export { handleMe } from './me.js';

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
