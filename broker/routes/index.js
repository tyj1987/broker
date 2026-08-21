// broker/routes/index.js — Phase B–F route registry

export { handleHealth } from './health.js';
export { handleStatic, STATIC_MAP } from './static.js';
export { handleAuth } from './auth.js';
export { handleMe } from './me.js';
export { handleSecrets } from './secrets.js';
export { handleServices } from './services.js';
export { handleClients } from './clients.js';
export { handleProxy } from './proxy.js';
export { handleMetrics } from './metrics.js';
export { handleOps } from './ops.js';

import { handleHealth } from './health.js';
import { handleStatic } from './static.js';
import { handleAuth } from './auth.js';
import { handleMe } from './me.js';
import { handleSecrets } from './secrets.js';
import { handleServices } from './services.js';
import { handleClients } from './clients.js';
import { handleProxy } from './proxy.js';
import { handleMetrics } from './metrics.js';
import { handleOps } from './ops.js';

export const PUBLIC_HANDLERS = [handleHealth, handleStatic, handleMetrics];

export const API_HANDLERS = [
  handleAuth,
  handleMe,
  handleSecrets,
  handleServices,
  handleClients,
  handleProxy,
  handleOps,
];

export const ALL_HANDLERS = [...PUBLIC_HANDLERS, ...API_HANDLERS];

export async function dispatch(handlers, ...args) {
  for (const h of handlers) {
    const r = await h(...args);
    if (r) return true;
  }
  return false;
}
