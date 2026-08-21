// broker/lib/index.js — public surface for extracted helpers

export { sopsDecrypt, sopsEncryptAtomic } from './sops.js';
export { send, readBody, jsonError } from './http.js';
export { buildZip, computeCrc32 } from './zip.js';
export { createAudit } from './audit.js';
export { parseRateLimit, createRateLimiter } from './rate-limit.js';
export { isIpAllowed, normalizeIp, matchIpRule } from './ip-allowlist.js';
export {
  createSessionStore,
  SESSION_TTL_MS,
  SESSION_HEADER,
  MAX_LOGIN_FAILS,
  LOGIN_LOCKOUT_MS,
} from './session.js';
export { buildRouteDeps, useModularRoutes } from './build-route-deps.js';
export {
  inc,
  observeMs,
  snapshot,
  prometheusText,
  timedRequest,
  getCounter,
} from './metrics.js';
export { log } from './log.js';
