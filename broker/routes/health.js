// broker/routes/health.js — public GET /health
// Phase B.2: first route module. deps: send, SECRET_CACHE, CONFIG, process.uptime

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ method: string, pathname: string }} route
 * @param {object} deps
 * @returns {boolean} true if handled
 */
export function handleHealth(req, res, route, deps) {
  if (route.method !== 'GET' || route.pathname !== '/health') return false;
  const { send, secretCache, config } = deps;
  send(res, 200, {
    status: 'ok',
    version: deps.version,
    sops_loaded: secretCache.size > 0,
    services: Object.keys(config.services || {}),
    uptime_seconds: Math.floor(process.uptime()),
  });
  return true;
}
