// broker/routes/health.js — /health, /ready, /live
// Phase B.2 + C readiness/liveness

/**
 * @returns {boolean}
 */
export function handleHealth(req, res, route, deps) {
  if (route.method !== 'GET') return false;
  const { send, secretCache, config } = deps;
  const p = route.pathname;

  // Liveness: process is up
  if (p === '/live' || p === '/healthz') {
    send(res, 200, { status: 'live' });
    return true;
  }

  // Readiness: config + optional sops loaded
  if (p === '/ready' || p === '/readyz') {
    const sopsOk = !deps.requireSops || (secretCache && secretCache.size > 0);
    const cfgOk = !!(config && typeof config === 'object');
    const ready = sopsOk && cfgOk;
    send(res, ready ? 200 : 503, {
      status: ready ? 'ready' : 'not_ready',
      sops_loaded: !!(secretCache && secretCache.size > 0),
      config_loaded: cfgOk,
    });
    return true;
  }

  if (p !== '/health') return false;

  send(res, 200, {
    status: 'ok',
    version: deps.version,
    sops_loaded: !!(secretCache && secretCache.size > 0),
    services: Object.keys(config?.services || {}),
    uptime_seconds: Math.floor(process.uptime()),
  });
  return true;
}
