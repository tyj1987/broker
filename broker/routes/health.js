// broker/routes/health.js — /health, /ready, /live (+ optional dependency probes)
// Phase B.2 + C + F

/**
 * @returns {boolean|Promise<boolean>}
 */
export async function handleHealth(req, res, route, deps) {
  if (route.method !== 'GET') return false;
  const { send, secretCache, config } = deps;
  const p = route.pathname;

  if (p === '/live' || p === '/healthz') {
    send(res, 200, { status: 'live' });
    return true;
  }

  if (p === '/ready' || p === '/readyz') {
    const sopsOk = !deps.requireSops || (secretCache && secretCache.size > 0);
    const cfgOk = !!(config && typeof config === 'object');
    let probesResult = null;
    if (typeof deps.runReadyProbes === 'function') {
      try {
        probesResult = await deps.runReadyProbes();
      } catch (e) {
        probesResult = { ok: false, probes: [], error: String(e?.message || e) };
      }
    }
    const probesOk = !probesResult || probesResult.ok;
    const ready = sopsOk && cfgOk && probesOk;
    send(res, ready ? 200 : 503, {
      status: ready ? 'ready' : 'not_ready',
      sops_loaded: !!(secretCache && secretCache.size > 0),
      config_loaded: cfgOk,
      probes: probesResult?.probes || undefined,
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
