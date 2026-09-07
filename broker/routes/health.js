// broker/routes/health.js — /health, /ready, /live (+ optional dependency probes)
// Public /health is fingerprint-free: { status: "ok" } only.
// Full ops payload is local-socket / authenticated /api/v1/health.

const HEALTH_RATE_MAX = 60;
const HEALTH_RATE_WINDOW_MS = 60_000;
const healthHits = new Map();

export function _resetHealthRateForTests() {
  healthHits.clear();
}

export function buildPublicHealth() {
  return { status: 'ok' };
}

export function buildOpsHealth(deps) {
  const services = deps.config?.services || {};
  return {
    status: 'ok',
    version: deps.version,
    sops_loaded: !!(deps.secretCache && deps.secretCache.size > 0),
    services_count: Object.keys(services).length,
    uptime_seconds: Math.floor(process.uptime()),
  };
}

function clientIp(req) {
  const raw = req?.socket?.remoteAddress || req?.connection?.remoteAddress || '';
  return String(raw).replace(/^::ffff:/, '') || 'unknown';
}

function allowPublicHealth(req) {
  if (!req) return true;
  const ip = clientIp(req);
  const now = Date.now();
  let rec = healthHits.get(ip);
  if (!rec || now > rec.reset) {
    rec = { n: 0, reset: now + HEALTH_RATE_WINDOW_MS };
    healthHits.set(ip, rec);
  }
  rec.n += 1;
  return rec.n <= HEALTH_RATE_MAX;
}

/**
 * @returns {boolean|Promise<boolean>}
 */
export async function handleHealth(req, res, route, deps) {
  if (route.method !== 'GET') return false;
  const { send, secretCache, config } = deps;
  const p = route.pathname;
  const local = deps.surface === 'local';

  if (p === '/live' || p === '/healthz') {
    send(res, 200, { status: 'live' });
    return true;
  }

  if (p === '/ready' || p === '/readyz') {
    // Ready details (sops / probes) stay off the public HTTPS listener.
    if (!local) return false;
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

  if (local) {
    send(res, 200, buildOpsHealth(deps));
    return true;
  }

  if (!allowPublicHealth(req)) {
    if (typeof deps.jsonError === 'function') {
      deps.jsonError(res, 429, 'Too many health checks');
    } else {
      send(res, 429, { error: 'Too many health checks', status: 429 });
    }
    return true;
  }

  send(res, 200, buildPublicHealth());
  return true;
}
