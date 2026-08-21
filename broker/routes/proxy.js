// broker/routes/proxy.js — /api/v1/proxy/:service/*
// Phase B.4: thin dispatch surface; actual upstream fetch lives in deps.proxyRequest

/**
 * @returns {Promise<boolean>}
 */
export async function handleProxy(req, res, route, deps) {
  const { method, pathname: p } = route;
  const m = p.match(/^\/api\/v1\/proxy\/([^/]+)(\/.*)?$/);
  if (!m) return false;

  const { send, jsonError, audit, ctx, config, proxyRequest, canProxy } = deps;
  if (!ctx?.client) {
    jsonError(res, 401, 'Authentication required');
    return true;
  }

  const serviceName = decodeURIComponent(m[1]);
  const subPath = m[2] || '/';
  const service = (config.services || {})[serviceName];
  if (!service) {
    jsonError(res, 404, 'Service not found');
    return true;
  }

  if (typeof canProxy === 'function' && !canProxy(serviceName, ctx, method, subPath)) {
    audit?.({ action: 'proxy', status: 'denied', service: serviceName, cn: ctx.cn });
    jsonError(res, 403, 'Proxy not allowed for this client/service');
    return true;
  }

  if (typeof proxyRequest !== 'function') {
    jsonError(res, 501, 'proxyRequest not wired');
    return true;
  }

  try {
    await proxyRequest(req, res, { serviceName, service, subPath, method, ctx });
    audit?.({ action: 'proxy', status: 'ok', service: serviceName, cn: ctx.cn, path: subPath });
  } catch (e) {
    audit?.({ action: 'proxy', status: 'error', service: serviceName, error: String(e?.message || e) });
    if (!res.headersSent) jsonError(res, 502, 'Upstream error');
  }
  return true;
}
