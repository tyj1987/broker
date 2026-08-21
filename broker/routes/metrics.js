// broker/routes/metrics.js — GET /metrics and GET /metrics.json
// Phase C. Public by default; set METRICS_REQUIRE_AUTH=1 + deps.ctx admin to lock down.

import { snapshot, prometheusText } from '../lib/metrics.js';

/**
 * @returns {boolean|Promise<boolean>}
 */
export function handleMetrics(req, res, route, deps) {
  const { method, pathname: p } = route;
  if (method !== 'GET') return false;
  if (p !== '/metrics' && p !== '/metrics.json') return false;

  const requireAuth = process.env.METRICS_REQUIRE_AUTH === '1'
    || process.env.METRICS_REQUIRE_AUTH === 'true';
  if (requireAuth) {
    if (!deps.ctx?.client || deps.ctx.client.role !== 'admin') {
      deps.jsonError?.(res, 401, 'Metrics require admin auth');
      return true;
    }
  }

  if (p === '/metrics.json') {
    deps.send(res, 200, snapshot());
    return true;
  }

  // Prometheus text
  const body = prometheusText({
    version: deps.version || 'unknown',
  });
  res.writeHead(200, {
    'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
  return true;
}
