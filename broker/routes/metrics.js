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

  // Default: local scrape or admin. METRICS_PUBLIC=1 restores the old anonymous scrape.
  const publicOk = process.env.METRICS_PUBLIC === '1'
    || process.env.METRICS_REQUIRE_AUTH === '0'
    || process.env.METRICS_REQUIRE_AUTH === 'false';
  const fromLocal = deps.isLocal === true;
  const isAdmin = deps.ctx?.client?.role === 'admin';
  if (!publicOk && !fromLocal && !isAdmin) {
    if (typeof deps.jsonError === 'function') {
      deps.jsonError(res, 401, 'Metrics require admin auth or local scrape');
    } else {
      deps.send(res, 401, { error: 'Metrics require admin auth or local scrape', status: 401 });
    }
    return true;
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
