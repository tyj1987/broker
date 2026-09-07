// Default admin "Test" action: prefer the service's first dashboard_action,
// else the matching service template. Avoids GET / on API roots (Cloudflare
// 301s https://api.cloudflare.com/client/v4/ ).

import { SERVICE_TEMPLATES } from '../service-templates.js';

function hostnameOf(upstream) {
  try { return new URL(upstream).hostname.toLowerCase(); } catch { return ''; }
}

function firstUsefulAction(actions) {
  if (!Array.isArray(actions)) return null;
  for (const a of actions) {
    if (!a || !a.path) continue;
    const path = String(a.path);
    if (path === '/' || path === '') continue;
    return a;
  }
  return null;
}

export function matchServiceTemplate(svc, templates = SERVICE_TEMPLATES) {
  if (!svc || typeof svc !== 'object') return null;
  const name = String(svc.name || svc.suggested_name || '').toLowerCase();
  if (name && templates[name]) return { id: name, ...templates[name] };
  const host = hostnameOf(svc.upstream);
  if (!host) return null;
  for (const [id, t] of Object.entries(templates)) {
    if (hostnameOf(t.upstream) === host) return { id, ...t };
  }
  return null;
}

/**
 * Pick method/path/query for POST /admin/services/:name/test when the
 * dashboard sends an empty body.
 */
export function defaultServiceTest(svc, templates = SERVICE_TEMPLATES) {
  const fromSvc = firstUsefulAction(svc && svc.dashboard_actions);
  if (fromSvc) {
    return {
      method: String(fromSvc.method || 'GET').toUpperCase(),
      path: fromSvc.path,
      query: fromSvc.query,
    };
  }
  const tpl = matchServiceTemplate(svc, templates);
  const fromTpl = firstUsefulAction(tpl && tpl.dashboard_actions);
  if (fromTpl) {
    return {
      method: String(fromTpl.method || 'GET').toUpperCase(),
      path: fromTpl.path,
      query: fromTpl.query,
    };
  }
  return { method: 'GET', path: '/' };
}

/**
 * Classify an upstream HTTP status for the admin test UI.
 * 2xx = ok; 3xx is reachability, not success (do not call it a network failure).
 */
export function describeUpstreamStatus(status, { path, hostname } = {}) {
  const code = Number(status) || 0;
  if (code >= 200 && code < 300) return { ok: true };
  if (code >= 300 && code < 400) {
    const cf = hostname && /cloudflare/i.test(hostname);
    const hint = cf
      ? 'Cloudflare API root redirects; use GET /user/tokens/verify'
      : 'the test path is probably the API root, not a documented action';
    return {
      ok: false,
      error: `upstream redirected (${code}) — ${hint}${path ? ` (path=${path})` : ''}`,
    };
  }
  return { ok: false };
}
