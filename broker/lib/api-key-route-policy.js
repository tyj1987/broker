// broker/lib/api-key-route-policy.js — HTTP surface available to delegated API keys.
//
// API keys are capability tokens, not interactive account sessions. They may
// use delegated data/proxy APIs and a master key may mint child keys, but they
// must not manage the owning account or enumerate/revoke sibling keys.

export function isApiKeyRouteAllowed(method, pathname) {
  const m = String(method || 'GET').toUpperCase();
  const p = String(pathname || '');

  if (p === '/api/v1/me/audit') return m === 'GET';

  if (p === '/api/v1/api-keys/issue-child') return m === 'POST';

  if (p === '/api/v1/me' || p.startsWith('/api/v1/me/')) return false;
  if (p === '/api/v1/api-keys' || p.startsWith('/api/v1/api-keys/')) return false;

  return true;
}
