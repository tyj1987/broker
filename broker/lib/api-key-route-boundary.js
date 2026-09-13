// Compatibility API boundary for delegated Bearer identities.
// API keys are capabilities, not interactive administrator sessions.  Keep
// the allowlist deliberately small; new legacy routes must opt in explicitly.

const READ_ONLY = new Set([
  'GET /api/v1/identity',
  'GET /api/v1/services',
  'GET /api/v1/secrets',
  'GET /api/v1/healthcheck/status',
]);

export function isApiKeyLegacyRouteAllowed(method, pathname) {
  const key = `${String(method || '').toUpperCase()} ${String(pathname || '')}`;
  if (READ_ONLY.has(key)) return true;
  if (key === 'POST /api/v1/logout') return true;
  if (key === 'POST /api/v1/secrets/resolve') return true;
  if (key === 'POST /api/v1/api-keys/issue-child') return true;
  if (String(method || '').toUpperCase() === 'POST'
      && /^\/api\/v1\/proxy\/[a-z0-9_-]+$/.test(String(pathname || ''))) return true;
  return false;
}

