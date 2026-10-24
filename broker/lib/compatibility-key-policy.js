// Bearer credentials narrow an identity; they never authorize legacy account,
// certificate, secret-management or operator endpoints through the owner's role.
// Typed v2 operations retain their own policy/approval pipeline.
import { canCreateChild } from '../api-keys.js';

export function isCompatibilityKeyRouteAllowed(key, method, pathname) {
  if (!key) return true;
  if (!Array.isArray(key.scopes)) return false;
  const has = scope => key.scopes.includes(scope);
  if (method === 'GET' && pathname === '/api/v1/identity') return true;
  if (method === 'GET' && pathname === '/api/v1/services') return has('services:proxy');
  if ((method === 'GET' && pathname === '/api/v1/secrets')
      || (method === 'POST' && pathname === '/api/v1/secrets/resolve')) return has('secrets:resolve');
  if (method === 'POST' && /^\/api\/v1\/proxy\/[a-z0-9_-]+$/.test(pathname)) return has('services:proxy');
  if (method === 'POST' && pathname === '/api/v1/api-keys/issue-child') return canCreateChild(key).ok;
  return false;
}
