import assert from 'node:assert/strict';
import { isApiKeyLegacyRouteAllowed } from '../broker/lib/api-key-route-boundary.js';

const allowed = [
  ['GET', '/api/v1/identity'],
  ['GET', '/api/v1/services'],
  ['GET', '/api/v1/secrets'],
  ['GET', '/api/v1/healthcheck/status'],
  ['POST', '/api/v1/logout'],
  ['POST', '/api/v1/secrets/resolve'],
  ['POST', '/api/v1/api-keys/issue-child'],
  ['POST', '/api/v1/proxy/github'],
];
for (const [method, path] of allowed) assert.equal(isApiKeyLegacyRouteAllowed(method, path), true, `${method} ${path}`);

const denied = [
  ['GET', '/api/v1/api-keys'],
  ['POST', '/api/v1/api-keys'],
  ['POST', '/api/v1/api-keys/master'],
  ['GET', '/api/v1/admin/secrets'],
  ['PUT', '/api/v1/admin/secrets/GITHUB_PAT'],
  ['DELETE', '/api/v1/admin/clients/alice'],
  ['POST', '/api/v1/healthcheck/run'],
  ['GET', '/api/v1/audit'],
  ['POST', '/api/v1/reload'],
  ['POST', '/api/v1/rotate/GITHUB_PAT'],
  ['POST', '/api/v1/ssh/exec'],
  ['GET', '/api/v1/me'],
  ['POST', '/api/v1/proxy/../admin'],
];
for (const [method, path] of denied) assert.equal(isApiKeyLegacyRouteAllowed(method, path), false, `${method} ${path}`);

console.log('API-key legacy route boundary: allowlist and admin-route denial passed');
