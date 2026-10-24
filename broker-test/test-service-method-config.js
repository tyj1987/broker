// Execute the actual admin CRUD handlers with synthetic persistence and identity.
// No server sockets, credentials, SOPS files or live provider calls are used.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import {
  DEFAULT_SERVICE_ALLOWED_METHODS,
  effectiveServiceAllowedMethods,
  validateMethod,
} from '../broker/lib/outbound-policy.js';

const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
function section(start, end) {
  const a = source.indexOf(start);
  const b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, `missing production section: ${start}`);
  assert.equal(source.indexOf(start, a + 1), -1, `ambiguous section: ${start}`);
  return source.slice(a, b);
}
const shared = section('const SERVICE_NAME_RE =', '// Get a secret by name.');
const handlers = [
  section('  // ----- GET /api/v1/admin/services -----', '  // ----- /api/v1/admin/services/:name + /test routing -----'),
  section('  // ----- GET /api/v1/admin/services/:name -----', '  // ----- POST /api/v1/admin/services (create) -----'),
  section('  // ----- POST /api/v1/admin/services (create) -----', '  // ----- PUT /api/v1/admin/services/:name (update, PARTIAL) -----'),
  section('  // ----- PUT /api/v1/admin/services/:name (update, PARTIAL) -----', '  // ----- DELETE /api/v1/admin/services/:name -----'),
].join('\n');
const context = vm.createContext({
  URL,
  CONFIG: { services: {} },
  isValidSecretName: value => /^[A-Za-z][A-Za-z0-9_-]*$/.test(value),
  clientNamesAllowedFor: () => ['synthetic-admin'],
  effectiveServiceAllowedMethods,
  readBody: async req => req.body,
  send: (_res, status, body) => ({ status, body }),
  jsonError: (_res, status, error) => ({ status, body: { error } }),
});
let persisted = null;
let writes = 0;
let failWrite = false;
const audit = [];
context.audit = entry => audit.push(JSON.parse(JSON.stringify(entry)));
context.persistConfig = async () => {
  if (failWrite) throw new Error('synthetic disk unavailable');
  persisted = JSON.parse(JSON.stringify(context.CONFIG.services));
  writes += 1;
};
vm.runInContext(shared + `
async function dispatch(m, p, body, role) {
  const req = { body };
  const res = {};
  const ctx = { client: { role }, cn: 'synthetic-admin', fp: 'synthetic-fingerprint' };
  const svcMatch = p.match(/^\\/api\\/v1\\/admin\\/services\\/([a-z][a-z0-9_-]{0,63})$/);
  ${handlers}
  return { status: 404 };
}
`, context);
const dispatch = async (method, path, body, role = 'admin') => {
  const result = await context.dispatch(method, path, body, role);
  return JSON.parse(JSON.stringify(result));
};
const api = '/api/v1/admin/services';
const base = {
  type: 'bearer', upstream: 'https://provider.example.test',
  token_secret: 'SYNTHETIC_TOKEN', allow_paths: ['^/fixed/resource$'],
};
let scenarios = 0;
let response = await dispatch('POST', api, {
  ...base, name: 'fixed_put', allowed_methods: ['get', 'PUT'],
});
assert.equal(response.status, 200);
assert.deepEqual(persisted.fixed_put.allowed_methods, ['GET', 'PUT']);
scenarios += 1;
context.CONFIG.services = JSON.parse(JSON.stringify(persisted));
response = await dispatch('GET', api + '/fixed_put');
assert.deepEqual(response.body.allowed_methods, ['GET', 'PUT']);
scenarios += 1;
response = await dispatch('GET', api);
assert.deepEqual(response.body.services[0].allowed_methods, ['GET', 'PUT']);
scenarios += 1;
response = await dispatch('PUT', api + '/fixed_put', { description: 'metadata only' });
assert.equal(response.status, 200);
assert.deepEqual(persisted.fixed_put.allowed_methods, ['GET', 'PUT']);
assert.deepEqual(persisted.fixed_put.allow_paths, ['^/fixed/resource$']);
assert.equal(persisted.fixed_put.token_secret, 'SYNTHETIC_TOKEN');
scenarios += 1;
assert.equal(validateMethod('PUT', persisted.fixed_put.allowed_methods), 'PUT');
for (const method of ['POST', 'PATCH', 'DELETE']) {
  assert.throws(() => validateMethod(method, persisted.fixed_put.allowed_methods));
}
scenarios += 1;
response = await dispatch('PUT', api + '/fixed_put', { allowed_methods: ['HEAD'] });
assert.equal(response.status, 200);
assert.deepEqual(persisted.fixed_put.allowed_methods, ['HEAD']);
assert.throws(() => validateMethod('PUT', persisted.fixed_put.allowed_methods));
scenarios += 1;
for (const invalid of [null, 'PUT', 1, {}, [null], [123], [''], ['TRACE'],
  ['CONNECT'], ['*'], [' GET'], ['GET\n'], ['GET', 'get'],
  ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'GET']]) {
  const before = JSON.stringify(persisted);
  const count = writes;
  response = await dispatch('POST', api, { ...base, name: 'invalid', allowed_methods: invalid });
  assert.equal(response.status, 400, JSON.stringify(invalid));
  response = await dispatch('PUT', api + '/fixed_put', { allowed_methods: invalid });
  assert.equal(response.status, 400, JSON.stringify(invalid));
  assert.equal(JSON.stringify(persisted), before);
  assert.equal(writes, count, 'invalid data must not persist');
  scenarios += 1;
}
response = await dispatch('PUT', api + '/fixed_put', { allowed_methods: [] });
assert.equal(response.status, 200);
assert.deepEqual(persisted.fixed_put.allowed_methods, []);
for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
  assert.throws(() => validateMethod(method, persisted.fixed_put.allowed_methods));
}
scenarios += 1;
response = await dispatch('POST', api, { ...base, name: 'legacy' });
assert.equal(response.status, 200);
assert.equal(Object.hasOwn(persisted.legacy, 'allowed_methods'), false);
// Unconfigured service: GET is the only default, on both the validateMethod
// default parameter and the effective list the proxy path uses.
assert.deepEqual([...DEFAULT_SERVICE_ALLOWED_METHODS], ['GET']);
assert.ok(Object.isFrozen(DEFAULT_SERVICE_ALLOWED_METHODS));
assert.deepEqual(effectiveServiceAllowedMethods(persisted.legacy), ['GET']);
assert.equal(validateMethod('GET', persisted.legacy.allowed_methods), 'GET');
assert.equal(validateMethod('GET', effectiveServiceAllowedMethods(persisted.legacy)), 'GET');
for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
  assert.throws(() => validateMethod(method, persisted.legacy.allowed_methods), /not permitted/);
  assert.throws(() => validateMethod(method, effectiveServiceAllowedMethods(persisted.legacy)), /not permitted/);
}
scenarios += 1;
// Admin read API reports GET as the effective default.
response = await dispatch('GET', api + '/legacy');
assert.deepEqual(response.body.allowed_methods, ['GET']);
response = await dispatch('GET', api);
assert.deepEqual(response.body.services.find(s => s.name === 'legacy').allowed_methods, ['GET']);
// Mutating a read-back must not widen the shared default.
response.body.services.find(s => s.name === 'legacy').allowed_methods.push('POST');
assert.deepEqual([...DEFAULT_SERVICE_ALLOWED_METHODS], ['GET']);
scenarios += 1;
// An explicitly configured GET/POST service keeps POST.
response = await dispatch('POST', api, { ...base, name: 'explicit_post', allowed_methods: ['GET', 'post'] });
assert.equal(response.status, 200);
assert.deepEqual(persisted.explicit_post.allowed_methods, ['GET', 'POST']);
context.CONFIG.services = JSON.parse(JSON.stringify(persisted));
assert.equal(validateMethod('POST', effectiveServiceAllowedMethods(persisted.explicit_post)), 'POST');
assert.equal(validateMethod('GET', effectiveServiceAllowedMethods(persisted.explicit_post)), 'GET');
assert.throws(() => validateMethod('PUT', effectiveServiceAllowedMethods(persisted.explicit_post)));
response = await dispatch('GET', api + '/explicit_post');
assert.deepEqual(response.body.allowed_methods, ['GET', 'POST']);
scenarios += 1;
// Explicit deny-all is not replaced by the default.
assert.deepEqual(effectiveServiceAllowedMethods({ allowed_methods: [] }), []);
// The proxy path and both admin reads use the shared helper, not literals.
assert.match(source, /validateMethod\(method, effectiveServiceAllowedMethods\(serviceCfg\)\)/);
assert.equal(source.match(/allowed_methods: effectiveServiceAllowedMethods\(svc\)/g)?.length, 2);
assert.doesNotMatch(source, /\['GET', 'POST'\]/);
scenarios += 1;
for (const role of ['reader', 'agent', '']) {
  const before = writes;
  assert.equal((await dispatch('POST', api, { ...base, name: 'forbidden', allowed_methods: ['PUT'] }, role)).status, 403);
  assert.equal((await dispatch('PUT', api + '/legacy', { allowed_methods: ['PUT'] }, role)).status, 403);
  assert.equal((await dispatch('GET', api + '/legacy', undefined, role)).status, 403);
  assert.equal(writes, before);
  scenarios += 1;
}
const beforeFailure = JSON.stringify(context.CONFIG.services);
failWrite = true;
response = await dispatch('PUT', api + '/legacy', { allowed_methods: ['PUT'] });
assert.equal(response.status, 500);
assert.equal(JSON.stringify(context.CONFIG.services), beforeFailure);
failWrite = false;
scenarios += 1;
assert.ok(audit.some(e => e.action === 'admin_services_create' && e.status === 'ok'));
assert.ok(audit.some(e => e.action === 'admin_services_update' && e.status === 'denied'));
assert.ok(audit.some(e => e.action === 'admin_services_update' && e.status === 'error'));
console.log(`service method configuration: ${scenarios} synthetic CRUD/policy scenarios passed`);
