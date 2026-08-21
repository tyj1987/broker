// broker-test/test-routes-b4.js
// Run: node broker-test/test-routes-b4.js

import { handleSecrets } from '../broker/routes/secrets.js';
import { handleServices } from '../broker/routes/services.js';
import { handleClients } from '../broker/routes/clients.js';
import { handleProxy } from '../broker/routes/proxy.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

function mockRes() {
  return { status: 0, body: null, setHeader() {}, writeHead() {}, end() {} };
}

console.log('=== secrets list ===');
{
  const res = mockRes();
  const cache = new Map([['FOO', 'bar'], ['BAZ', 'qux']]);
  await handleSecrets({}, res, { method: 'GET', pathname: '/api/v1/secrets' }, {
    send: (r, s, b) => { r.status = s; r.body = b; },
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: { client: { role: 'admin' }, cn: 'a', clientName: 'a' },
    secretCache: cache,
    canAccessSecret: () => true,
  });
  assert(res.status === 200 && res.body.secrets.length === 2, 'list');
}

console.log('=== secrets forbidden without auth ===');
{
  const res = mockRes();
  await handleSecrets({}, res, { method: 'GET', pathname: '/api/v1/secrets' }, {
    send: () => {},
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: null,
    secretCache: new Map(),
  });
  assert(res.status === 401, '401');
}

console.log('=== services list ===');
{
  const res = mockRes();
  await handleServices({}, res, { method: 'GET', pathname: '/api/v1/services' }, {
    send: (r, s, b) => { r.status = s; r.body = b; },
    jsonError: () => {},
    ctx: { client: { role: 'developer' } },
    config: { services: { github: { type: 'http', description: 'gh' } } },
  });
  assert(res.body.services[0].name === 'github', 'service');
}

console.log('=== clients admin only ===');
{
  const res = mockRes();
  await handleClients({}, res, { method: 'GET', pathname: '/api/v1/clients' }, {
    send: () => {},
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: { client: { role: 'developer' }, clientName: 'dev' },
    config: { clients: {} },
  });
  assert(res.status === 403, '403');
}

console.log('=== proxy missing service ===');
{
  const res = mockRes();
  await handleProxy({}, res, { method: 'GET', pathname: '/api/v1/proxy/nope/x' }, {
    send: () => {},
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: { client: { role: 'ci' } },
    config: { services: {} },
  });
  assert(res.status === 404, '404');
}

console.log('=== proxy ok path ===');
{
  const res = mockRes();
  let called = false;
  await handleProxy({}, res, { method: 'GET', pathname: '/api/v1/proxy/gh/repos' }, {
    send: () => {},
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: { client: { role: 'ci' }, cn: 'c' },
    config: { services: { gh: { type: 'http' } } },
    canProxy: () => true,
    proxyRequest: async () => { called = true; res.status = 200; },
    audit: () => {},
  });
  assert(called && res.status === 200, 'proxied');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
