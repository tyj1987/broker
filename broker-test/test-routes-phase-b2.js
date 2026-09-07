// broker-test/test-routes-phase-b2.js
// Run: node broker-test/test-routes-phase-b2.js

import { handleHealth } from '../broker/routes/health.js';
import { handleStatic, STATIC_MAP } from '../broker/routes/static.js';
// chore/oss-modular-security: dispatcher (routes/index.js) removed.
// `dispatch([h1, h2, h3])` returned true once any handler returned true;
// its only test block has been dropped with the dispatcher. Inline path
// coverage lives in broker/server.js + broker-test/test-*.js.
import { createSessionStore, SESSION_TTL_MS } from '../broker/lib/session.js';
import { BROKER_VERSION } from '../broker/version.js';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

function mockRes() {
  return {
    status: 0,
    headers: {},
    body: null,
    writeHead(s, h) { this.status = s; this.headers = h || {}; },
    end(b) { this.body = b; },
  };
}

console.log('=== handleHealth ===');
{
  const res = mockRes();
  let payload = null;
  const send = (_res, status, body) => {
    _res.status = status;
    payload = body;
    _res.end(JSON.stringify(body));
  };
  const handled = await handleHealth({}, res, { method: 'GET', pathname: '/health' }, {
    send,
    version: BROKER_VERSION,
    secretCache: new Map([['X', {}]]),
    config: { services: { github: {} } },
  });
  assert(handled === true, 'handles /health');
  assert(payload?.status === 'ok', 'status ok');
  assert(payload?.version === undefined, 'public /health has no version');
  assert(payload?.sops_loaded === undefined, 'public /health has no sops_loaded');
  assert(payload?.services === undefined, 'public /health has no services');
  assert(payload?.uptime_seconds === undefined, 'public /health has no uptime');
  assert(await handleHealth({}, res, { method: 'POST', pathname: '/health' }, { send }) === false, 'POST not handled');
}
{
  const res = mockRes();
  let payload = null;
  const send = (_res, status, body) => {
    _res.status = status;
    payload = body;
    _res.end(JSON.stringify(body));
  };
  await handleHealth({}, res, { method: 'GET', pathname: '/health' }, {
    send,
    version: BROKER_VERSION,
    secretCache: new Map([['X', {}]]),
    config: { services: { github: {} } },
    surface: 'local',
  });
  assert(payload?.version === BROKER_VERSION, 'local /health version');
  assert(payload?.sops_loaded === true, 'local /health sops_loaded');
  assert(payload?.services_count === 1, 'local /health services_count');
  assert(payload?.services === undefined, 'local /health does not list service names');
}
{
  const res = mockRes();
  const send = (_res, status, body) => { _res.status = status; _res.body = body; };
  const hidden = await handleHealth({}, res, { method: 'GET', pathname: '/ready' }, {
    send, secretCache: new Map([['X', {}]]), config: {}, surface: 'public',
  });
  assert(hidden === false, 'public /ready is not handled');
}

console.log('=== handleStatic ===');
{
  const dir = mkdtempSync(join(tmpdir(), 'broker-dash-'));
  writeFileSync(join(dir, 'index.html'), '<html>ok</html>');
  const res = mockRes();
  const ok = handleStatic({}, res, { method: 'GET', pathname: '/' }, { dashboardDir: dir });
  assert(ok === true, 'serves /');
  assert(res.status === 200, '200');
  assert(String(res.body).includes('ok'), 'body');
  assert(handleStatic({}, res, { method: 'GET', pathname: '/nope' }, { dashboardDir: dir }) === false, 'unknown path');
  assert(Object.keys(STATIC_MAP).length >= 10, 'STATIC_MAP size');
  rmSync(dir, { recursive: true, force: true });
}

console.log('=== createSessionStore ===');
{
  const store = createSessionStore({ ttlMs: 60_000 });
  const client = { role: 'admin' };
  const tok = store.makeSession({ cn: 'a', fp: 'f', clientName: 'admin', client, cert: {} });
  assert(typeof tok === 'string' && tok.length > 10, 'token');
  const req = { headers: { [store.header]: tok } };
  const s = store.getSession(req);
  assert(s && s.cn === 'a' && s.role === 'admin', 'getSession');
  assert(store.checkLoginLock('u|pw') === true, 'lock open');
  for (let i = 0; i < 5; i++) store.recordLoginFail('u|pw');
  assert(store.checkLoginLock('u|pw') === false, 'locked after fails');
  store.clearLoginLock('u|pw');
  assert(store.checkLoginLock('u|pw') === true, 'cleared');
  assert(SESSION_TTL_MS === 30 * 60 * 1000, 'default TTL const');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
