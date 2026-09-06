// broker-test/test-routes-phase-b2.js
// Run: node broker-test/test-routes-phase-b2.js

import { handleHealth } from '../broker/routes/health.js';
import { handleStatic, STATIC_MAP } from '../broker/routes/static.js';
import { dispatch } from '../broker/routes/index.js';
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
  assert(payload?.version === BROKER_VERSION, 'version');
  assert(payload?.sops_loaded === true, 'sops_loaded');
  assert(Array.isArray(payload?.services) && payload.services.includes('github'), 'services');
  assert(await handleHealth({}, res, { method: 'POST', pathname: '/health' }, { send }) === false, 'POST not handled');
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

console.log('=== dispatch ===');
{
  let order = [];
  const h1 = async () => { order.push(1); return false; };
  const h2 = async () => { order.push(2); return true; };
  const h3 = async () => { order.push(3); return true; };
  const r = await dispatch([h1, h2, h3]);
  assert(r === true, 'dispatch stops');
  assert(order.join(',') === '1,2', 'order');
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
  assert(SESSION_TTL_MS === 15 * 60 * 1000, 'default TTL const');
}

console.log('=== session revocation and current authorization ===');
{
  const clients = { admin: { role: 'admin', cert_fingerprint_sha256: 'AA' } };
  const store = createSessionStore({ ttlMs: 60_000, resolveClient: name => clients[name] });
  const token = store.makeSession({ cn: 'a', fp: 'aa', clientName: 'admin', client: clients.admin, cert: {} });
  const req = { headers: { [store.header]: token } };
  assert(store.getSession(req)?.role === 'admin', 'current client accepted');
  clients.admin = { role: 'readonly', cert_fingerprint_sha256: 'AA' };
  assert(store.getSession(req)?.role === 'readonly', 'role downgrade takes effect immediately');
  clients.admin.cert_fingerprint_sha256 = 'BB';
  assert(store.getSession(req) === null, 'certificate rotation revokes bound session');

  const webToken = store.makeSession({ cn: 'a@webauthn', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  const webReq = { headers: { cookie: `other=x; broker_session=${webToken}` } };
  assert(!!store.getSession(webReq), 'webauthn session accepted');
  clients.admin.disabled = true;
  assert(store.getSession(webReq) === null, 'disabled client session revoked');

  clients.admin = { role: 'admin', cert_fingerprint_sha256: 'CC', revoked_at: new Date().toISOString() };
  const revokedToken = store.makeSession({ cn: 'revoked', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  assert(store.getSession({ headers: { [store.header]: revokedToken } }) === null, 'revoked client session denied');

  clients.admin = { role: 'admin', cert_fingerprint_sha256: 'CC' };
  const missingToken = store.makeSession({ cn: 'missing', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  delete clients.admin;
  assert(store.getSession({ headers: { [store.header]: missingToken } }) === null, 'deleted client session denied');

  clients.admin = { role: 'admin', cert_fingerprint_sha256: 'CC' };
  const one = store.makeSession({ cn: 'one', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  const two = store.makeSession({ cn: 'two', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  assert(store.deleteSessionsForClient('admin') === 2, 'all client sessions revoked');
  assert(store.getSession({ headers: { [store.header]: one } }) === null && store.getSession({ headers: { [store.header]: two } }) === null, 'revoked sessions unusable');

  const expiredStore = createSessionStore({ ttlMs: -1, resolveClient: name => clients[name] });
  const expired = expiredStore.makeSession({ cn: 'expired', fp: null, clientName: 'admin', client: clients.admin, cert: {} });
  assert(expiredStore.getSession({ headers: { [expiredStore.header]: expired } }) === null, 'expired session removed');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
