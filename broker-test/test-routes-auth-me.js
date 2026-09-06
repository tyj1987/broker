// broker-test/test-routes-auth-me.js
// Run: node broker-test/test-routes-auth-me.js

import { handleAuth } from '../broker/routes/auth.js';
import { handleMe } from '../broker/routes/me.js';
import { createMfaPending, getMfaPending, consumeMfaPending, isMfaRequired, MFA_TOKEN_TTL_MS } from '../broker/auth-flow.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

function mockRes() {
  const headers = {};
  return {
    status: 0,
    body: null,
    headers,
    setHeader(k, v) { headers[k] = v; },
    writeHead() {},
    end(b) { this.body = b; },
  };
}

function baseDeps(over = {}) {
  const sessions = new Map();
  return {
    send: (res, status, body) => { res.status = status; res.body = body; },
    jsonError: (res, status, msg) => { res.status = status; res.body = { error: msg, status }; },
    readBody: async () => ({}),
    audit: () => {},
    config: { security_profile: 'compatibility', clients: { alice: { role: 'developer', password: 'scrypt$x', allow_password_login: true } } },
    getIdentity: () => null,
    verifyClientPassword: async () => true,
    isMfaRequired: () => false,
    createMfaPending,
    getMfaPending,
    consumeMfaPending,
    verifyMfaCode: () => ({ ok: true, method: 'totp' }),
    MFA_TOKEN_TTL_MS,
    makeSession: () => 'tok-test',
    deleteSession: (t) => sessions.delete(t),
    sessions,
    checkLoginLock: () => true,
    recordLoginFail: () => {},
    clearLoginLock: () => {},
    SESSION_TTL_MS: 1800000,
    SESSION_HEADER: 'x-auth-token',
    ...over,
  };
}

console.log('=== handleAuth login missing password ===');
{
  const res = mockRes();
  const deps = baseDeps({ readBody: async () => ({}) });
  const h = await handleAuth({}, res, { method: 'POST', pathname: '/api/v1/login' }, deps);
  assert(h === true, 'handled');
  assert(res.status === 400, '400');
}

console.log('=== handleAuth password login ok ===');
{
  const res = mockRes();
  const deps = baseDeps({
    readBody: async () => ({ client: 'alice', password: 'secret' }),
  });
  const h = await handleAuth({}, res, { method: 'POST', pathname: '/api/v1/login' }, deps);
  assert(h === true, 'handled');
  assert(res.status === 200 && !res.body?.token, 'session token absent from response body');
  assert(String(res.headers['Set-Cookie'] || '').includes('HttpOnly'), 'session delivered as HttpOnly cookie');
  assert(res.body?.via === 'password', 'via password');
}

console.log('=== handleAuth strict rejects legacy login ===');
{
  const res = mockRes();
  const deps = baseDeps({
    config: { security_profile: 'strict', clients: { alice: { role: 'admin', allow_password_login: true } } },
    readBody: async () => ({ client: 'alice', password: 'secret' }),
  });
  await handleAuth({}, res, { method: 'POST', pathname: '/api/v1/login' }, deps);
  assert(res.status === 403, 'strict legacy login denied');
}

console.log('=== handleAuth controlled mTLS needs no password ===');
{
  const res = mockRes();
  const client = { role: 'developer', allow_password_login: false };
  const deps = baseDeps({
    config: { security_profile: 'controlled', clients: { alice: client } },
    readBody: async () => ({}),
    getIdentity: () => ({ via: 'mtls-via-nginx', cn: 'alice', fp: 'AA', clientName: 'alice', client }),
    verifyClientPassword: async () => { throw new Error('password verifier must not run'); },
  });
  await handleAuth({}, res, { method: 'POST', pathname: '/api/v1/login' }, deps);
  assert(res.status === 200 && res.body?.via === 'mtls', 'controlled mTLS session created');
}

console.log('=== handleAuth logout ===');
{
  const res = mockRes();
  const deps = baseDeps();
  const h = await handleAuth(
    { headers: { 'x-auth-token': 'x' } },
    res,
    { method: 'POST', pathname: '/api/v1/logout' },
    deps,
  );
  assert(h === true, 'handled');
  assert(res.body?.logged_out === true, 'logged_out');
}

console.log('=== handleAuth non-match ===');
{
  const h = await handleAuth({}, mockRes(), { method: 'GET', pathname: '/api/v1/me' }, baseDeps());
  assert(h === false, 'not auth route');
}

console.log('=== handleMe profile ===');
{
  const res = mockRes();
  const deps = {
    send: (r, s, b) => { r.status = s; r.body = b; },
    jsonError: (r, s, m) => { r.status = s; r.body = { error: m }; },
    ctx: {
      clientName: 'alice',
      cn: 'alice',
      client: { role: 'developer', description: 'd', totp_secret: null },
    },
    certPaths: { clientPaths: () => ({ crt: '/no', key: '/no' }) },
    existsSync: () => false,
  };
  const h = await handleMe({}, res, { method: 'GET', pathname: '/api/v1/me' }, deps);
  assert(h === true, 'handled');
  assert(res.body?.name === 'alice' && res.body?.role === 'developer', 'profile');
  assert(res.body?.totp_enabled === false, 'no totp');
}

console.log('=== isMfaRequired sanity ===');
{
  assert(isMfaRequired({ totp_secret: 'ABC' }, 'password') === true, 'totp required');
  assert(isMfaRequired({}, 'password') === false, 'no totp');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
