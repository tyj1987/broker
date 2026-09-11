// broker-test/test-session.js — V4.7.0 lib/session.js 单元测试
// 覆盖 createSessionStore 工厂的所有表面:makeSession / getSession /
// deleteSession / checkLoginLock / recordLoginFail / clearLoginLock /
// sliding expiration

import { createSessionStore } from '../broker/lib/session.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

const store = createSessionStore();

// ============================================================
// makeSession + getSession
// ============================================================
section('makeSession + getSession');
{
  const ctx = {
    cn: 'client.alice',
    fp: 'AB:CD:EF:...',
    role: 'developer',
    clientName: 'client.alice',
    cert: { subject: { CN: 'client.alice' } },
    client: { role: 'developer' },
  };
  const token = store.makeSession(ctx);
  ok('returns token string', typeof token === 'string' && token.length >= 32);
  const session = store.getSession({ headers: { 'x-auth-token': token } });
  ok('getSession returns session', session !== null);
  ok('session cn matches', session && session.cn === 'client.alice');
  ok('session role matches', session && session.role === 'developer');
  ok('session clientName matches', session && session.clientName === 'client.alice');
  ok('session has expiresAt', session && typeof session.expiresAt === 'number');
  ok('session has createdAt', session && typeof session.createdAt === 'number');
}

// ============================================================
// getSession via cookie
// ============================================================
section('getSession via cookie');
{
  const token = store.makeSession({ cn: 'c2', client: { role: 'ci' } });
  const session = store.getSession({ headers: { cookie: `broker_session=${token}` } });
  ok('cookie-based session lookup works', session && session.cn === 'c2');
}

// ============================================================
// getSession invalid token
// ============================================================
section('getSession invalid token');
{
  ok('null when no header/cookie', store.getSession({ headers: {} }) === null);
  ok('null for non-existent token', store.getSession({ headers: { 'x-auth-token': 'bogus' } }) === null);
}

// ============================================================
// sliding expiration
// ============================================================
section('sliding expiration');
{
  const shortStore = createSessionStore({ ttlMs: 50 });
  const tok = shortStore.makeSession({ cn: 'c', client: { role: 'ci' } });
  ok('session immediately retrievable', shortStore.getSession({ headers: { 'x-auth-token': tok } }) !== null);
  const expiresBefore = shortStore.getSession({ headers: { 'x-auth-token': tok } }).expiresAt;
  await new Promise(r => setTimeout(r, 20));
  const expiresAfter = shortStore.getSession({ headers: { 'x-auth-token': tok } }).expiresAt;
  ok('expiresAt slides forward on getSession', expiresAfter > expiresBefore);
}

// ============================================================
// expiration → null
// ============================================================
section('expiration');
{
  const tinyStore = createSessionStore({ ttlMs: 10 });
  const tok = tinyStore.makeSession({ cn: 'c', client: { role: 'ci' } });
  await new Promise(r => setTimeout(r, 30));
  ok('expired session returns null', tinyStore.getSession({ headers: { 'x-auth-token': tok } }) === null);
}

// ============================================================
// deleteSession
// ============================================================
section('deleteSession');
{
  const tok = store.makeSession({ cn: 'c3', client: { role: 'ci' } });
  ok('session exists before delete', store.getSession({ headers: { 'x-auth-token': tok } }) !== null);
  store.deleteSession(tok);
  ok('session null after delete', store.getSession({ headers: { 'x-auth-token': tok } }) === null);
  // Idempotent
  store.deleteSession(tok);
  store.deleteSession(null);
  store.deleteSession(undefined);
  ok('deleteSession is idempotent', true);
}

// ============================================================
// checkLoginLock / recordLoginFail / clearLoginLock
// ============================================================
section('login lockout');
{
  const lockStore = createSessionStore({ maxFails: 3, lockoutMs: 60_000 });
  const key = 'client.alice|password';
  ok('no prior fails → unlocked', lockStore.checkLoginLock(key) === true);

  lockStore.recordLoginFail(key);
  lockStore.recordLoginFail(key);
  ok('2 fails → still unlocked', lockStore.checkLoginLock(key) === true);

  lockStore.recordLoginFail(key);  // 3rd fail
  ok('3 fails (== max) → locked', lockStore.checkLoginLock(key) === false);

  // After clearing, unlocked again
  lockStore.clearLoginLock(key);
  ok('after clearLoginLock → unlocked', lockStore.checkLoginLock(key) === true);
}

// ============================================================
// lockout expiry
// ============================================================
section('lockout expiry');
{
  const expStore = createSessionStore({ maxFails: 2, lockoutMs: 30 });
  expStore.recordLoginFail('k1');
  expStore.recordLoginFail('k1');
  ok('locked after max fails', expStore.checkLoginLock('k1') === false);
  await new Promise(r => setTimeout(r, 60));
  ok('unlocked after lockoutMs', expStore.checkLoginLock('k1') === true);
  // After expiry, next fail should reset counter
  expStore.recordLoginFail('k1');
  ok('1 fail after expiry (counter reset)', expStore.checkLoginLock('k1') === true);
}

// ============================================================
// lockout per-key isolation
// ============================================================
section('lockout per-key isolation');
{
  const isoStore = createSessionStore({ maxFails: 2, lockoutMs: 60_000 });
  isoStore.recordLoginFail('client.a|password');
  isoStore.recordLoginFail('client.a|password');
  ok('client.a locked', isoStore.checkLoginLock('client.a|password') === false);
  ok('client.b still unlocked', isoStore.checkLoginLock('client.b|password') === true);
  ok('different mode still unlocked', isoStore.checkLoginLock('client.a|api_key') === true);
}

// ============================================================
// sessions Map exposure
// ============================================================
section('sessions Map exposure');
{
  const tok = store.makeSession({ cn: 'inspect', client: { role: 'ci' } });
  ok('store.sessions is Map', store.sessions instanceof Map);
  ok('sessions Map contains token', store.sessions.has(tok));
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
