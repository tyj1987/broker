// broker-test/test-session.js — V4.7.0 lib/session.js 单元测试
// 覆盖 createSessionStore 工厂的所有表面:makeSession / getSession /
// deleteSession / deleteSessionsForClient / deleteSessionsForFingerprint /
// login lockout / sliding and absolute expiration

import { readFileSync } from 'node:fs';
import { createSessionStore, SESSION_TTL_MS } from '../broker/lib/session.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

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
  ok(
    'null for non-existent token',
    store.getSession({ headers: { 'x-auth-token': 'bogus' } }) === null,
  );
}

// ============================================================
// sliding expiration
// ============================================================
section('sliding expiration');
{
  const shortStore = createSessionStore({ ttlMs: 50 });
  const tok = shortStore.makeSession({ cn: 'c', client: { role: 'ci' } });
  ok(
    'session immediately retrievable',
    shortStore.getSession({ headers: { 'x-auth-token': tok } }) !== null,
  );
  const expiresBefore = shortStore.getSession({ headers: { 'x-auth-token': tok } }).expiresAt;
  await new Promise((r) => setTimeout(r, 20));
  const expiresAfter = shortStore.getSession({ headers: { 'x-auth-token': tok } }).expiresAt;
  ok('expiresAt slides forward on getSession', expiresAfter > expiresBefore);
}

// ============================================================
// absolute lifetime cap
// ============================================================
section('absolute lifetime');
{
  const absoluteStore = createSessionStore({ ttlMs: 60_000, maxLifetimeMs: 1_000 });
  const tok = absoluteStore.makeSession({
    cn: 'absolute',
    clientName: 'client.absolute',
    client: { role: 'ci' },
  });
  const session = absoluteStore.sessions.get(tok);
  session.createdAt = Date.now() - 1_001;
  session.expiresAt = Date.now() + 60_000;
  ok(
    'absolute lifetime expires an otherwise-active session',
    absoluteStore.getSession({ headers: { 'x-auth-token': tok } }) === null,
  );
  ok('absolute-expired session is removed', !absoluteStore.sessions.has(tok));
}

// ============================================================
// bounded session capacity
// ============================================================
section('bounded session capacity');
{
  let now = 0;
  const boundedStore = createSessionStore({ now: () => now, maxSessions: 2 });
  const make = (cn) =>
    boundedStore.makeSession({
      cn,
      clientName: cn,
      client: { role: 'developer' },
    });
  const first = make('first');
  now = 1;
  const second = make('second');
  now = 2;
  const third = make('third');
  ok('session pool stays at configured capacity', boundedStore.sessions.size === 2);
  ok('oldest session is evicted at capacity', !boundedStore.sessions.has(first));
  ok('newer session remains', boundedStore.sessions.has(second));
  ok('new session is admitted', boundedStore.sessions.has(third));

  now = SESSION_TTL_MS + 10;
  ok('expired-session pruning removes stale entries', boundedStore.pruneExpiredSessions() === 2);
  ok('expired-session pruning empties pool', boundedStore.sessions.size === 0);
}

// ============================================================
// expiration → null
// ============================================================
section('expiration');
{
  const tinyStore = createSessionStore({ ttlMs: 10 });
  const tok = tinyStore.makeSession({ cn: 'c', client: { role: 'ci' } });
  await new Promise((r) => setTimeout(r, 30));
  ok(
    'expired session returns null',
    tinyStore.getSession({ headers: { 'x-auth-token': tok } }) === null,
  );
}

// ============================================================
// deleteSession
// ============================================================
section('deleteSession');
{
  const tok = store.makeSession({ cn: 'c3', client: { role: 'ci' } });
  ok(
    'session exists before delete',
    store.getSession({ headers: { 'x-auth-token': tok } }) !== null,
  );
  store.deleteSession(tok);
  ok('session null after delete', store.getSession({ headers: { 'x-auth-token': tok } }) === null);
  // Idempotent
  store.deleteSession(tok);
  store.deleteSession(null);
  store.deleteSession(undefined);
  ok('deleteSession is idempotent', true);
}

// ============================================================
// deleteSessionsForClient
// ============================================================
section('deleteSessionsForClient');
{
  const revokeStore = createSessionStore();
  const a1 = revokeStore.makeSession({
    cn: 'a1',
    clientName: 'client.a',
    client: { role: 'developer' },
  });
  const a2 = revokeStore.makeSession({
    cn: 'a2',
    clientName: 'client.a',
    client: { role: 'developer' },
  });
  const b1 = revokeStore.makeSession({
    cn: 'b1',
    clientName: 'client.b',
    client: { role: 'developer' },
  });
  ok(
    'client revocation removes every matching session',
    revokeStore.deleteSessionsForClient('client.a') === 2,
  );
  ok('first matching session removed', !revokeStore.sessions.has(a1));
  ok('second matching session removed', !revokeStore.sessions.has(a2));
  ok('other client session preserved', revokeStore.sessions.has(b1));

  const kept = revokeStore.makeSession({
    cn: 'keep',
    clientName: 'client.b',
    client: { role: 'developer' },
  });
  const removed = revokeStore.makeSession({
    cn: 'remove',
    clientName: 'client.b',
    client: { role: 'developer' },
  });
  ok(
    'exceptToken preserves the selected session',
    revokeStore.deleteSessionsForClient('client.b', { exceptToken: kept }) === 2,
  );
  ok('selected session remains', revokeStore.sessions.has(kept));
  ok('other matching session is removed', !revokeStore.sessions.has(removed));
}

// ============================================================
// deleteSessionsForFingerprint
// ============================================================
section('deleteSessionsForFingerprint');
{
  const revokeStore = createSessionStore();
  const old1 = revokeStore.makeSession({
    cn: 'old1',
    fp: 'OLD:FP',
    clientName: 'client.a',
    client: { role: 'developer' },
  });
  const old2 = revokeStore.makeSession({
    cn: 'old2',
    fp: 'OLD:FP',
    clientName: 'client.b',
    client: { role: 'developer' },
  });
  const current = revokeStore.makeSession({
    cn: 'current',
    fp: 'NEW:FP',
    clientName: 'client.a',
    client: { role: 'developer' },
  });
  ok(
    'fingerprint revocation removes every matching session',
    revokeStore.deleteSessionsForFingerprint('OLD:FP') === 2,
  );
  ok('first old-fingerprint session removed', !revokeStore.sessions.has(old1));
  ok('second old-fingerprint session removed', !revokeStore.sessions.has(old2));
  ok('new fingerprint session preserved', revokeStore.sessions.has(current));
  ok('empty fingerprint is a no-op', revokeStore.deleteSessionsForFingerprint('') === 0);
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

  lockStore.recordLoginFail(key); // 3rd fail
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
  await new Promise((r) => setTimeout(r, 60));
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
// bounded login-attempt capacity
// ============================================================
section('bounded login-attempt capacity');
{
  let now = 0;
  const boundedLocks = createSessionStore({
    now: () => now,
    maxLoginAttempts: 2,
    lockoutMs: 100,
    maxFails: 3,
  });
  boundedLocks.recordLoginFail('a');
  boundedLocks.recordLoginFail('b');
  ok('login-attempt pool reaches configured capacity', boundedLocks.loginAttempts.size === 2);
  ok(
    'new key is initially checkable before overflow is recorded',
    boundedLocks.checkLoginLock('c'),
  );
  ok('new key fails closed when pool is full', boundedLocks.recordLoginFail('c') === false);
  ok('overflow protection denies new identities', boundedLocks.checkLoginLock('c') === false);
  ok('active existing identity retains its own state', boundedLocks.checkLoginLock('a') === true);
  ok('overflow does not grow the pool', boundedLocks.loginAttempts.size === 2);
  now = 100;
  ok('expired login-attempt entries are pruned', boundedLocks.pruneLoginAttempts() === 2);
  ok('overflow lock expires with the lockout window', boundedLocks.checkLoginLock('c') === true);
}

// ============================================================
// password-change transaction wiring
// ============================================================
section('password-change transaction wiring');
{
  const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  const passwordRoute = source.slice(
    source.indexOf('// ----- POST /api/v1/me/change-password -----'),
    source.indexOf('// ----- POST /api/v1/me/rotate-cert -----'),
  );
  ok('password change rejects password reuse', passwordRoute.includes('New password must differ'));
  ok(
    'password persistence failure restores previous hash',
    passwordRoute.includes('c.password = previous.password'),
  );
  ok(
    'password persistence failure does not expose internal details',
    passwordRoute.includes("jsonError(res, 500, 'Unable to persist password change')") &&
      !passwordRoute.includes('Persist failed:'),
  );
  ok(
    'successful password change revokes client sessions',
    passwordRoute.includes('deleteSessionsForClient(ctx.clientName)'),
  );
  ok(
    'successful password change clears browser cookie',
    passwordRoute.includes("sessionCookieHeader('', { clear: true })"),
  );
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
