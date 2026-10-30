// broker/lib/session.js — bounded dashboard sessions + login lockout

import { randomUUID } from 'node:crypto';

export const SESSION_TTL_MS = 30 * 60 * 1000; // 30 min sliding idle timeout
export const SESSION_MAX_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8h absolute lifetime
export const SESSION_MAX_ENTRIES = 10_000;
export const SESSION_HEADER = 'x-auth-token';
export const MAX_LOGIN_FAILS = 5;
export const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
export const LOGIN_ATTEMPT_MAX_ENTRIES = 50_000;

/**
 * @returns {{
 *   makeSession: Function,
 *   getSession: Function,
 *   deleteSession: Function,
 *   deleteSessionsForClient: Function,
 *   deleteSessionsForFingerprint: Function,
 *   checkLoginLock: Function,
 *   recordLoginFail: Function,
 *   clearLoginLock: Function,
 *   pruneExpiredSessions: Function,
 *   pruneLoginAttempts: Function,
 *   sessions: Map,
 *   loginAttempts: Map,
 * }}
 */
export function createSessionStore(opts = {}) {
  const ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
  const maxLifetimeMs = opts.maxLifetimeMs ?? SESSION_MAX_LIFETIME_MS;
  const maxSessions = positiveInteger(opts.maxSessions, SESSION_MAX_ENTRIES);
  const header = opts.header ?? SESSION_HEADER;
  const maxFails = positiveInteger(opts.maxFails, MAX_LOGIN_FAILS);
  const lockoutMs = positiveInteger(opts.lockoutMs, LOGIN_LOCKOUT_MS);
  const maxLoginAttempts = positiveInteger(opts.maxLoginAttempts, LOGIN_ATTEMPT_MAX_ENTRIES);
  const nowFn = typeof opts.now === 'function' ? opts.now : Date.now;

  const sessions = new Map();
  const loginAttempts = new Map();
  let loginOverflowUntil = 0;
  let loginOperations = 0;

  function pruneExpiredSessions(now = nowFn()) {
    let removed = 0;
    for (const [token, session] of sessions) {
      const absoluteExpiresAt = session.createdAt + maxLifetimeMs;
      if (now >= session.expiresAt || now >= absoluteExpiresAt) {
        sessions.delete(token);
        removed += 1;
      }
    }
    return removed;
  }

  function evictOldestSession() {
    let oldestToken = null;
    let oldestCreatedAt = Infinity;
    for (const [token, session] of sessions) {
      if (session.createdAt < oldestCreatedAt) {
        oldestCreatedAt = session.createdAt;
        oldestToken = token;
      }
    }
    if (oldestToken) sessions.delete(oldestToken);
    return oldestToken;
  }

  function makeSession(ctx) {
    const createdAt = nowFn();
    if (sessions.size >= maxSessions) pruneExpiredSessions(createdAt);
    while (sessions.size >= maxSessions) evictOldestSession();

    const token = randomUUID();
    sessions.set(token, {
      cn: ctx.cn,
      fp: ctx.fp,
      role: ctx.client.role,
      clientName: ctx.clientName,
      cert: ctx.cert,
      client: ctx.client,
      expiresAt: Math.min(createdAt + ttlMs, createdAt + maxLifetimeMs),
      createdAt,
    });
    return token;
  }

  function getSession(req) {
    const headers = req?.headers || {};
    const token =
      headers[header] || String(headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
    if (!token) return null;
    const session = sessions.get(token);
    if (!session) return null;

    const now = nowFn();
    const absoluteExpiresAt = session.createdAt + maxLifetimeMs;
    if (now >= session.expiresAt || now >= absoluteExpiresAt) {
      sessions.delete(token);
      return null;
    }
    session.expiresAt = Math.min(now + ttlMs, absoluteExpiresAt);
    return session;
  }

  function deleteSession(token) {
    if (token) sessions.delete(token);
  }

  function deleteSessionsForClient(clientName, { exceptToken = null } = {}) {
    let deleted = 0;
    for (const [token, session] of sessions) {
      if (token !== exceptToken && session.clientName === clientName) {
        sessions.delete(token);
        deleted += 1;
      }
    }
    return deleted;
  }

  function deleteSessionsForFingerprint(fingerprint, { exceptToken = null } = {}) {
    if (!fingerprint) return 0;
    let deleted = 0;
    for (const [token, session] of sessions) {
      if (token !== exceptToken && session.fp === fingerprint) {
        sessions.delete(token);
        deleted += 1;
      }
    }
    return deleted;
  }

  function pruneLoginAttempts(now = nowFn()) {
    let removed = 0;
    for (const [key, attempt] of loginAttempts) {
      const lockExpired = !attempt.lockedUntil || now >= attempt.lockedUntil;
      const inactive = now - attempt.updatedAt >= lockoutMs;
      if (lockExpired && inactive) {
        loginAttempts.delete(key);
        removed += 1;
      }
    }
    if (now >= loginOverflowUntil) loginOverflowUntil = 0;
    return removed;
  }

  function checkLoginLock(key) {
    const now = nowFn();
    const attempt = loginAttempts.get(key);
    if (!attempt) return !(loginOverflowUntil && now < loginOverflowUntil);
    if (attempt.lockedUntil && now < attempt.lockedUntil) return false;
    if (now - attempt.updatedAt >= lockoutMs) {
      loginAttempts.delete(key);
      return true;
    }
    return true;
  }

  function recordLoginFail(key) {
    const now = nowFn();
    loginOperations += 1;
    if (loginOperations % 256 === 0 || !loginAttempts.has(key)) {
      pruneLoginAttempts(now);
    }

    let attempt = loginAttempts.get(key);
    if (!attempt && loginAttempts.size >= maxLoginAttempts) {
      // Do not evict active lockout state: that would let a high-cardinality
      // attacker reset limits. New identities fail closed until entries expire.
      loginOverflowUntil = Math.max(loginOverflowUntil, now + lockoutMs);
      return false;
    }
    if (!attempt || now - attempt.updatedAt >= lockoutMs) {
      attempt = { fails: 0, lockedUntil: 0, updatedAt: now };
    }
    if (attempt.lockedUntil && now >= attempt.lockedUntil) {
      attempt.fails = 0;
      attempt.lockedUntil = 0;
    }
    attempt.fails += 1;
    attempt.updatedAt = now;
    if (attempt.fails >= maxFails) attempt.lockedUntil = now + lockoutMs;
    loginAttempts.set(key, attempt);
    return !attempt.lockedUntil;
  }

  function clearLoginLock(key) {
    loginAttempts.delete(key);
  }

  return {
    makeSession,
    getSession,
    deleteSession,
    deleteSessionsForClient,
    deleteSessionsForFingerprint,
    checkLoginLock,
    recordLoginFail,
    clearLoginLock,
    pruneExpiredSessions,
    pruneLoginAttempts,
    sessions,
    loginAttempts,
    ttlMs,
    maxLifetimeMs,
    maxSessions,
    maxLoginAttempts,
    header,
  };
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}
