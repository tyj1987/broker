// broker/lib/session.js — dashboard session tokens + login lockout
// Phase B.2 extraction from server.js.

import { randomUUID } from 'node:crypto';

export const SESSION_TTL_MS = 15 * 60 * 1000; // 15 min inactivity
export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;
export const SESSION_HEADER = 'x-auth-token';
export const MAX_LOGIN_FAILS = 5;
export const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

/**
 * @returns {{ makeSession, getSession, deleteSession, checkLoginLock, recordLoginFail, clearLoginLock, sessions }}
 */
export function createSessionStore(opts = {}) {
  const ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
  const absoluteTtlMs = opts.absoluteTtlMs ?? SESSION_ABSOLUTE_TTL_MS;
  const header = opts.header ?? SESSION_HEADER;
  const maxFails = opts.maxFails ?? MAX_LOGIN_FAILS;
  const lockoutMs = opts.lockoutMs ?? LOGIN_LOCKOUT_MS;
  const enforceCurrentClient = typeof opts.resolveClient === 'function';
  const resolveClient = opts.resolveClient ?? ((_, session) => session.client);

  const sessions = new Map();
  const loginAttempts = new Map();

  function makeSession(ctx) {
    const token = randomUUID();
    sessions.set(token, {
      sessionId: randomUUID(),
      cn: ctx.cn,
      fp: ctx.fp,
      role: ctx.client.role,
      clientName: ctx.clientName,
      cert: ctx.cert,
      client: ctx.client,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
      absoluteExpiresAt: Date.now() + absoluteTtlMs,
    });
    return token;
  }

  function getSession(req) {
    const t = req.headers[header]
      || (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
    if (!t) return null;
    const s = sessions.get(t);
    if (!s) return null;
    if (Date.now() > s.expiresAt || Date.now() > s.absoluteExpiresAt) {
      sessions.delete(t);
      return null;
    }
    const currentClient = resolveClient(s.clientName, s);
    if (!currentClient || currentClient.disabled === true || currentClient.revoked_at) {
      sessions.delete(t);
      return null;
    }
    if (enforceCurrentClient && s.fp && String(currentClient.cert_fingerprint_sha256 || '').toUpperCase() !== String(s.fp).toUpperCase()) {
      sessions.delete(t);
      return null;
    }
    s.client = currentClient;
    s.role = currentClient.role;
    s.expiresAt = Math.min(Date.now() + ttlMs, s.absoluteExpiresAt);
    return s;
  }

  function deleteSession(token) {
    if (token) sessions.delete(token);
  }

  function deleteSessionsForClient(clientName) {
    let deleted = 0;
    for (const [token, session] of sessions) {
      if (session.clientName === clientName) {
        sessions.delete(token);
        deleted++;
      }
    }
    return deleted;
  }

  function checkLoginLock(key) {
    const a = loginAttempts.get(key);
    if (!a) return true;
    if (a.lockedUntil && Date.now() < a.lockedUntil) return false;
    return true;
  }

  function recordLoginFail(key) {
    const a = loginAttempts.get(key) || { fails: 0, lockedUntil: 0 };
    if (a.lockedUntil && Date.now() >= a.lockedUntil) {
      a.fails = 0;
      a.lockedUntil = 0;
    }
    a.fails += 1;
    if (a.fails >= maxFails) a.lockedUntil = Date.now() + lockoutMs;
    loginAttempts.set(key, a);
  }

  function clearLoginLock(key) {
    loginAttempts.delete(key);
  }

  return {
    makeSession,
    getSession,
    deleteSession,
    deleteSessionsForClient,
    checkLoginLock,
    recordLoginFail,
    clearLoginLock,
    sessions,
    ttlMs,
    header,
  };
}
