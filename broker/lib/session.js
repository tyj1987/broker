// broker/lib/session.js — dashboard session tokens + login lockout
// Phase B.2 extraction from server.js.

import { randomUUID } from 'node:crypto';

export const SESSION_TTL_MS = 10 * 60 * 1000; // absolute lifetime
export const SESSION_HEADER = 'x-auth-token';
export const MAX_LOGIN_FAILS = 5;
export const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

/**
 * @returns {{ makeSession, getSession, deleteSession, checkLoginLock, recordLoginFail, clearLoginLock, sessions }}
 */
export function createSessionStore(opts = {}) {
  const ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
  const header = opts.header ?? SESSION_HEADER;
  const maxFails = opts.maxFails ?? MAX_LOGIN_FAILS;
  const lockoutMs = opts.lockoutMs ?? LOGIN_LOCKOUT_MS;
  const now = opts.now ?? Date.now;

  const sessions = new Map();
  const loginAttempts = new Map();

  function makeSession(ctx) {
    const token = randomUUID();
    sessions.set(token, {
      cn: ctx.cn,
      fp: ctx.fp,
      role: ctx.client.role,
      clientName: ctx.clientName,
      cert: ctx.cert,
      client: ctx.client,
      expiresAt: now() + ttlMs,
      createdAt: now(),
    });
    return token;
  }

  function getSession(req) {
    const t = req.headers[header]
      || (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
    if (!t) return null;
    const s = sessions.get(t);
    if (!s) return null;
    if (now() > s.expiresAt) {
      sessions.delete(t);
      return null;
    }
    return s;
  }

  function deleteSession(token) {
    if (token) sessions.delete(token);
  }

  function checkLoginLock(key) {
    const a = loginAttempts.get(key);
    if (!a) return true;
    if (a.lockedUntil && now() < a.lockedUntil) return false;
    return true;
  }

  function recordLoginFail(key) {
    const a = loginAttempts.get(key) || { fails: 0, lockedUntil: 0 };
    if (a.lockedUntil && now() >= a.lockedUntil) {
      a.fails = 0;
      a.lockedUntil = 0;
    }
    a.fails += 1;
    if (a.fails >= maxFails) a.lockedUntil = now() + lockoutMs;
    loginAttempts.set(key, a);
  }

  function clearLoginLock(key) {
    loginAttempts.delete(key);
  }

  return {
    makeSession,
    getSession,
    deleteSession,
    checkLoginLock,
    recordLoginFail,
    clearLoginLock,
    sessions,
    ttlMs,
    header,
  };
}
