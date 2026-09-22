// Client configuration normalization and authentication-boundary comparison.

import { hashPassword } from '../totp.js';

export const CLIENT_SECURITY_FIELDS = Object.freeze([
  'password',
  'allow_password_login',
  'role',
  'allowed_resolve',
  'allowed_proxy',
  'mfa_required',
  'totp_secret',
  'totp_recovery_codes_hash',
  'preferred_2fa',
  'webauthn_credentials',
]);

function cloneJsonValue(value) {
  return value === undefined ? undefined : structuredClone(value);
}

/**
 * Normalize API-provided client fields. Password input is plaintext at this
 * boundary and is always converted to a scrypt hash before it reaches config.
 */
export function normalizeClientConfig(body, opts = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const out = {};

  if (body.password !== undefined) {
    if (body.password === null || body.password === '') {
      // An explicit empty value means clear the password.
      out.password = null;
    } else {
      const password = String(body.password);
      if (password.length < 12) throw new Error('Password must be at least 12 characters');
      if (Buffer.byteLength(password, 'utf8') > 1024) {
        throw new Error('Password is too long');
      }
      const hashPasswordFn = opts.hashPasswordFn || hashPassword;
      out.password = hashPasswordFn(password);
      out.password_set_at = new Date(opts.now ?? Date.now()).toISOString();
      out.last_password_change = out.password_set_at;
    }
  }

  if (body.allow_password_login !== undefined) {
    out.allow_password_login = body.allow_password_login === true;
  }
  if (body.role !== undefined) {
    const role = String(body.role);
    if (!['admin', 'developer', 'readonly'].includes(role)) {
      throw new Error(`Invalid role: ${role}`);
    }
    out.role = role;
  }
  if (body.allowed_resolve !== undefined) {
    out.allowed_resolve = Array.isArray(body.allowed_resolve)
      ? body.allowed_resolve.map(String)
      : [];
  }
  if (body.allowed_proxy !== undefined) {
    out.allowed_proxy = Array.isArray(body.allowed_proxy) ? cloneJsonValue(body.allowed_proxy) : [];
  }
  if (body.rate_limit !== undefined) out.rate_limit = String(body.rate_limit);
  if (body.description !== undefined) out.description = String(body.description).slice(0, 4096);
  return out;
}

function canonical(value) {
  if (value === undefined) return '__undefined__';
  return JSON.stringify(value);
}

/** True when an update should invalidate existing interactive sessions. */
export function clientSecurityConfigChanged(before = {}, after = {}) {
  return CLIENT_SECURITY_FIELDS.some(
    (field) => canonical(before[field]) !== canonical(after[field]),
  );
}
