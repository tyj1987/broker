// broker/lib/config-validate.js — lightweight config preflight (no deps)
// Phase E. Not a full JSON Schema engine — critical invariants only.

import { existsSync as nodeExistsSync } from 'node:fs';
import { normalizeOperations } from './security-profile.js';

/**
 * @typedef {{ level: 'error'|'warn', path: string, message: string }}
 */

/**
 * Validate broker CONFIG shape after load / migration.
 * @param {object} config
 * @param {{ strict?: boolean }} [opts] strict: treat warns as errors for exit code
 * @returns {{ ok: boolean, errors: object[], warnings: object[] }}
 */
export function validateBrokerConfig(config, opts = {}) {
  const errors = [];
  const warnings = [];

  if (!config || typeof config !== 'object') {
    errors.push({ level: 'error', path: '', message: 'config must be an object' });
    return { ok: false, errors, warnings };
  }

  const profile = String(config.security_profile || 'strict').toLowerCase();
  if (!['strict', 'controlled', 'compatibility'].includes(profile)) {
    errors.push({ level: 'error', path: 'security_profile', message: 'must be strict, controlled, or compatibility' });
  }
  if (profile === 'strict') {
    if (!config.webauthn?.rp_id) errors.push({ level: 'error', path: 'webauthn.rp_id', message: 'strict profile requires a WebAuthn RP ID' });
    if (!config.webauthn?.origin || !String(config.webauthn.origin).startsWith('https://')) {
      errors.push({ level: 'error', path: 'webauthn.origin', message: 'strict profile requires an HTTPS WebAuthn origin' });
    }
  }

  if (!config.clients || typeof config.clients !== 'object') {
    errors.push({ level: 'error', path: 'clients', message: 'clients map is required' });
  } else {
    for (const [name, c] of Object.entries(config.clients)) {
      if (!c || typeof c !== 'object') {
        errors.push({ level: 'error', path: `clients.${name}`, message: 'must be object' });
        continue;
      }
      if (!c.role || !['admin', 'developer', 'ci', 'readonly', 'user'].includes(c.role)) {
        // allow unknown roles as warn for forward-compat
        if (!c.role) {
          errors.push({ level: 'error', path: `clients.${name}.role`, message: 'role is required' });
        } else {
          warnings.push({
            level: 'warn',
            path: `clients.${name}.role`,
            message: `unrecognized role "${c.role}"`,
          });
        }
      }
      if (c.allow_password_login && !c.password) {
        warnings.push({
          level: 'warn',
          path: `clients.${name}`,
          message: 'allow_password_login true but no password set',
        });
      }
      if (profile === 'strict' && c.allow_password_login) {
        errors.push({ level: 'error', path: `clients.${name}.allow_password_login`, message: 'password login is forbidden in strict profile' });
      }
      if (c.rate_limit && typeof c.rate_limit === 'string' &&
          c.rate_limit.toLowerCase() !== 'unlimited' &&
          !/^\d+\/(second|minute|hour|day)$/i.test(c.rate_limit)) {
        warnings.push({
          level: 'warn',
          path: `clients.${name}.rate_limit`,
          message: `unusual rate_limit format: ${c.rate_limit}`,
        });
      }
    }
  }

  if (config.services != null) {
    if (typeof config.services !== 'object') {
      errors.push({ level: 'error', path: 'services', message: 'must be object' });
    } else {
      for (const [name, s] of Object.entries(config.services)) {
        if (!s || typeof s !== 'object') {
          errors.push({ level: 'error', path: `services.${name}`, message: 'must be object' });
          continue;
        }
        const upstream = s.upstream || s.base_url;
        if (upstream && typeof upstream === 'string') {
          try {
            const parsed = new URL(upstream);
            if (parsed.protocol !== 'https:') errors.push({ level: 'error', path: `services.${name}.upstream`, message: 'upstream must use HTTPS' });
          } catch {
            errors.push({
              level: 'error',
              path: `services.${name}.upstream`,
              message: 'invalid URL',
            });
          }
        }
        if (profile === 'strict' && (!s.operations || typeof s.operations !== 'object' || Object.keys(s.operations).length === 0)) {
          errors.push({ level: 'error', path: `services.${name}.operations`, message: 'strict profile requires typed operations' });
        } else if (s.operations !== undefined) {
          try { normalizeOperations(s.operations); }
          catch (e) { errors.push({ level: 'error', path: `services.${name}.operations`, message: e.message }); }
        }
      }
    }
  }

  if (config.api_keys != null && typeof config.api_keys !== 'object') {
    errors.push({ level: 'error', path: 'api_keys', message: 'must be object/array map' });
  }

  // At least one admin recommended
  const clients = config.clients || {};
  const admins = Object.values(clients).filter((c) => c && c.role === 'admin');
  if (Object.keys(clients).length > 0 && admins.length === 0) {
    warnings.push({
      level: 'warn',
      path: 'clients',
      message: 'no client with role admin',
    });
  }

  const ok = errors.length === 0 && (!opts.strict || warnings.length === 0);
  return { ok, errors, warnings };
}

/**
 * Preflight filesystem / env checks before listen.
 * @param {object} paths e.g. { configPath, auditDir, certDir, ageKey }
 * @param {{ existsSync: Function }} fs
 * @returns {{ ok: boolean, errors: object[], warnings: object[] }}
 */
export function preflightPaths(paths = {}, fsApi = null) {
  const errors = [];
  const warnings = [];
  // dynamic import avoided; caller passes existsSync
  const exists = fsApi?.existsSync || nodeExistsSync;

  // Use only if paths provided
  for (const [label, p] of Object.entries(paths)) {
    if (p == null || p === '') continue;
    if (label.endsWith('_optional')) {
      if (!exists(p)) warnings.push({ level: 'warn', path: label, message: `missing optional path ${p}` });
      continue;
    }
    // required-ish keys
    if (['configPath', 'ageKey', 'caCert', 'serverCert', 'serverKey'].includes(label)) {
      if (!exists(p)) {
        errors.push({ level: 'error', path: label, message: `required path missing: ${p}` });
      }
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

/**
 * Format validation result for logs / CLI.
 */
export function formatValidationReport(result) {
  const lines = [];
  for (const e of result.errors || []) lines.push(`ERROR ${e.path}: ${e.message}`);
  for (const w of result.warnings || []) lines.push(`WARN  ${w.path}: ${w.message}`);
  if (!lines.length) lines.push('OK');
  return lines.join('\n');
}
