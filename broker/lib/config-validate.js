// broker/lib/config-validate.js — lightweight config preflight (no deps)
// Phase E. Not a full JSON Schema engine — critical invariants only.

import { existsSync } from 'node:fs';
import { validateConfiguredUpstream } from './upstream-url.js';
import { normalizeFingerprint, normalizeIp } from './trusted-proxy.js';

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
          errors.push({
            level: 'error',
            path: `clients.${name}.role`,
            message: 'role is required',
          });
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
      if (
        c.rate_limit &&
        typeof c.rate_limit === 'string' &&
        c.rate_limit !== 'unlimited' &&
        !/^\d+\/(second|minute|hour|day)$/.test(c.rate_limit)
      ) {
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
        for (const field of ['upstream', 'base_url']) {
          const value = s[field];
          if (!value) continue;
          if (typeof value !== 'string') {
            errors.push({
              level: 'error',
              path: `services.${name}.${field}`,
              message: 'must be a URL string',
            });
            continue;
          }
          try {
            const parsed = validateConfiguredUpstream(value, {
              allowInsecureHttp: s.allow_insecure_http === true,
            });
            if (parsed.protocol === 'http:' && s.allow_insecure_http === true) {
              warnings.push({
                level: 'warn',
                path: `services.${name}.${field}`,
                message:
                  'plain HTTP upstream explicitly enabled; credentials may traverse an unencrypted network',
              });
            }
          } catch (err) {
            errors.push({
              level: 'error',
              path: `services.${name}.${field}`,
              message: err.message,
            });
          }
        }
      }
    }
  }

  if (config.api_keys != null && typeof config.api_keys !== 'object') {
    errors.push({ level: 'error', path: 'api_keys', message: 'must be object/array map' });
  }

  if (config.trusted_proxies !== undefined) {
    if (!Array.isArray(config.trusted_proxies) || config.trusted_proxies.length > 32) {
      errors.push({
        level: 'error',
        path: 'trusted_proxies',
        message: 'must be an array of at most 32 exact proxy bindings',
      });
    } else {
      const fingerprints = new Set();
      for (const [index, proxy] of config.trusted_proxies.entries()) {
        const fingerprint = normalizeFingerprint(proxy?.cert_fingerprint_sha256);
        if (
          !fingerprint ||
          fingerprints.has(fingerprint) ||
          !Array.isArray(proxy?.addresses) ||
          !proxy.addresses.length ||
          proxy.addresses.length > 32 ||
          proxy.addresses.some((ip) => !normalizeIp(ip))
        ) {
          errors.push({
            level: 'error',
            path: `trusted_proxies.${index}`,
            message:
              'requires unique SHA-256 fingerprint and exact IP addresses (no wildcard/CIDR)',
          });
        }
        if (
          fingerprint &&
          Object.values(config.clients || {}).some(
            (c) => normalizeFingerprint(c?.cert_fingerprint_sha256) === fingerprint,
          )
        ) {
          errors.push({
            level: 'error',
            path: `trusted_proxies.${index}`,
            message: 'proxy certificates must not also be business clients',
          });
        }
        fingerprints.add(fingerprint);
      }
    }
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
  const exists = fsApi?.existsSync || existsSync;

  // Use only if paths provided
  for (const [label, p] of Object.entries(paths)) {
    if (p == null || p === '') continue;
    if (label.endsWith('_optional')) {
      if (!exists(p)) {
        warnings.push({ level: 'warn', path: label, message: `missing optional path ${p}` });
      }
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
