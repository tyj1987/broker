// broker/lib/config-validate.js — lightweight config preflight (no deps)
// Phase E. Not a full JSON Schema engine — critical invariants only.

import { existsSync as nodeExistsSync } from 'node:fs';
import { validatePolicyConditions } from './policy-conditions.js';
import { validateParameterSchema } from './operation-policy.js';
import { _rateLimitDimensions } from './rate-limit.js';

/**
 * @typedef {{ level: 'error'|'warn', path: string, message: string }}
 */

/**
 * Validate broker CONFIG shape after load / migration.
 * @param {object} config
 * @param {{ strict?: boolean, allowWebAuthnBootstrap?: boolean }} [opts]
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
      if (c.security_profile == null) {
        warnings.push({
          level: 'warn', path: `clients.${name}.security_profile`,
          message: 'security_profile is missing; compatibility behavior applies',
        });
      } else if (!['strict', 'controlled', 'compatible'].includes(c.security_profile)) {
        errors.push({
          level: 'error', path: `clients.${name}.security_profile`,
          message: 'must be strict, controlled, or compatible',
        });
      }
      if (c.security_profile === 'strict') {
        if (c.password || c.allow_password_login) {
          errors.push({ level: 'error', path: `clients.${name}`, message: 'strict profile cannot enable password authentication' });
        }
        if ((c.allowed_resolve || []).length > 0 || (c.allowed_proxy || []).length > 0) {
          errors.push({ level: 'error', path: `clients.${name}`, message: 'strict profile cannot enable plaintext resolve or compatibility proxy access' });
        }
        const keys = c.factors?.webauthn?.credentials || [];
        const hardwareKeys = keys.filter((key) => key?.device_type === 'singleDevice' && key?.backed_up === false);
        if (hardwareKeys.length < 2 && !(opts.allowWebAuthnBootstrap && c.webauthn_bootstrap === true)) {
          errors.push({ level: 'error', path: `clients.${name}.factors.webauthn`, message: 'strict profile requires two non-synced hardware-bound credentials' });
        }
      }
      if (c.rate_limit !== undefined && _rateLimitDimensions(c.rate_limit) === null) {
        errors.push({
          level: 'error',
          path: `clients.${name}.rate_limit`,
          message: 'invalid rate_limit policy',
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
        if (s.base_url && typeof s.base_url === 'string') {
          try {
            // eslint-disable-next-line no-new
            new URL(s.base_url);
          } catch {
            errors.push({
              level: 'error',
              path: `services.${name}.base_url`,
              message: 'invalid URL',
            });
          }
        }
      }
    }
  }

  if (config.api_keys != null) {
    if (typeof config.api_keys !== 'object') {
      errors.push({ level: 'error', path: 'api_keys', message: 'must be object/array map' });
    } else {
      const entries = Array.isArray(config.api_keys)
        ? config.api_keys.map((key, index) => [`[${index}]`, key])
        : Object.entries(config.api_keys);
      const seenIds = new Set();
      const listFields = [
        'scopes', 'child_scopes', 'allowed_secrets', 'allowed_services',
        'allowed_operations', 'allowed_accounts', 'allowed_resources',
        'allowed_environments', 'ip_whitelist',
      ];
      for (const [entryName, key] of entries) {
        const path = `api_keys.${entryName}`;
        if (!key || typeof key !== 'object' || Array.isArray(key)) {
          errors.push({ level: 'error', path, message: 'must be an object' });
          continue;
        }
        if (typeof key.id !== 'string' || key.id.length === 0) {
          errors.push({ level: 'error', path: `${path}.id`, message: 'id is required' });
        } else if (seenIds.has(key.id)) {
          errors.push({ level: 'error', path: `${path}.id`, message: 'duplicate id' });
        } else {
          seenIds.add(key.id);
        }
        if (typeof key.client !== 'string' || key.client.length === 0) {
          errors.push({ level: 'error', path: `${path}.client`, message: 'client is required' });
        }
        for (const field of listFields) {
          if (key[field] !== undefined && (!Array.isArray(key[field])
            || key[field].some((value) => typeof value !== 'string' || value.length === 0))) {
            errors.push({ level: 'error', path: `${path}.${field}`, message: 'must be an array of non-empty strings' });
          }
        }
        if (key.rate_limit !== undefined && _rateLimitDimensions(key.rate_limit) === null) {
          errors.push({ level: 'error', path: `${path}.rate_limit`, message: 'invalid rate_limit policy' });
        }
        for (const field of ['expires_at', 'revoked_at', 'created_at', 'last_used_at']) {
          if (key[field] !== undefined && key[field] !== null
            && (typeof key[field] !== 'string' || !Number.isFinite(Date.parse(key[field])))) {
            errors.push({ level: 'error', path: `${path}.${field}`, message: 'must be an ISO timestamp' });
          }
        }
        if (key.fingerprint_sha256 !== undefined
          && (typeof key.fingerprint_sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(key.fingerprint_sha256))) {
          errors.push({ level: 'error', path: `${path}.fingerprint_sha256`, message: 'must be a SHA-256 hex digest' });
        }
        for (const field of ['is_master', 'can_create_child']) {
          if (key[field] !== undefined && typeof key[field] !== 'boolean') {
            errors.push({ level: 'error', path: `${path}.${field}`, message: 'must be boolean' });
          }
        }
      }
    }
  }

  if (
    config.provider_accounts != null &&
    (!config.provider_accounts ||
      typeof config.provider_accounts !== 'object' ||
      Array.isArray(config.provider_accounts))
  ) {
    errors.push({ level: 'error', path: 'provider_accounts', message: 'must be an object' });
  }

  if (config.healthcheck?.upstream && config.healthcheck.upstream !== 'local') {
    errors.push({
      level: 'error',
      path: 'healthcheck.upstream',
      message: 'external MCP healthcheck execution is not supported',
    });
  }

  if (config.operation_policies != null) {
    if (!config.operation_policies || typeof config.operation_policies !== 'object' || Array.isArray(config.operation_policies)) {
      errors.push({ level: 'error', path: 'operation_policies', message: 'must be an object' });
    } else {
      for (const [provider, operations] of Object.entries(config.operation_policies)) {
        if (!operations || typeof operations !== 'object' || Array.isArray(operations)) {
          errors.push({ level: 'error', path: `operation_policies.${provider}`, message: 'must be an object' });
          continue;
        }
        for (const [operationId, policy] of Object.entries(operations)) {
          const path = `operation_policies.${provider}.${operationId}`;
          if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
            errors.push({ level: 'error', path, message: 'must be an object' });
            continue;
          }
          if (policy.execution_mode != null && !['adapter', 'browser'].includes(policy.execution_mode)) {
            errors.push({ level: 'error', path: `${path}.execution_mode`, message: 'must be adapter or browser' });
          }
          if (policy.parameter_schema != null) {
            const schema = validateParameterSchema(policy.parameter_schema);
            if (!schema.ok) errors.push({ level: 'error', path: `${path}.parameter_schema`, message: schema.reason });
          }
          const conditions = validatePolicyConditions(policy);
          if (!conditions.ok) {
            errors.push({ level: 'error', path, message: conditions.reason });
          }
          if (provider === 'broker' && ['device.enroll', 'device.state', 'emergency.stop'].includes(operationId)) {
            const safeControlPolicy = policy.approval_required === true
              && Number(policy.required_approvals) >= 2
              && policy.roles?.includes('admin')
              && policy.security_profiles?.includes('strict')
              && policy.identity_methods?.includes('session');
            if (!safeControlPolicy) {
              errors.push({
                level: 'error', path,
                message: 'critical broker control requires strict admin session policy and at least two approvals',
              });
            }
          }
        }
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
 * Normalize legacy object-map API keys at the configuration boundary. The
 * runtime key store and management routes operate on arrays; keeping this
 * conversion next to validation prevents a config that passes preflight from
 * silently disabling every bearer key at runtime.
 */
export function normalizeBrokerConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return config;
  if (config.api_keys && typeof config.api_keys === 'object' && !Array.isArray(config.api_keys)) {
    config.api_keys = Object.values(config.api_keys);
  }
  return config;
}

export function requireValidBrokerConfig(config, opts = {}) {
  const result = validateBrokerConfig(config, opts);
  if (!result.ok) throw new Error(`broker configuration rejected:\n${formatValidationReport(result)}`);
  return result;
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
