// broker/routes/read-api.js — V4.1.1 read-only API routes extracted from server.js.
//
// Handles:
//   GET  /api/v1/identity
//   GET  /api/v1/services
//   GET  /api/v1/secrets
//   POST /api/v1/secrets/resolve
//
// All handlers follow the (req, res, route, deps) signature and return true
// when the route was handled, false otherwise. The dispatch loop in server.js
// iterates over the registered handlers in order.

import { send, jsonError, readBody } from '../lib/http.js';
import { verifyAuditDir } from '../lib/audit-hash-chain.js';

/**
 * @param {object} deps
 * @param {object} deps.config         - broker CONFIG
 * @param {object} deps.audit          - audit() function
 * @param {object} deps.canResolve     - canResolve(ctx, secretName)
 * @param {object} deps.checkPathAllowed - checkPathAllowed(pattern, path)
 * @param {object} deps.getSecret      - getSecret(name) → entry
 * @param {object} deps.isServiceAllowed - isServiceAllowed(ctx, serviceName)
 * @param {object} deps.healthcheckGetSecretStatus - (name) → status
 * @param {object} deps.SECRET_CACHE   - Map of secret metadata
 * @returns {Function} dispatch(req, res, route, ctx) → boolean
 */
export function createReadApiRoutes(deps) {
  function handleIdentity(req, res, route, ctx) {
    if (route.method !== 'GET' || route.pathname !== '/api/v1/identity') return false;
    send(res, 200, {
      cn: ctx.cn,
      fingerprint_sha256: ctx.fp,
      role: ctx.client.role,
      client_name: ctx.clientName,
      cert_subject: ctx.certSubject,
      via: ctx.via,
      auth_factors: Array.isArray(ctx.authFactors) ? [...new Set(ctx.authFactors)] : [],
    });
    return true;
  }

  function handleServices(req, res, route, ctx) {
    if (route.method !== 'GET' || route.pathname !== '/api/v1/services') return false;
    const services = [];
    const entries = Object.entries(deps.config.services).filter(([name]) => {
      // Delegated keys must not enumerate service metadata outside their
      // explicit capability boundary (upstream and token_secret are useful
      // reconnaissance even when `allowed` is false).
      if (ctx.via === 'api_key' || ctx.apiKey) return deps.isServiceAllowed(ctx, name);
      return true;
    });
    for (const [name, svc] of entries) {
      const secretHealth = svc.token_secret
        ? (() => {
            const s = deps.healthcheckGetSecretStatus(svc.token_secret);
            return s ? { name: svc.token_secret, status: s.status, detail: s.detail, latency_ms: s.latency_ms, ts: s.ts } : null;
          })()
        : null;
      services.push({
        name,
        type: svc.type || 'unknown',
        description: svc.description || '',
        upstream: svc.upstream || '',
        region: svc.region || '',
        action: svc.action || '',
        token_secret: svc.token_secret || null,
        secret_health: secretHealth,
        allowed: deps.isServiceAllowed(ctx, name),
        actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
      });
    }
    deps.audit({ action: 'list_services', cn: ctx.cn, fp: ctx.fp, count: services.length });
    send(res, 200, { services });
    return true;
  }

  function handleSecrets(req, res, route, ctx) {
    if (route.method !== 'GET' || route.pathname !== '/api/v1/secrets') return false;
    const all = Array.from(deps.SECRET_CACHE.keys());
    let visible;
    // Use the same authorization predicate as resolve itself.  This prevents
    // metadata enumeration from exposing secrets outside a child API key's
    // explicit allowed_secrets boundary.
    if (ctx.client.role === 'admin' && ctx.via !== 'api_key' && !ctx.apiKey) {
      visible = all;
    } else if (ctx.via === 'api_key' || ctx.apiKey) {
      visible = all.filter(n => deps.canResolve(ctx, n));
    } else {
      const allow = ctx.client.allowed_resolve || [];
      if (allow.includes('.*') || allow.includes('*')) visible = all;
      else visible = all.filter(n => deps.checkPathAllowed(allow, n));
    }
    deps.audit({ action: 'list', cn: ctx.cn, fp: ctx.fp, count: visible.length });
    if (ctx.client.role === 'admin') {
      const out = visible.map(name => {
        const meta = deps.SECRET_CACHE.get(name);
        if (!meta) return { name };
        return {
          name,
          type: meta.type,
          description: meta.description,
          created_at: meta.created_at,
          updated_at: meta.updated_at,
          last_rotated_at: meta.last_rotated_at || meta.updated_at,
          rotation_policy_days: meta.rotation_policy_days,
          updated_by: meta.updated_by,
        };
      });
      send(res, 200, { secrets: out });
      return true;
    }
    // Non-admin: minimal metadata
    const out = visible.map(name => {
      const meta = deps.SECRET_CACHE.get(name);
      if (!meta) return { name };
      return {
        name,
        type: meta.type,
        description: meta.description,
        last_rotated_at: meta.last_rotated_at || meta.updated_at,
        rotation_policy_days: meta.rotation_policy_days,
      };
    });
    send(res, 200, { secrets: out });
    return true;
  }

  async function handleSecretsResolve(req, res, route, ctx) {
    if (route.method !== 'POST' || route.pathname !== '/api/v1/secrets/resolve') return false;
    const body = await readBody(req);
    if (!body || !body.name) {
      jsonError(res, 400, 'Missing {name}');
      return true;
    }
    if (!deps.canResolve(ctx, body.name)) {
      deps.audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret_name: body.name, status: 'denied' });
      jsonError(res, 403, 'Not allowed to resolve this secret');
      return true;
    }
    const entry = deps.getSecret(body.name);
    if (!entry) {
      deps.audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret_name: body.name, status: 'not_found' });
      jsonError(res, 404, `Secret ${body.name} not loaded`);
      return true;
    }
    const field = body.field;
    if (field) {
      const v = entry.fields?.[field];
      if (v === undefined) {
        jsonError(res, 404, `Field ${field} not found on secret ${body.name}`);
        return true;
      }
      deps.audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret_name: body.name, field, status: 'ok' });
      send(res, 200, { name: body.name, field, value: v });
      return true;
    }
    deps.audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret_name: body.name, status: 'ok' });
    send(res, 200, { name: body.name, type: entry.type, value: entry.value, fields: entry.fields });
    return true;
  }

  async function handleAuditVerify(req, res, route, ctx) {
    if (route.method !== 'GET' || route.pathname !== '/api/v1/admin/audit/verify') return false;
    if (ctx.client.role !== 'admin') {
      jsonError(res, 403, 'Admin only');
      return true;
    }
    if (!deps.auditDir) {
      jsonError(res, 500, 'auditDir not configured');
      return true;
    }
    try {
      const r = await verifyAuditDir(deps.auditDir);
      send(res, r.ok ? 200 : 422, r);
    } catch (err) {
      jsonError(res, 500, `verify failed: ${err.message}`);
    }
    return true;
  }

  const handlers = [handleIdentity, handleServices, handleSecrets, handleSecretsResolve, handleAuditVerify];

  /**
   * Dispatch loop. Returns true if any handler claimed the request.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {{ method: string, pathname: string }} route
   * @param {object} ctx
   */
  async function dispatch(req, res, route, ctx) {
    for (const h of handlers) {
      const result = h(req, res, route, ctx);
      // Some handlers are async (return Promise<boolean>)
      if (result && typeof result.then === 'function') {
        return await result;
      }
      if (result === true) return true;
    }
    return false;
  }

  return { dispatch, handlers };
}
