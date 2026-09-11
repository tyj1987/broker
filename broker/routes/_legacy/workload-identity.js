// broker/routes/workload-identity.js — V4.1 任务 11
// 端点:
//   POST /api/v1/workload-identity/assume    — 拿 STS 临时凭证
//   GET  /api/v1/workload-identity/cache     — 看 cache 状态 (admin)
//   POST /api/v1/workload-identity/invalidate — 强制刷新某个 provider/role (admin)
//
// 安全: assume 端点要求 mTLS client 已认证(任何 client 都能用,broker 内置
// 限流在 deps.rateLimit); cache/invalidate 要求 admin client.

import { getCredentials, listCache, invalidateCache, validateConfig, _resetForTests } from '../../lib/workload-identity.js';

/**
 * @returns {Promise<boolean>}
 */
export async function handleWorkloadIdentity(req, res, route, deps) {
  const { method, pathname: p } = route;
  const { send, jsonError, readBody, audit, ctx, config, rateLimit } = deps;

  if (p === '/api/v1/workload-identity/assume') {
    return handleAssume(req, res, { method, send, jsonError, readBody, audit, ctx, config, rateLimit });
  }
  if (p === '/api/v1/workload-identity/cache' && method === 'GET') {
    return handleCacheList(res, { jsonError, ctx, config });
  }
  if (p === '/api/v1/workload-identity/invalidate' && method === 'POST') {
    return handleInvalidate(req, res, { jsonError, readBody, audit, ctx, config });
  }
  if (p === '/api/v1/workload-identity/config/validate' && method === 'POST') {
    return handleValidateConfig(req, res, { jsonError, readBody, ctx, config });
  }
  return false;
}

async function handleAssume(req, res, { send, jsonError, readBody, audit, ctx, config, rateLimit }) {
  if (!ctx?.client) {
    jsonError(res, 401, 'Authentication required');
    return true;
  }
  // rate limit
  if (rateLimit && !rateLimit(ctx, 'workload_identity.assume')) {
    jsonError(res, 429, 'Too many requests');
    return true;
  }
  const body = await readBody(req) || {};
  const { provider, oidc_token, oidcToken, role_arn, roleArn, audience, session_name, sessionName } = body;
  if (!provider) {
    jsonError(res, 400, 'provider required (aliyun | aws | gcp)');
    return true;
  }
  const token = oidcToken || oidc_token;
  if (!token) {
    jsonError(res, 400, 'oidc_token required');
    return true;
  }
  // 检查 broker.yaml 里这个 provider 是否被允许
  const wi = (config && config.workload_identity) || {};
  const provCfg = (wi.providers || {})[provider];
  if (!provCfg) {
    audit?.({ action: 'workload_identity.assume', status: 'denied', provider, reason: 'provider_not_configured', cn: ctx.cn });
    jsonError(res, 403, `provider ${provider} not configured`);
    return true;
  }
  try {
    const opts = {
      roleArn: roleArn || role_arn || (provCfg.roleArns && provCfg.roleArns[0]),
      audience: audience || provCfg.audience,
      oidcProviderArn: provCfg.oidcProviderArn,
      sessionName: sessionName || session_name,
    };
    if (provider === 'gcp') {
      // gcp 走 audience 作为 STS 资源名
      opts.audience = audience || provCfg.audience;
    }
    const creds = await getCredentials(provider, token, opts);
    audit?.({ action: 'workload_identity.assume', status: 'ok', provider, role: opts.roleArn || opts.audience, cn: ctx.cn });
    send(res, 200, {
      ok: true,
      provider: creds.provider,
      role: creds.role,
      access_key_id: creds.access_key_id,
      access_key_secret: creds.access_key_secret,
      security_token: creds.security_token,
      expiration: new Date(creds.expires_at_ms).toISOString(),
      expires_in_ms: creds.expires_at_ms - Date.now(),
    });
  } catch (e) {
    audit?.({ action: 'workload_identity.assume', status: 'error', provider, error: String(e?.message || e), cn: ctx.cn });
    jsonError(res, 502, `assume failed: ${e.message}`);
  }
  return true;
}

async function handleCacheList(res, { jsonError, ctx, config }) {
  if (!ctx?.client || !isAdminClient(ctx, config)) {
    jsonError(res, 403, 'admin only');
    return true;
  }
  const items = listCache();
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ ok: true, count: items.length, items }));
  return true;
}

async function handleInvalidate(req, res, { jsonError, readBody, audit, ctx, config }) {
  if (!ctx?.client || !isAdminClient(ctx, config)) {
    jsonError(res, 403, 'admin only');
    return true;
  }
  const body = await readBody(req) || {};
  const { provider, role_arn, roleArn, audience } = body;
  if (!provider) {
    jsonError(res, 400, 'provider required');
    return true;
  }
  const r = invalidateCache(provider, { roleArn: roleArn || role_arn, audience });
  audit?.({ action: 'workload_identity.invalidate', status: 'ok', provider, cn: ctx.cn });
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(r));
  return true;
}

async function handleValidateConfig(req, res, { jsonError, readBody, ctx, config }) {
  if (!ctx?.client || !isAdminClient(ctx, config)) {
    jsonError(res, 403, 'admin only');
    return true;
  }
  const body = await readBody(req) || {};
  const r = validateConfig(body);
  res.statusCode = r.ok ? 200 : 400;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(r));
  return true;
}

function isAdminClient(ctx, config) {
  // 复用 broker 的 admin 判断:client.cn 在 config.clients[cn].admin === true
  const clients = (config && config.clients) || {};
  const c = clients[ctx.cn] || clients[ctx.clientName] || {};
  return c.admin === true || c.can_create_child === true;
}
