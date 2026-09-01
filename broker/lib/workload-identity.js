// broker/lib/workload-identity.js — V4.1 任务 11: Workload Identity
// 目标: K8s/ECS/GKE Pod 0 AK,broker 持 OIDC token 换 STS 临时凭证
// 3 个 provider: aliyun (OIDC) / aws (OIDC) / gcp (workload identity federation)
// 用 Node 内置 https + 注入的 httpClient (测试可用 mock)
// Cache: in-memory Map,key = `${provider}:${role}`,提前 10min 过期
// in-flight Promise 合并:防止并发重复调

import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';

const REFRESH_SKEW_MS = 10 * 60_000;  // 提前 10 分钟 refresh
const DEFAULT_TIMEOUT_MS = 10_000;
export { REFRESH_SKEW_MS };

export const PROVIDER_NAMES = ['aliyun', 'aws', 'gcp'];

const TOKEN_CACHE = new Map();  // key -> { creds, expires_at_ms }
const IN_FLIGHT = new Map();    // key -> Promise

/**
 * Default HTTP client — uses Node https. Test code can inject a mock.
 * @param {string} url
 * @param {object} opts { method, headers, body, timeoutMs }
 * @returns {Promise<{status:number, body:string, headers:object}>}
 */
export function defaultHttpClient(url, opts = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error(`bad url: ${url}`)); }
    const reqOpts = {
      method: opts.method || 'POST',
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(opts.headers || {}) },
    };
    const req = httpsRequest(reqOpts, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode || 0, body, headers: res.headers }));
    });
    req.setTimeout(opts.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
      req.destroy(new Error(`http timeout after ${opts.timeoutMs || DEFAULT_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ============================================================
// Aliyun: AssumeRoleWithOIDC
// ============================================================
async function assumeAliyun(oidcToken, opts, http) {
  if (!opts.oidcProviderArn) throw new Error('aliyun: oidcProviderArn required');
  if (!opts.roleArn) throw new Error('aliyun: roleArn required');
  const params = new URLSearchParams({
    Action: 'AssumeRoleWithOIDC',
    Format: 'JSON',
    Version: '2015-04-01',
    OIDCProviderArn: opts.oidcProviderArn,
    RoleArn: opts.roleArn,
    OIDCToken: oidcToken,
    RoleSessionName: opts.sessionName || 'broker-session',
  });
  if (opts.audience) params.set('TokenExtra', opts.audience);
  const res = await http('https://sts.aliyuncs.com/', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    body: params.toString(),
  });
  if (res.status !== 200) {
    throw new Error(`aliyun sts ${res.status}: ${res.body.slice(0, 300)}`);
  }
  const parsed = JSON.parse(res.body);
  if (!parsed.Credentials) {
    throw new Error(`aliyun sts: no Credentials in response: ${res.body.slice(0, 200)}`);
  }
  const c = parsed.Credentials;
  return {
    access_key_id: c.AccessKeyId,
    access_key_secret: c.AccessKeySecret,
    security_token: c.SecurityToken,
    expiration: c.Expiration,
    provider: 'aliyun',
    role: opts.roleArn,
  };
}

// ============================================================
// AWS: AssumeRoleWithWebIdentity
// ============================================================
async function assumeAws(oidcToken, opts, http) {
  if (!opts.roleArn) throw new Error('aws: roleArn required');
  const params = new URLSearchParams({
    Action: 'AssumeRoleWithWebIdentity',
    Version: '2011-06-15',
    RoleArn: opts.roleArn,
    WebIdentityToken: oidcToken,
    RoleSessionName: opts.sessionName || 'broker-session',
  });
  if (opts.durationSeconds) params.set('DurationSeconds', String(opts.durationSeconds));
  const res = await http('https://sts.amazonaws.com/', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    body: params.toString(),
  });
  if (res.status !== 200) {
    throw new Error(`aws sts ${res.status}: ${res.body.slice(0, 300)}`);
  }
  // AWS STS 200 也可能返回 XML 错误嵌套,需要先看 root
  const parsed = JSON.parse(res.body);
  const inner = parsed.AssumeRoleWithWebIdentityResult;
  if (!inner || !inner.Credentials) {
    throw new Error(`aws sts: no Credentials: ${res.body.slice(0, 200)}`);
  }
  const c = inner.Credentials;
  return {
    access_key_id: c.AccessKeyId,
    access_key_secret: c.SecretAccessKey,
    security_token: c.SessionToken,
    expiration: c.Expiration,
    provider: 'aws',
    role: opts.roleArn,
  };
}

// ============================================================
// GCP: Workload Identity Federation (token exchange)
// ============================================================
async function assumeGcp(oidcToken, opts, http) {
  if (!opts.audience) throw new Error('gcp: audience (full resource name) required');
  const body = JSON.stringify({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    audience: opts.audience,
    subject_token_type: 'urn:k8s:params:oauth:token-type:serviceaccount',
    subject_token: oidcToken,
    scope: opts.scope || 'https://www.googleapis.com/auth/cloud-platform',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  });
  const res = await http('https://sts.googleapis.com/v1/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
  if (res.status !== 200) {
    throw new Error(`gcp sts ${res.status}: ${res.body.slice(0, 300)}`);
  }
  const parsed = JSON.parse(res.body);
  if (!parsed.access_token) {
    throw new Error(`gcp sts: no access_token: ${res.body.slice(0, 200)}`);
  }
  // Google token 响应给 expires_in (秒),换算为 ISO
  const expiresAtMs = Date.now() + (parsed.expires_in * 1000);
  return {
    access_key_id: parsed.access_token,  // GCP 习惯用 access_token 作 id
    access_key_secret: '',                // GCP IAM 不需要 secret
    security_token: parsed.token_type || 'Bearer',
    expiration: new Date(expiresAtMs).toISOString(),
    expires_at_ms: expiresAtMs,
    provider: 'gcp',
    role: opts.audience,
  };
}

const PROVIDER_HANDLERS = {
  aliyun: assumeAliyun,
  aws: assumeAws,
  gcp: assumeGcp,
};

/**
 * Convert a V4 response to a normalized credentials object with expires_at_ms.
 */
function normalizeExpiry(creds) {
  if (creds.expires_at_ms) return creds;
  if (creds.expiration) {
    const t = new Date(creds.expiration).getTime();
    return { ...creds, expires_at_ms: isNaN(t) ? Date.now() + 3600_000 : t };
  }
  return { ...creds, expires_at_ms: Date.now() + 3600_000 };
}

function cacheKey(provider, opts) {
  if (provider === 'gcp') return `gcp:${opts.audience}`;
  return `${provider}:${opts.roleArn}`;
}

/**
 * Get STS credentials for a given provider + role, using OIDC token.
 * Cached until REFRESH_SKEW_MS before expiration.
 * Concurrent calls for the same key are coalesced into one upstream call.
 *
 * @param {string} provider    'aliyun' | 'aws' | 'gcp'
 * @param {string} oidcToken   OIDC / SA token from workload
 * @param {object} opts        provider-specific opts
 * @param {object} deps        { httpClient?, now?, log? }
 * @returns {Promise<object>}  credentials
 */
export async function getCredentials(provider, oidcToken, opts = {}, deps = {}) {
  if (!PROVIDER_NAMES.includes(provider)) {
    throw new Error(`unknown workload identity provider: ${provider}; must be one of ${PROVIDER_NAMES.join(', ')}`);
  }
  if (!oidcToken || typeof oidcToken !== 'string') {
    throw new Error('oidcToken must be a non-empty string');
  }
  const http = deps.httpClient || defaultHttpClient;
  const now = deps.now ? deps.now() : Date.now();
  const key = cacheKey(provider, opts);

  // 1. cache hit
  const cached = TOKEN_CACHE.get(key);
  if (cached && cached.expires_at_ms > now + REFRESH_SKEW_MS) {
    return cached.creds;
  }

  // 2. in-flight coalesce
  if (IN_FLIGHT.has(key)) {
    return IN_FLIGHT.get(key);
  }

  // 3. call upstream
  const handler = PROVIDER_HANDLERS[provider];
  const promise = (async () => {
    const credsRaw = await handler(oidcToken, opts, http);
    const creds = normalizeExpiry(credsRaw);
    TOKEN_CACHE.set(key, { creds, expires_at_ms: creds.expires_at_ms });
    return creds;
  })();
  IN_FLIGHT.set(key, promise);
  try {
    return await promise;
  } finally {
    IN_FLIGHT.delete(key);
  }
}

/**
 * Force a refresh on next call (admin tool).
 */
export function invalidateCache(provider, opts = {}) {
  const key = cacheKey(provider, opts);
  TOKEN_CACHE.delete(key);
  return { ok: true, key, cleared: TOKEN_CACHE.size };
}

/**
 * List all cached credentials (for /cache endpoint).
 * Note: returns METADATA only, never the actual keys.
 */
export function listCache() {
  const out = [];
  for (const [key, entry] of TOKEN_CACHE.entries()) {
    out.push({
      key,
      expires_at: new Date(entry.expires_at_ms).toISOString(),
      remaining_ms: entry.expires_at_ms - Date.now(),
      provider: entry.creds.provider,
      role: entry.creds.role,
    });
  }
  return out;
}

/**
 * Validate a workload identity config (used by /admin endpoint).
 * @param {object} cfg
 * @returns {{ok: boolean, errors: string[]}}
 */
export function validateConfig(cfg) {
  const errors = [];
  if (!cfg || typeof cfg !== 'object') {
    return { ok: false, errors: ['config must be an object'] };
  }
  if (!cfg.providers || typeof cfg.providers !== 'object') {
    errors.push('providers section missing');
    return { ok: false, errors };
  }
  for (const [name, p] of Object.entries(cfg.providers)) {
    if (!PROVIDER_NAMES.includes(name)) {
      errors.push(`unknown provider: ${name}`);
      continue;
    }
    if (!p || typeof p !== 'object') {
      errors.push(`${name}: not an object`);
      continue;
    }
    if (name === 'aliyun') {
      if (!p.oidcProviderArn) errors.push('aliyun: oidcProviderArn required');
      if (!p.roleArns || !Array.isArray(p.roleArns) || p.roleArns.length === 0) {
        errors.push('aliyun: roleArns (non-empty array) required');
      }
    } else if (name === 'aws') {
      if (!p.clusterOidcIssuer && !p.oidcProviderArn) {
        errors.push('aws: clusterOidcIssuer or oidcProviderArn required');
      }
      if (!p.roleArns || !Array.isArray(p.roleArns) || p.roleArns.length === 0) {
        errors.push('aws: roleArns (non-empty array) required');
      }
    } else if (name === 'gcp') {
      if (!p.audience && !p.projectNumber) {
        errors.push('gcp: audience (resource name) or projectNumber required');
      }
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * For tests: clear all caches and in-flight promises.
 */
export function _resetForTests() {
  TOKEN_CACHE.clear();
  IN_FLIGHT.clear();
}

export default {
  getCredentials,
  invalidateCache,
  listCache,
  validateConfig,
  PROVIDER_NAMES,
  REFRESH_SKEW_MS,
  _resetForTests,
  defaultHttpClient,
};
