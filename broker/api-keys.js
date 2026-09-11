// broker/api-keys.js — v3.0 M2 API Key 管理
// 短命 Bearer token，给 Web 端 AI 用。无需 mTLS。
//
// 设计：
//   - 格式: mb_<env>_<random> (32 字符 base62)
//     env: live / test
//   - secret 只显示一次，存 SHA-256 hash
//   - 字段:
//     id, name, client (归属), scopes, allowed_secrets, allowed_services,
//     rate_limit, expires_at, created_at, created_by,
//     fingerprint (SHA-256 of secret), revoked_at (可选)
//     ip_whitelist (可选 string[]): 精确 IP 或 CIDR；空 = 不限制
//
// API:
//   POST   /api/v1/api-keys              (admin or self + TOTP)
//   GET    /api/v1/api-keys              (admin: 全部; self: 自己的)
//   GET    /api/v1/api-keys/:id
//   DELETE /api/v1/api-keys/:id         (admin or self)
//   GET    /api/v1/api-keys/:id/usage
//
// Auth: session/mTLS (走 ctx.client) 或 Bearer (自己处理)

import { randomInt, createHash } from 'node:crypto';
import { isIpAllowed, normalizeIp } from './lib/ip-allowlist.js';

const ENV = process.env.NODE_ENV === 'production' ? 'live' : 'test';
const KEY_PREFIX = 'mb';
const KEY_RANDOM_LEN = 32;  // base62
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;  // 24h
// v3.0 M3.3: Master Key 用于 MCP Server auto-refresh child keys
const DEFAULT_MASTER_TTL_MS = 30 * 24 * 60 * 60 * 1000;  // 30d
const DEFAULT_CHILD_TTL_SECONDS = 60 * 60;  // 1h
const MASTER_KEY_SCOPES = ['keys:issue_child'];  // master key 只能创建子 key，不能直接调 service
const DEFAULT_CHILD_SCOPES = ['secrets:resolve', 'services:proxy'];

function normalizeStringList(value, field) {
  const list = value === undefined ? [] : value;
  if (!Array.isArray(list) || list.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new TypeError(`API key ${field} must be an array of non-empty strings`);
  }
  return [...list];
}

// V4.0 任务 6: 多维度限额
// 历史 v3 rate_limit 字段是 "100/hour" 字符串;V4 支持每分钟/小时/天 三个维度
// 旧的字符串格式仍可解析(向后兼容)
export const RATE_LIMIT_PRESETS = {
  '100/hour':  { minute: null, hour: 100, day: 1000 },
  '1000/hour': { minute: null, hour: 1000, day: 10000 },
  'unlimited': { minute: null, hour: null, day: null },
};

/**
 * Normalize a rate_limit field from broker.yaml.
 * Accepts:
 *   - '100/hour' | 'unlimited'  (v3 strings)
 *   - { minute, hour, day }     (v4 object)
 * @returns {{ minute: number|null, hour: number|null, day: number|null } | null}
 */
export function normalizeRateLimit(rl) {
  if (rl == null) return null; // unlimited
  if (typeof rl === 'string') {
    if (rl === 'unlimited') return { minute: null, hour: null, day: null };
    return RATE_LIMIT_PRESETS[rl] || null;
  }
  if (typeof rl === 'object') {
    return {
      minute: Number.isFinite(rl.minute) ? rl.minute : null,
      hour:   Number.isFinite(rl.hour)   ? rl.hour   : null,
      day:    Number.isFinite(rl.day)    ? rl.day    : null,
    };
  }
  return null;
}

// ============================================================
// helpers
// ============================================================

function genRandomBase62(len) {
  // base62 = 0-9 a-z A-Z
  const alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let s = '';
  for (let i = 0; i < len; i++) s += alphabet[randomInt(alphabet.length)];
  return s;
}

/**
 * 生成 API Key (display 一次, 存 hash)
 * @returns {{ id, secret, fingerprint, key_obj }}
 */
export function generateApiKey(name, client, opts = {}) {
  const scopes = opts.scopes === undefined
    ? (opts.is_master ? MASTER_KEY_SCOPES : DEFAULT_CHILD_SCOPES)
    : opts.scopes;
  const childScopes = opts.child_scopes === undefined ? DEFAULT_CHILD_SCOPES : opts.child_scopes;
  if (!Array.isArray(scopes) || scopes.some((scope) => typeof scope !== 'string' || scope.length === 0)) {
    throw new TypeError('API key scopes must be an array of non-empty strings');
  }
  if (!Array.isArray(childScopes) || childScopes.some((scope) => typeof scope !== 'string' || scope.length === 0)) {
    throw new TypeError('API key child_scopes must be an array of non-empty strings');
  }
  const allowedSecrets = normalizeStringList(opts.allowed_secrets, 'allowed_secrets');
  const allowedServices = normalizeStringList(opts.allowed_services, 'allowed_services');
  const allowedOperations = normalizeStringList(opts.allowed_operations, 'allowed_operations');
  const allowedAccounts = normalizeStringList(opts.allowed_accounts, 'allowed_accounts');
  const allowedResources = normalizeStringList(opts.allowed_resources, 'allowed_resources');
  const allowedEnvironments = normalizeStringList(opts.allowed_environments, 'allowed_environments');
  const ipWhitelist = opts.ip_whitelist == null ? null : normalizeStringList(opts.ip_whitelist, 'ip_whitelist');
  const random = genRandomBase62(KEY_RANDOM_LEN);
  const secret = `${KEY_PREFIX}_${ENV}_${random}`;
  const fingerprint = createHash('sha256').update(secret).digest('hex');
  const id = fingerprint.slice(0, 16);  // 短 id
  const now = new Date();
  const ttlMs = opts.ttl_ms || DEFAULT_TTL_MS;
  const expiresAtMs = opts.expires_at_ms == null ? now.getTime() + ttlMs : Number(opts.expires_at_ms);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= now.getTime()) {
    throw new RangeError('API key expiration must be a future millisecond timestamp');
  }
  const key_obj = {
    id,
    name: name || 'unnamed',
    client,  // 归属的 client name
    scopes,
    allowed_secrets: allowedSecrets,
    allowed_services: allowedServices,
    allowed_operations: allowedOperations,
    allowed_accounts: allowedAccounts,
    allowed_resources: allowedResources,
    allowed_environments: allowedEnvironments,
    rate_limit: opts.rate_limit || '100/hour',
    ip_whitelist: ipWhitelist,
    fingerprint_sha256: fingerprint,
    created_at: now.toISOString(),
    created_by: opts.created_by || client,
    expires_at: new Date(expiresAtMs).toISOString(),
    revoked_at: null,
    last_used_at: null,
    use_count: 0,
    // v3.0 M3.3: Master / Child Key 关系
    is_master: !!opts.is_master,
    can_create_child: !!opts.is_master,  // 只能 master 创建 child
    default_child_ttl_seconds: opts.default_child_ttl_seconds || DEFAULT_CHILD_TTL_SECONDS,
    child_scopes: childScopes,
    parent_master_id: opts.parent_master_id || null,  // 子 key 记录归属 master
  };
  return { id, secret, fingerprint, key_obj };
}

/**
 * v3.0 M3.3: 生成 Master Key（30d TTL, scope 限定 keys:issue_child）
 */
export function generateMasterKey(name, client, opts = {}) {
  return generateApiKey(name, client, {
    ...opts,
    is_master: true,
    ttl_ms: opts.ttl_ms || DEFAULT_MASTER_TTL_MS,
    scopes: MASTER_KEY_SCOPES,
  });
}

/**
 * v3.0 M3.3: 鉴权 — 检查 API Key 是否有创建子 key 权限
 */
export function canCreateChild(k) {
  if (!k) return { ok: false, reason: 'not_found' };
  if (k.revoked_at) return { ok: false, reason: 'revoked' };
  if (isExpired(k)) return { ok: false, reason: 'expired' };
  if (!k.is_master) return { ok: false, reason: 'not_master' };
  if (!k.can_create_child) return { ok: false, reason: 'no_child_perm' };
  if (!k.scopes || !k.scopes.includes('keys:issue_child')) {
    return { ok: false, reason: 'no_keys_scope' };
  }
  return { ok: true };
}

/**
 * v3.0 M3.3: 鉴别子 key（有 parent_master_id）
 */
export function isChildKey(k) {
  return !!(k && k.parent_master_id);
}

/**
 * v3.2: API Key IP 白名单
 * whitelist 为空/null → 允许任意 IP
 * 否则 remoteIp 必须命中 exact 或 CIDR 规则
 */
export function isClientIpAllowed(k, remoteIp) {
  if (!k) return false;
  return isIpAllowed(k.ip_whitelist, remoteIp);
}

/**
 * v3.0 M3.3: 创建子 key（仅 master key 可调）
 */
export function createChildKey(cfgKeys, master, name, opts = {}) {
  const check = canCreateChild(master);
  if (!check.ok) return { ok: false, reason: check.reason };

  let childScopes = opts.scopes || master.child_scopes || DEFAULT_CHILD_SCOPES;
  if (Array.isArray(childScopes) && Array.isArray(master.child_scopes)) {
    childScopes = childScopes.filter(s => master.child_scopes.includes(s));
  }
  if (!Array.isArray(childScopes) || childScopes.length === 0) {
    return { ok: false, reason: 'no_valid_scopes' };
  }

  const requestedSecrets = opts.allowed_secrets || master.allowed_secrets || [];
  const parentSecrets = Array.isArray(master.allowed_secrets) ? master.allowed_secrets : [];
  const allowedSecrets = parentSecrets.length > 0
    ? requestedSecrets.filter((value) => parentSecrets.includes(value)) : [];
  const requestedServices = opts.allowed_services || master.allowed_services || [];
  const parentServices = Array.isArray(master.allowed_services) ? master.allowed_services : [];
  const allowedServices = parentServices.length > 0
    ? requestedServices.filter((value) => parentServices.includes(value)) : [];
  const childSubset = (field) => {
    const requested = Array.isArray(opts[field]) ? opts[field] : (master[field] || []);
    const parent = Array.isArray(master[field]) ? master[field] : [];
    return parent.length > 0 ? requested.filter((value) => parent.includes(value)) : [];
  };
  const allowedOperations = childSubset('allowed_operations');
  const allowedAccounts = childSubset('allowed_accounts');
  const allowedResources = childSubset('allowed_resources');
  const allowedEnvironments = childSubset('allowed_environments');
  if (childScopes.includes('secrets:resolve') && allowedSecrets.length === 0) {
    return { ok: false, reason: 'secret_constraints_required' };
  }
  if (childScopes.includes('services:proxy') && allowedServices.length === 0) {
    return { ok: false, reason: 'service_constraints_required' };
  }
  if (childScopes.some((scope) => scope === 'operations:execute' || scope.startsWith('operations:'))
      && [allowedServices, allowedOperations, allowedAccounts, allowedResources, allowedEnvironments]
        .some((values) => values.length === 0)) {
    return { ok: false, reason: 'operation_constraints_required' };
  }

  const requestedIp = Array.isArray(opts.ip_whitelist) ? opts.ip_whitelist : master.ip_whitelist;
  const parentIp = Array.isArray(master.ip_whitelist) ? master.ip_whitelist : null;
  const childIp = parentIp && parentIp.length > 0
    ? (Array.isArray(requestedIp) ? requestedIp.filter((value) => parentIp.includes(value)) : [...parentIp])
    : (Array.isArray(requestedIp) ? requestedIp : null);
  if (parentIp?.length > 0 && (!childIp || childIp.length === 0)) {
    return { ok: false, reason: 'ip_constraints_required' };
  }

  const parentRate = normalizeRateLimit(master.rate_limit);
  const requestedRate = normalizeRateLimit(opts.rate_limit ?? master.rate_limit);
  const childRate = Object.fromEntries(['minute', 'hour', 'day'].map((dimension) => {
    const parentValue = parentRate?.[dimension] ?? null;
    const requestedValue = requestedRate?.[dimension] ?? null;
    if (parentValue === null) return [dimension, requestedValue];
    if (requestedValue === null) return [dimension, parentValue];
    return [dimension, Math.min(parentValue, requestedValue)];
  }));

  const requestedTtl = Number(opts.ttl_seconds || master.default_child_ttl_seconds || DEFAULT_CHILD_TTL_SECONDS);
  const now = Date.now();
  const parentExpiresAtMs = new Date(master.expires_at).getTime();
  const requestedTtlMs = requestedTtl * 1000;
  if (!Number.isSafeInteger(requestedTtl) || requestedTtl <= 0
      || !Number.isSafeInteger(requestedTtlMs) || !Number.isFinite(parentExpiresAtMs)
      || parentExpiresAtMs <= now) {
    return { ok: false, reason: 'invalid_child_ttl' };
  }
  const childExpiresAtMs = Math.min(now + requestedTtlMs, parentExpiresAtMs);

  const { id, secret, key_obj } = generateApiKey(name, master.client, {
    scopes: childScopes,
    allowed_secrets: allowedSecrets,
    allowed_services: allowedServices,
    allowed_operations: allowedOperations,
    allowed_accounts: allowedAccounts,
    allowed_resources: allowedResources,
    allowed_environments: allowedEnvironments,
    rate_limit: childRate,
    ip_whitelist: childIp,
    expires_at_ms: childExpiresAtMs,
    parent_master_id: master.id,
    created_by: `master:${master.id}`,
  });
  cfgKeys.push(key_obj);
  return { ok: true, key_obj: publicView(key_obj), secret };
}

/**
 * 从 Authorization header 解析 API Key
 * @returns {string|null} secret (未验)
 */
export function parseBearer(authHeader) {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/.exec(authHeader);
  return m ? m[1] : null;
}

/**
 * 用 fingerprint 查 API Key (从 CONFIG.api_keys 数组里)
 * 同时检查 expires_at 和 revoked_at
 * @returns {object|null} key obj or null
 */
export function findApiKey(cfgKeys, secret) {
  if (!cfgKeys || !Array.isArray(cfgKeys) || !secret) return null;
  const fp = createHash('sha256').update(secret).digest('hex');
  const k = cfgKeys.find(x => x.fingerprint_sha256 === fp);
  if (!k) return null;
  if (k.revoked_at) return null;
  if (isExpired(k)) return null;
  return k;
}

/**
 * 验证 API Key 是否能 resolve 某个 secret
 */
export function canResolveSecret(k, secretName) {
  if (!k || !k.scopes || !k.scopes.includes('secrets:resolve')) return false;
  return Array.isArray(k.allowed_secrets)
    && k.allowed_secrets.length > 0
    && typeof secretName === 'string'
    && k.allowed_secrets.includes(secretName);
}

/**
 * 验证 API Key 是否能 proxy 某个 service
 */
export function canProxyService(k, serviceName) {
  if (!k || !k.scopes || !k.scopes.includes('services:proxy')) return false;
  return Array.isArray(k.allowed_services)
    && k.allowed_services.length > 0
    && typeof serviceName === 'string'
    && k.allowed_services.includes(serviceName);
}

/**
 * 检查 API Key 是否过期
 */
export function isExpired(k, now = Date.now()) {
  if (!k || typeof k.expires_at !== 'string' || k.expires_at.length === 0) return true;
  const expiresAt = Date.parse(k.expires_at);
  return !Number.isFinite(expiresAt) || expiresAt <= now;
}

/**
 * 列出 client 自己可见的 api keys (admin 看全部)
 */
export function listApiKeys(cfgKeys, opts = {}) {
  if (!cfgKeys || !Array.isArray(cfgKeys)) return [];
  let keys = cfgKeys;
  if (opts.clientOnly) keys = keys.filter(k => k.client === opts.clientOnly);
  return keys.map(k => publicView(k));
}

/**
 * 公开视图 (隐藏 fingerprint 后半段)
 */
export function publicView(k) {
  if (!k) return null;
  const fp = k.fingerprint_sha256 || '';
  return {
    id: k.id,
    name: k.name,
    client: k.client,
    scopes: k.scopes || [],
    allowed_secrets: k.allowed_secrets || [],
    allowed_services: k.allowed_services || [],
    allowed_operations: k.allowed_operations || [],
    allowed_accounts: k.allowed_accounts || [],
    allowed_resources: k.allowed_resources || [],
    allowed_environments: k.allowed_environments || [],
    rate_limit: k.rate_limit || '100/hour',
    ip_whitelist: k.ip_whitelist || null,
    fingerprint_prefix: fp.slice(0, 8) + '...',
    created_at: k.created_at,
    created_by: k.created_by,
    expires_at: k.expires_at,
    last_used_at: k.last_used_at,
    use_count: k.use_count || 0,
    revoked: !!k.revoked_at,
    revoked_at: k.revoked_at,
    is_master: !!k.is_master,
    can_create_child: !!k.can_create_child,
    default_child_ttl_seconds: k.default_child_ttl_seconds || null,
    child_scopes: k.child_scopes || null,
    parent_master_id: k.parent_master_id || null,
  };
}

/**
 * 创建 API Key (admin 或自己; 都需 TOTP 通过)
 * @returns {{ key_obj, secret }} secret 仅本次显示
 */
export function createApiKey(cfgKeys, name, client, opts = {}) {
  const { id, secret, key_obj } = generateApiKey(name, client, opts);
  cfgKeys.push(key_obj);
  return { key_obj: publicView(key_obj), secret };
}

/**
 * 撤销 API Key (admin 或 self)
 */
export function revokeApiKey(cfgKeys, id, by) {
  const k = cfgKeys.find(x => x.id === id);
  if (!k) return { ok: false, reason: 'not_found' };
  if (k.revoked_at) return { ok: false, reason: 'already_revoked' };
  k.revoked_at = new Date().toISOString();
  k.revoked_by = by;
  return { ok: true };
}

/**
 * 记录使用
 */
export function recordUse(k) {
  if (!k) return;
  k.use_count = (k.use_count || 0) + 1;
  k.last_used_at = new Date().toISOString();
}

export {
  ENV,
  KEY_PREFIX,
  KEY_RANDOM_LEN,
  DEFAULT_TTL_MS,
  DEFAULT_MASTER_TTL_MS,
  DEFAULT_CHILD_TTL_SECONDS,
  MASTER_KEY_SCOPES,
  DEFAULT_CHILD_SCOPES,
  normalizeIp,
  isIpAllowed,
};
