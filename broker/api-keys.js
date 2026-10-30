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

import { createHash } from 'node:crypto';
import { randomString } from './lib/random.js';
import { isIpAllowed, normalizeIp } from './lib/ip-allowlist.js';

const ENV = process.env.NODE_ENV === 'production' ? 'live' : 'test';
const KEY_PREFIX = 'mb';
const KEY_RANDOM_LEN = 32; // base62
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h
// v3.0 M3.3: Master Key 用于 MCP Server auto-refresh child keys
const DEFAULT_MASTER_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30d
const DEFAULT_CHILD_TTL_SECONDS = 60 * 60; // 1h
const MASTER_KEY_SCOPES = ['keys:issue_child']; // master key 只能创建子 key，不能直接调 service
const DEFAULT_CHILD_SCOPES = ['secrets:resolve', 'services:proxy'];

// V4.0 任务 6: 多维度限额
// 历史 v3 rate_limit 字段是 "100/hour" 字符串;V4 支持每分钟/小时/天 三个维度
// 旧的字符串格式仍可解析(向后兼容)
export const RATE_LIMIT_PRESETS = {
  '100/hour': { minute: null, hour: 100, day: 1000 },
  '1000/hour': { minute: null, hour: 1000, day: 10000 },
  unlimited: { minute: null, hour: null, day: null },
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
    if (RATE_LIMIT_PRESETS[rl]) return { ...RATE_LIMIT_PRESETS[rl] };
    const m = /^(\d+)\/(minute|hour|day)$/.exec(rl);
    if (!m) return null;
    const out = { minute: null, hour: null, day: null };
    out[m[2]] = parseInt(m[1], 10);
    return out;
  }
  if (typeof rl === 'object') {
    const normalizeDimension = (value) =>
      Number.isFinite(value) ? Math.max(0, Math.floor(value)) : null;
    return {
      minute: normalizeDimension(rl.minute),
      hour: normalizeDimension(rl.hour),
      day: normalizeDimension(rl.day),
    };
  }
  return null;
}

// ============================================================
// Runtime API-key rate limiting
// ============================================================

const API_KEY_RATE_WINDOWS_MS = {
  minute: 60_000,
  hour: 3_600_000,
  day: 86_400_000,
};

/**
 * Create a sliding-window limiter that enforces every configured API-key
 * dimension atomically. V4 object limits and legacy string limits share the
 * same runtime path. Invalid non-empty configurations fall back to 100/hour
 * rather than silently disabling throttling.
 *
 * @param {{ now?: () => number, defaultLimit?: string|object }} [opts]
 * @returns {(key: object) => boolean}
 */
export function createApiKeyRateLimiter(opts = {}) {
  const buckets = new Map();
  const nowFn = typeof opts.now === 'function' ? opts.now : Date.now;
  const defaultLimit = opts.defaultLimit ?? '100/hour';
  const maxBuckets = positiveInteger(opts.maxBuckets, 10_000);
  const maxEventsPerBucket = positiveInteger(opts.maxEventsPerBucket, 100_000);
  const cleanupEvery = positiveInteger(opts.cleanupEvery, 256);
  let checks = 0;

  function prune(now = nowFn()) {
    let removed = 0;
    for (const [bucketKey, bucket] of buckets) {
      const fresh = bucket.timestamps.filter((timestamp) => now - timestamp < bucket.maxWindowMs);
      if (fresh.length === 0) {
        buckets.delete(bucketKey);
        removed += 1;
      } else {
        bucket.timestamps = fresh;
      }
    }
    return removed;
  }

  function check(key) {
    if (!key) return true;
    const bucketKey = `apikey:${key.id || key.fingerprint_sha256 || key.client || 'unknown'}`;
    const rawLimit = key.rate_limit === undefined ? defaultLimit : key.rate_limit;
    if (rawLimit == null) {
      buckets.delete(bucketKey);
      return true;
    }

    let limits = normalizeRateLimit(rawLimit);
    if (!limits) limits = normalizeRateLimit(defaultLimit);
    if (!limits) return false;

    const active = Object.entries(API_KEY_RATE_WINDOWS_MS)
      .filter(([name]) => limits[name] != null)
      .map(([name, windowMs]) => ({ name, windowMs, max: limits[name] }));
    if (active.length === 0) {
      buckets.delete(bucketKey);
      return true;
    }

    const now = nowFn();
    checks += 1;
    if (checks % cleanupEvery === 0 || (!buckets.has(bucketKey) && buckets.size >= maxBuckets)) {
      prune(now);
    }
    if (!buckets.has(bucketKey) && buckets.size >= maxBuckets) return false;

    const maxWindowMs = Math.max(...active.map((x) => x.windowMs));
    const fresh = (buckets.get(bucketKey)?.timestamps || []).filter(
      (timestamp) => now - timestamp < maxWindowMs,
    );

    for (const { windowMs, max } of active) {
      const count = fresh.reduce(
        (total, timestamp) => total + (now - timestamp < windowMs ? 1 : 0),
        0,
      );
      if (count >= max) {
        buckets.set(bucketKey, { timestamps: fresh, maxWindowMs });
        return false;
      }
    }
    if (fresh.length >= maxEventsPerBucket) {
      buckets.set(bucketKey, { timestamps: fresh, maxWindowMs });
      return false;
    }

    fresh.push(now);
    buckets.set(bucketKey, { timestamps: fresh, maxWindowMs });
    return true;
  }

  check.prune = prune;
  check.size = () => buckets.size;
  return check;
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

// ============================================================
// helpers
// ============================================================

function genRandomBase62(len) {
  // base62 = 0-9 a-z A-Z; rejection sampling keeps every symbol equiprobable.
  const alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return randomString(alphabet, len);
}

/**
 * 生成 API Key (display 一次, 存 hash)
 * @returns {{ id, secret, fingerprint, key_obj }}
 */
export function generateApiKey(name, client, opts = {}) {
  const random = genRandomBase62(KEY_RANDOM_LEN);
  const secret = `${KEY_PREFIX}_${ENV}_${random}`;
  const fingerprint = createHash('sha256').update(secret).digest('hex');
  const id = fingerprint.slice(0, 16); // 短 id
  const now = new Date();
  const ttlMs = opts.ttl_ms || DEFAULT_TTL_MS;
  const key_obj = {
    id,
    name: name || 'unnamed',
    client, // 归属的 client name
    scopes: opts.scopes || (opts.is_master ? MASTER_KEY_SCOPES : DEFAULT_CHILD_SCOPES),
    allowed_secrets: opts.allowed_secrets || [],
    allowed_services: opts.allowed_services || [],
    rate_limit: opts.rate_limit || '100/hour',
    ip_whitelist: opts.ip_whitelist || null,
    fingerprint_sha256: fingerprint,
    created_at: now.toISOString(),
    created_by: opts.created_by || client,
    expires_at: new Date(now.getTime() + ttlMs).toISOString(),
    revoked_at: null,
    last_used_at: null,
    use_count: 0,
    // v3.0 M3.3: Master / Child Key 关系
    is_master: !!opts.is_master,
    can_create_child: !!opts.is_master, // 只能 master 创建 child
    default_child_ttl_seconds: opts.default_child_ttl_seconds || DEFAULT_CHILD_TTL_SECONDS,
    child_scopes: opts.child_scopes || DEFAULT_CHILD_SCOPES,
    parent_master_id: opts.parent_master_id || null, // 子 key 记录归属 master
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
    scopes: opts.scopes || MASTER_KEY_SCOPES,
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
    childScopes = childScopes.filter((s) => master.child_scopes.includes(s));
  }
  if (!Array.isArray(childScopes) || childScopes.length === 0) {
    return { ok: false, reason: 'no_valid_scopes' };
  }

  const masterAllowedSecrets = Array.isArray(master.allowed_secrets) ? master.allowed_secrets : [];
  const masterSecretsRestricted = masterAllowedSecrets.length > 0;
  let allowedSecrets =
    opts.allowed_secrets !== undefined
      ? Array.isArray(opts.allowed_secrets)
        ? opts.allowed_secrets
        : []
      : masterAllowedSecrets;
  if (masterSecretsRestricted) {
    allowedSecrets = allowedSecrets.filter((s) => masterAllowedSecrets.includes(s));
    if (childScopes.includes('secrets:resolve') && allowedSecrets.length === 0) {
      return { ok: false, reason: 'no_allowed_secrets' };
    }
  }

  const masterAllowedServices = Array.isArray(master.allowed_services)
    ? master.allowed_services
    : [];
  const masterServicesRestricted = masterAllowedServices.length > 0;
  let allowedServices =
    opts.allowed_services !== undefined
      ? Array.isArray(opts.allowed_services)
        ? opts.allowed_services
        : []
      : masterAllowedServices;
  if (masterServicesRestricted) {
    allowedServices = allowedServices.filter((s) => masterAllowedServices.includes(s));
    if (childScopes.includes('services:proxy') && allowedServices.length === 0) {
      return { ok: false, reason: 'no_allowed_services' };
    }
  }

  const masterIps = Array.isArray(master.ip_whitelist) ? master.ip_whitelist : [];
  const masterIpRestricted = masterIps.length > 0;
  let childIps =
    opts.ip_whitelist !== undefined
      ? Array.isArray(opts.ip_whitelist)
        ? opts.ip_whitelist
        : []
      : masterIps;
  if (masterIpRestricted) {
    childIps = childIps.filter((ip) => masterIps.includes(ip));
    if (childIps.length === 0) return { ok: false, reason: 'no_allowed_ips' };
  }

  const parentRate = master.rate_limit ?? '100/hour';
  const childRate = opts.rate_limit ?? parentRate;
  const parentRateNorm = normalizeRateLimit(parentRate);
  const childRateNorm = normalizeRateLimit(childRate);
  if (!childRateNorm) return { ok: false, reason: 'invalid_rate_limit' };
  if (parentRateNorm) {
    for (const dim of ['minute', 'hour', 'day']) {
      const parentMax = parentRateNorm[dim];
      const childMax = childRateNorm[dim];
      if (parentMax != null && (childMax == null || childMax > parentMax)) {
        return { ok: false, reason: 'rate_limit_escalation' };
      }
    }
  }

  let childTtlSec = Number(
    opts.ttl_seconds ?? master.default_child_ttl_seconds ?? DEFAULT_CHILD_TTL_SECONDS,
  );
  if (!Number.isSafeInteger(childTtlSec) || childTtlSec <= 0) {
    return { ok: false, reason: 'invalid_ttl' };
  }
  if (master.expires_at) {
    const remainingMs = new Date(master.expires_at).getTime() - Date.now();
    if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
      return { ok: false, reason: 'expired' };
    }
    if (remainingMs < 1000) return { ok: false, reason: 'expired' };
    childTtlSec = Math.min(childTtlSec, Math.floor(remainingMs / 1000));
  }

  const { secret, key_obj } = generateApiKey(name, master.client, {
    scopes: childScopes,
    allowed_secrets: allowedSecrets,
    allowed_services: allowedServices,
    rate_limit: childRate,
    ip_whitelist: childIps.length > 0 ? childIps : null,
    ttl_ms: childTtlSec * 1000,
    parent_master_id: master.id,
    created_by: `master:${master.id}`,
  });
  if (master.expires_at && Date.parse(key_obj.expires_at) > Date.parse(master.expires_at)) {
    key_obj.expires_at = master.expires_at;
  }
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
  const k = cfgKeys.find((x) => x.fingerprint_sha256 === fp);
  if (!k) return null;
  if (k.revoked_at || isExpired(k)) return null;
  if (k.parent_master_id) {
    const parent = cfgKeys.find((candidate) => candidate.id === k.parent_master_id);
    if (!parent || parent.client !== k.client || !canCreateChild(parent).ok) return null;
  }
  return k;
}

/**
 * 验证 API Key 是否能 resolve 某个 secret
 */
export function canResolveSecret(k, secretName) {
  if (!k || !k.scopes || !k.scopes.includes('secrets:resolve')) return false;
  if (Array.isArray(k.allowed_secrets) && k.allowed_secrets.length > 0) {
    if (!k.allowed_secrets.includes(secretName)) return false;
  }
  return true;
}

/**
 * 验证 API Key 是否能 proxy 某个 service
 */
export function canProxyService(k, serviceName) {
  if (!k || !k.scopes || !k.scopes.includes('services:proxy')) return false;
  if (Array.isArray(k.allowed_services) && k.allowed_services.length > 0) {
    if (!k.allowed_services.includes(serviceName)) return false;
  }
  return true;
}

/**
 * 检查 API Key 是否过期
 */
export function isExpired(k) {
  if (!k?.expires_at) return true;
  const expiresAt = Date.parse(k.expires_at);
  return !Number.isFinite(expiresAt) || Date.now() >= expiresAt;
}

/**
 * 列出 client 自己可见的 api keys (admin 看全部)
 */
export function listApiKeys(cfgKeys, opts = {}) {
  if (!cfgKeys || !Array.isArray(cfgKeys)) return [];
  let keys = cfgKeys;
  if (opts.clientOnly) keys = keys.filter((k) => k.client === opts.clientOnly);
  return keys.map((k) => publicView(k));
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
  const { secret, key_obj } = generateApiKey(name, client, opts);
  cfgKeys.push(key_obj);
  return { key_obj: publicView(key_obj), secret };
}

/**
 * 撤销 API Key (admin 或 self)
 */
export function revokeApiKey(cfgKeys, id, by) {
  const k = cfgKeys.find((x) => x.id === id);
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
