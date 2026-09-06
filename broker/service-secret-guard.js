// broker/service-secret-guard.js — v3.1 M5.5
// Service ↔ Secret 联动: call_service 前置检查
//
// 设计目标:
//   当 svc.token_secret 引用的 secret 是 expired / unreachable / misconfigured 时,
//   /api/v1/proxy/:service 提前 503 阻断, 不真去调上游.
//
// 理由:
//   1. 节省上游调用 time / 配额
//   2. 避免把 expired 凭据传给上游触发风控 (e.g. 401 风暴)
//   3. 让用户能立刻知道"这个 service 不可用是 secret 挂了"
//
// 5 min 内存缓存 (避免每个 call_service 都查 healthcheck state 读盘)
// 健康度数据来自 broker/healthcheck.js getSecretStatus() (M5.3)
//
// 公开 API:
//   checkSecretForService(tokenSecret, getSecretStatusFn) → { allowed, status, detail, ... }
//   clearSecretGuardCache(name?)  → 清缓存 (name 缺省清全部)
//   SECRET_GUARD_TTL_MS           → 5 min (常量, 暴露给测试)
//
// 5 维 status 分类 (跟 healthcheck M5.3 一致):
//   allowed=true  + ok       → 凭据好, 放过
//   allowed=true  + skipped  → service 可能不用 secret, 放过
//   allowed=true  + unknown  → 没 healthcheck 数据, 放过 (不阻断)
//   allowed=false + expired       → 真凭据过期, 阻断
//   allowed=false + unreachable   → 基础设施层不可达, 阻断
//   allowed=false + misconfigured → 配置错, 阻断
//   allowed=false + fail           → 兜底未知错, 阻断

export const SECRET_GUARD_TTL_MS = 5 * 60 * 1000;
const secretGuardCache = new Map();  // tokenSecret -> { result, cached_at }

/**
 * 检查 tokenSecret 引用的 secret 是否可用.
 * @param {string|null} tokenSecret - service.token_secret 字段值
 * @param {(name: string) => ({status, detail, latency_ms?, ts?} | null)} getSecretStatusFn
 *   - 注入的 healthcheck.getSecretStatus 函数, 方便测试
 * @returns {{allowed: boolean, status: string, detail: string, latency_ms?: number, ts?: string}}
 */
export function checkSecretForService(tokenSecret, getSecretStatusFn, opts = {}) {
  const failClosed = opts.failClosed === true;
  const maxStatusAgeMs = Number(opts.maxStatusAgeMs || SECRET_GUARD_TTL_MS * 2);
  if (!tokenSecret) {
    return { allowed: !failClosed, status: 'no_secret', detail: 'service has no credential reference configured' };
  }
  if (typeof getSecretStatusFn !== 'function') {
    return { allowed: !failClosed, status: 'no_check_fn', detail: 'getSecretStatus not provided' };
  }
  const cacheKey = `${failClosed ? 'strict' : 'compat'}:${tokenSecret}`;
  const cached = secretGuardCache.get(cacheKey);
  const now = Date.now();
  if (cached && (now - cached.cached_at) < SECRET_GUARD_TTL_MS) {
    return cached.result;
  }
  const s = getSecretStatusFn(tokenSecret);
  let result;
  if (!s) {
    result = { allowed: !failClosed, status: 'unknown', detail: 'no healthcheck data yet' };
  } else if (failClosed && (!s.ts || !Number.isFinite(Date.parse(s.ts)) || now - Date.parse(s.ts) > maxStatusAgeMs)) {
    result = { allowed: false, status: 'stale', detail: 'credential health evidence is missing or stale' };
  } else if (s.status === 'ok' || s.status === 'skipped' || s.status === 'unknown') {
    result = { allowed: true, status: s.status, detail: s.detail, latency_ms: s.latency_ms, ts: s.ts };
  } else if (s.status === 'expired' || s.status === 'unreachable' || s.status === 'misconfigured' || s.status === 'fail') {
    // 5 维中的 4 个非 ok 维度都阻断
    result = { allowed: false, status: s.status, detail: s.detail, latency_ms: s.latency_ms, ts: s.ts };
  } else {
    // 未知 status (e.g. 未来新 status), 保守阻断
    result = { allowed: false, status: s.status, detail: s.detail || 'unknown secret status' };
  }
  secretGuardCache.set(cacheKey, { result, cached_at: now });
  return result;
}

export function clearSecretGuardCache(name) {
  if (name) {
    secretGuardCache.delete(`strict:${name}`);
    secretGuardCache.delete(`compat:${name}`);
  }
  else secretGuardCache.clear();
}

/**
 * 把 guard 结果翻译成给用户看的提示.
 * @param {string} status - expired / unreachable / misconfigured / fail
 * @returns {string} 用户行动提示
 */
export function guardHint(status) {
  switch (status) {
    case 'expired':       return 'rotate the secret first';
    case 'unreachable':   return 'fix the upstream network/firewall';
    case 'misconfigured': return 'fix the secret config (broker.yaml)';
    case 'fail':          return 'check the secret status';
    case 'stale':         return 'run a fresh credential health check';
    default:              return 'check the secret status';
  }
}
