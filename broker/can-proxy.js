// broker/can-proxy.js — 抽离 canProxy / isServiceAllowed / clientNamesAllowedFor
// 让 server.js 不被 ACL 逻辑拖长, 便于单测
//
// rule 形式 (client.allowed_proxy / allowed_resolve):
//   - '*' 或 '.*'                         → 通配
//   - 'github'                            → 精确匹配 serviceName
//   - 'githu*' / '^github$' / 'aliyun.*'  → 含 regex 元字符时走 RegExp
//   - { service: 'github' }               → object 显式
//   - { service: 'github', paths: [...] } → service + path 都匹配
//
// canProxy / isServiceAllowed / clientNamesAllowedFor 都用统一 matchProxyRule,
// 累加语义: 任一 rule 命中即可 (之前是首个不匹配就 return false, 已修)

export function isSafeRegexPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length > 256) return false;
  if (/\([^)]*[*+][^)]*\)[*+{]/.test(pattern)) return false;
  if (/\(([^|()]+)\|\1[^)]*\)[*+{]/.test(pattern)) return false;
  return true;
}

export function checkPathAllowed(pattern, path) {
  if (pattern == null) return true;
  if (Array.isArray(pattern)) {
    if (pattern.length === 0) return true; // empty allowlist = no restriction
    return pattern.some(p => checkPathAllowed(p, path));
  }
  if (!isSafeRegexPattern(pattern)) return false;
  try {
    return new RegExp(pattern).test(path);
  } catch {
    return false;
  }
}

// 仅当 string 含 * / ^ / $ 时才走 RegExp. 普通字面 (如 "github") 不会触发,
// 避免把 '.' 当任意字符. 用户要 regex 显式用 ^...$ / ...* / .* 等含 *^$ 形式.
const REGEX_META = /[*^$]/;
function matchAsRegex(s, name) {
  if (typeof s !== 'string' || !REGEX_META.test(s)) return false;
  try { return new RegExp(s).test(name); } catch { return false; }
}

export function matchProxyRule(rule, serviceName, path) {
  if (rule === '*' || rule === '.*') return true;
  if (typeof rule === 'string') {
    return rule === serviceName || matchAsRegex(rule, serviceName);
  }
  if (rule && typeof rule === 'object') {
    const svc = rule.service;
    if (svc != null && svc !== serviceName && !matchAsRegex(svc, serviceName)) return false;
    if (rule.paths && !checkPathAllowed(rule.paths, path)) return false;
    return true;
  }
  return false;
}

export function canProxy(ctx, serviceName, path) {
  if (!ctx || !ctx.client) return false;
  if (ctx.client.security_profile === 'strict') return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  for (const rule of allow) {
    if (matchProxyRule(rule, serviceName, path)) return true;
  }
  return false;
}

// Does the client have ANY access to a service at all (for the dashboard badge)?
export function isServiceAllowed(ctx, serviceName) {
  if (!ctx || !ctx.client) return false;
  if (ctx.client.security_profile === 'strict') return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  return allow.some(rule => matchProxyRule(rule, serviceName, '*'));
}

// Phase 1.2: list client names that have access to a given service. Used by
// the admin Services UI to show the permission matrix.
export function clientNamesAllowedFor(clients, serviceName) {
  const out = [];
  for (const [cname, c] of Object.entries(clients || {})) {
    if (c.role === 'admin') { out.push(cname); continue; }
    const allow = c.allowed_proxy || [];
    if (allow.some(rule => matchProxyRule(rule, serviceName, '*'))) out.push(cname);
  }
  return out;
}
