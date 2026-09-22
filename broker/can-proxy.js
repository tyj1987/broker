// broker/can-proxy.js — 抽离 canProxy / isServiceAllowed / clientNamesAllowedFor
// 让 server.js 不被 ACL 逻辑拖长, 便于单测
//
// rule 形式 (client.allowed_proxy / allowed_resolve):
//   - '*' 或 '.*'                         → 通配
//   - 'github'                            → 精确匹配 serviceName
//   - 'githu*' / '^github$' / 'aliyun.*'  → 含 regex 元字符时走 RegExp
//   - { service: 'github' }               → object 显式
//   - { service: 'github', paths: [...] } → service + path 都匹配
//   - { service: 'github', methods: ['GET'] } → 同时限制 HTTP method
//
// canProxy / isServiceAllowed / clientNamesAllowedFor 都用统一 matchProxyRule,
// 累加语义: 任一 rule 命中即可 (之前是首个不匹配就 return false, 已修)

export function checkPathAllowed(pattern, path) {
  if (pattern == null) return true;
  if (Array.isArray(pattern)) {
    if (pattern.length === 0) return true; // empty allowlist = no restriction
    return pattern.some((p) => checkPathAllowed(p, path));
  }
  try {
    return new RegExp(pattern).test(path);
  } catch {
    return false;
  }
}

// 仅当 string 含 * / ^ / $ 时才走 RegExp. 普通字面 (如 "github") 不会触发,
// 避免把 '.' 当任意字符. 用户要 regex 显式用 ^...$ / ...* / .* 等含 *^$ 形式.
const REGEX_META = /[*^$]/;
const SUPPORTED_PROXY_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
]);

export function normalizeProxyMethod(method = 'GET') {
  const normalized = String(method || 'GET')
    .trim()
    .toUpperCase();
  return SUPPORTED_PROXY_METHODS.has(normalized) ? normalized : null;
}

export function checkMethodAllowed(methods, method = 'GET') {
  const normalized = normalizeProxyMethod(method);
  if (!normalized) return false;
  if (methods == null) return true;
  if (!Array.isArray(methods) || methods.length === 0) return false;
  return methods.some((m) => {
    const candidate = String(m).trim().toUpperCase();
    return candidate === '*' || candidate === normalized;
  });
}

function matchAsRegex(s, name) {
  if (typeof s !== 'string' || !REGEX_META.test(s)) return false;
  try {
    return new RegExp(s).test(name);
  } catch {
    return false;
  }
}

export function matchProxyRule(rule, serviceName, path, method = 'GET') {
  if (rule === '*' || rule === '.*') return true;
  if (typeof rule === 'string') {
    return rule === serviceName || matchAsRegex(rule, serviceName);
  }
  if (rule && typeof rule === 'object') {
    const svc = rule.service;
    if (svc != null && svc !== serviceName && !matchAsRegex(svc, serviceName)) return false;
    if (rule.paths && !checkPathAllowed(rule.paths, path)) return false;
    if (rule.methods !== undefined && !checkMethodAllowed(rule.methods, method)) return false;
    return true;
  }
  return false;
}

export function canProxy(ctx, serviceName, path, method = 'GET') {
  if (!ctx || !ctx.client) return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  for (const rule of allow) {
    if (matchProxyRule(rule, serviceName, path, method)) return true;
  }
  return false;
}

// Does the client have ANY access to a service at all (for the dashboard badge)?
function matchServiceRule(rule, serviceName) {
  if (rule === '*' || rule === '.*') return true;
  if (typeof rule === 'string') {
    return rule === serviceName || matchAsRegex(rule, serviceName);
  }
  if (rule && typeof rule === 'object') {
    const svc = rule.service;
    return svc == null || svc === serviceName || matchAsRegex(svc, serviceName);
  }
  return false;
}

export function isServiceAllowed(ctx, serviceName) {
  if (!ctx || !ctx.client) return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  return allow.some((rule) => matchServiceRule(rule, serviceName));
}

// Phase 1.2: list client names that have access to a given service. Used by
// the admin Services UI to show the permission matrix.
export function clientNamesAllowedFor(clients, serviceName) {
  const out = [];
  for (const [cname, c] of Object.entries(clients || {})) {
    if (c.role === 'admin') {
      out.push(cname);
      continue;
    }
    const allow = c.allowed_proxy || [];
    if (allow.some((rule) => matchServiceRule(rule, serviceName))) out.push(cname);
  }
  return out;
}
