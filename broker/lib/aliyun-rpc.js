// Aliyun RPC (OpenAPI v2) helpers: per-product Version, merge path query.

/** Common RPC API versions keyed by OpenAPI hostname. */
export const ALIYUN_RPC_VERSION_BY_HOST = {
  'ecs.aliyuncs.com': '2014-05-26',
  'alidns.aliyuncs.com': '2015-01-09',
  'ram.aliyuncs.com': '2015-05-01',
  'sts.aliyuncs.com': '2015-04-01',
  'vpc.aliyuncs.com': '2016-04-28',
  'rds.aliyuncs.com': '2014-08-15',
  'slb.aliyuncs.com': '2014-05-15',
  'cdn.aliyuncs.com': '2018-05-10',
  'domain.aliyuncs.com': '2018-01-29',
  'cr.aliyuncs.com': '2016-06-07',
  'pvtz.aliyuncs.com': '2018-01-01',
};

export function hostnameOf(upstream) {
  try { return new URL(upstream).hostname.toLowerCase(); } catch { return ''; }
}

/**
 * Resolve Aliyun RPC Version.
 * Precedence: query / path → serviceCfg.api_version → hostname map → ECS default.
 */
export function aliyunRpcVersion({ serviceCfg = {}, upstream, path, query } = {}) {
  if (query && query.Version) return String(query.Version);
  try {
    const u = new URL(path || '/', 'http://x/');
    const v = u.searchParams.get('Version');
    if (v) return v;
  } catch { /* ignore */ }
  if (serviceCfg.api_version) return String(serviceCfg.api_version);
  if (serviceCfg.version && /^\d{4}-\d{2}-\d{2}$/.test(String(serviceCfg.version))) {
    return String(serviceCfg.version);
  }
  const host = hostnameOf(upstream || serviceCfg.upstream || '');
  if (host && ALIYUN_RPC_VERSION_BY_HOST[host]) return ALIYUN_RPC_VERSION_BY_HOST[host];
  return '2014-05-26';
}

/** Merge `/?Action=&Version=` from path with the JSON query object. */
export function mergeAliyunQuery(path, query) {
  const fromPath = {};
  try {
    const u = new URL(path || '/', 'http://x/');
    for (const [k, v] of u.searchParams.entries()) fromPath[k] = v;
  } catch { /* ignore */ }
  return { ...fromPath, ...(query || {}) };
}
