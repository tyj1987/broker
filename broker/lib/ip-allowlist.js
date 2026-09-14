// broker/lib/ip-allowlist.js — IP / CIDR allowlist checks (zero deps)
// Used by API Key auth (ip_whitelist field) and optionally by other gates.

/**
 * Normalize remote address from Node req.socket / X-Forwarded-For style.
 * Strips IPv4-mapped IPv6 prefix (::ffff:1.2.3.4 -> 1.2.3.4).
 */
export function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') return '';
  let s = ip.trim();
  // strip zone id (fe80::1%eth0)
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  if (s.startsWith('::ffff:')) s = s.slice(7);
  return s;
}

/** Parse IPv4 "a.b.c.d" to uint32, or null if invalid. */
function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = [+m[1], +m[2], +m[3], +m[4]];
  if (parts.some(n => n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/**
 * Does `ip` match a single rule?
 * Rules: exact IP, or CIDR like 10.0.0.0/8, or "*" / "any" for allow-all.
 * IPv6: exact match only (no CIDR in v3.2 to keep zero-dep).
 */
export function matchIpRule(ip, rule) {
  const addr = normalizeIp(ip);
  if (!addr || !rule || typeof rule !== 'string') return false;
  const r = rule.trim();
  if (r === '*' || r.toLowerCase() === 'any') return true;

  // CIDR
  if (r.includes('/')) {
    const [base, bitsStr] = r.split('/');
    const bits = parseInt(bitsStr, 10);
    if (!Number.isFinite(bits) || bits < 0 || bits > 32) return false;
    const ipInt = ipv4ToInt(addr);
    const baseInt = ipv4ToInt(normalizeIp(base));
    if (ipInt === null || baseInt === null) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
  }

  // Exact
  return normalizeIp(r) === addr;
}

/**
 * Allow if whitelist is empty/null (open), or any rule matches.
 * @param {string[]|null|undefined} whitelist
 * @param {string} remoteIp
 */
export function isIpAllowed(whitelist, remoteIp) {
  if (whitelist == null) return true;
  if (!Array.isArray(whitelist)) return false;
  if (whitelist.length === 0) return true;
  const addr = normalizeIp(remoteIp);
  if (!addr) return false; // have whitelist but no usable IP -> deny
  return whitelist.some(rule => matchIpRule(addr, rule));
}
