import { isIP } from 'node:net';

const BLOCKED_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'host',
  'connection', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te',
  'trailer', 'content-length', 'forwarded', 'x-forwarded-for',
  'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip',
]);

export function normalizeMethod(method) {
  const value = String(method || 'GET').toUpperCase();
  if (!/^[A-Z]+$/.test(value)) throw new Error('Invalid HTTP method');
  return value;
}

export function buildPinnedUrl(upstream, requestPath = '/', query) {
  const base = new URL(upstream);
  if (base.protocol !== 'https:') throw new Error('Upstream must use HTTPS');
  const rawPath = String(requestPath || '/');
  if (!rawPath.startsWith('/') || rawPath.startsWith('//') || /[\r\n\\]/.test(rawPath)) {
    throw new Error('Proxy path must be an absolute-path reference');
  }
  const target = new URL(rawPath, base);
  if (target.origin !== base.origin) throw new Error('Proxy target origin is not allowed');
  for (const [key, value] of Object.entries(query || {})) {
    if (value !== null && value !== undefined) target.searchParams.set(key, String(value));
  }
  return target;
}

export function sanitizeCallerHeaders(headers, allowedHeaders = ['accept', 'content-type', 'idempotency-key', 'if-match', 'if-none-match']) {
  const out = {};
  const allow = new Set(allowedHeaders.map(h => String(h).toLowerCase()));
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (BLOCKED_HEADERS.has(lower)) throw new Error(`Caller header is forbidden: ${name}`);
    if (!allow.has(lower)) throw new Error(`Caller header is not allowlisted: ${name}`);
    if (/[\r\n]/.test(String(value))) throw new Error(`Invalid caller header value: ${name}`);
    out[name] = value;
  }
  return out;
}

// Caller headers are applied first; broker-owned headers must always win.
export function mergeOutboundHeaders(baseHeaders = {}, callerHeaders = {}, brokerHeaders = {}) {
  return { ...baseHeaders, ...callerHeaders, ...brokerHeaders };
}

function ipv4Number(ip) {
  return ip.split('.').reduce((n, part) => (n * 256) + Number(part), 0) >>> 0;
}

export function isForbiddenDestinationIp(ip) {
  if (isIP(ip) === 4) {
    const n = ipv4Number(ip);
    const inRange = (base, bits) => (n >>> (32 - bits)) === (ipv4Number(base) >>> (32 - bits));
    return inRange('0.0.0.0', 8) || inRange('10.0.0.0', 8) || inRange('100.64.0.0', 10) ||
      inRange('127.0.0.0', 8) || inRange('169.254.0.0', 16) || inRange('172.16.0.0', 12) ||
      inRange('192.0.0.0', 24) || inRange('192.168.0.0', 16) || inRange('198.18.0.0', 15) ||
      inRange('224.0.0.0', 4) || inRange('240.0.0.0', 4);
  }
  if (isIP(ip) === 6) {
    const value = ip.toLowerCase();
    return value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') ||
      /^fe[89ab]/.test(value) || value.startsWith('ff') || value.startsWith('::ffff:127.') ||
      value.startsWith('::ffff:10.') || value.startsWith('::ffff:192.168.');
  }
  return true;
}

export function assertSafeDestination(hostname, resolvedIp) {
  if (isIP(hostname)) throw new Error('IP-literal upstreams are forbidden');
  if (isForbiddenDestinationIp(resolvedIp)) throw new Error('Upstream resolved to a forbidden network');
}

export const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
