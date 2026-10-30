// broker/lib/proxy-headers.js — sanitize headers crossing the credential-proxy boundary.
//
// Caller-controlled request headers must not override broker-managed credentials,
// tracing metadata, Host framing, or hop-by-hop transport headers. Likewise,
// upstream response headers must not be able to set cookies for the broker origin.

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const BLOCKED_REQUEST_HEADERS = new Set([
  ...HOP_BY_HOP,
  'host',
  'content-length',
  'expect',
  'x-broker-relay-secret',
  'x-broker-upstream-authorization',
]);

const BLOCKED_RESPONSE_HEADERS = new Set([...HOP_BY_HOP, 'set-cookie', 'set-cookie2']);

function lowerName(name) {
  return String(name || '')
    .trim()
    .toLowerCase();
}

/**
 * Build outbound headers for an upstream credential-proxy request.
 *
 * Broker-managed base/injected headers always win case-insensitively over
 * caller-supplied headers.
 */
export function buildProxyRequestHeaders({
  baseHeaders = {},
  userHeaders = {},
  injectHeaders = {},
} = {}) {
  const protectedNames = new Set([
    ...Object.keys(baseHeaders).map(lowerName),
    ...Object.keys(injectHeaders).map(lowerName),
  ]);

  const nominated = connectionHeaderNames(userHeaders);
  const safeUserHeaders = {};
  const safeUserKeys = new Map();
  if (userHeaders && typeof userHeaders === 'object' && !Array.isArray(userHeaders)) {
    for (const [rawName, value] of Object.entries(userHeaders)) {
      const name = String(rawName || '').trim();
      const lower = lowerName(name);
      if (!name || !lower || value == null) continue;
      if (BLOCKED_REQUEST_HEADERS.has(lower) || protectedNames.has(lower) || nominated.has(lower))
        continue;

      // Collapse case-insensitive duplicates deterministically.
      const previous = safeUserKeys.get(lower);
      if (previous) delete safeUserHeaders[previous];
      safeUserKeys.set(lower, name);
      safeUserHeaders[name] = value;
    }
  }

  return {
    ...baseHeaders,
    ...safeUserHeaders,
    ...injectHeaders,
  };
}

/**
 * Filter upstream response headers before they are sent from the broker origin.
 *
 * Content-Encoding and Content-Length are intentionally preserved: Node's
 * https.request does not auto-decompress the response body.
 */
function connectionHeaderNames(headers) {
  const names = new Set();
  for (const [key, value] of Object.entries(headers || {})) {
    if (lowerName(key) === 'connection') {
      for (const part of String(value).split(',')) if (part.trim()) names.add(lowerName(part));
    }
  }
  return names;
}

export function sanitizeProxyResponseHeaders(headers = {}) {
  const nominated = connectionHeaderNames(headers);
  const out = {};
  const seen = new Map();
  for (const [rawName, value] of Object.entries(headers || {})) {
    const name = String(rawName || '').trim();
    const lower = lowerName(name);
    if (
      !name ||
      !lower ||
      value == null ||
      BLOCKED_RESPONSE_HEADERS.has(lower) ||
      nominated.has(lower)
    )
      continue;

    const previous = seen.get(lower);
    if (previous) delete out[previous];
    seen.set(lower, name);
    out[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

export { HOP_BY_HOP, BLOCKED_REQUEST_HEADERS, BLOCKED_RESPONSE_HEADERS };
