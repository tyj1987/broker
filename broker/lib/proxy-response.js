// Keep an upstream response outside the Broker browser security boundary.
// The body remains byte-for-byte unchanged (Node does not auto-decompress it).
const BLOCKED = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'set-cookie', 'set-cookie2']);
const normalize = name => String(name || '').trim().toLowerCase();

export function proxyResponseHeaders(upstream = {}, trusted = {}) {
  const nominated = new Set();
  for (const [name, value] of Object.entries(upstream || {})) {
    if (normalize(name) === 'connection') for (const item of String(value).split(',')) nominated.add(normalize(item));
  }
  const headers = Object.create(null);
  for (const [name, value] of Object.entries(upstream || {})) {
    const lower = normalize(name);
    if (!lower || value == null || BLOCKED.has(lower) || nominated.has(lower)) continue;
    const text = Array.isArray(value) ? value.join(', ') : String(value);
    if (!/^[!#$%&'*+\-.^_`|~0-9a-z]+$/.test(lower) || /[\r\n\0]/.test(text)) continue;
    headers[lower] = text;
  }
  for (const [name, value] of Object.entries(trusted)) headers[normalize(name)] = value;
  // Upstream HTML may be returned for inspection, never with Broker-origin privileges.
  headers['content-security-policy'] = "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  headers['x-content-type-options'] = 'nosniff';
  headers['x-frame-options'] = 'DENY';
  headers['referrer-policy'] = 'no-referrer';
  headers['cache-control'] = 'no-store';
  return headers;
}
