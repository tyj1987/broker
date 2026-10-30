// broker/lib/upstream-url.js — safe URL resolution for credential-bearing proxy calls.
//
// A caller-controlled path must never be able to replace the configured
// upstream origin. WHATWG URL resolution accepts absolute and scheme-relative
// URLs, so resolving without an origin check can exfiltrate injected secrets.

const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);

export function isLoopbackHostname(hostname) {
  const host = String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  if (host === 'localhost' || host === '::1') return true;
  return /^127(?:\.\d{1,3}){3}$/.test(host);
}

export function validateConfiguredUpstream(upstream, { allowInsecureHttp = false } = {}) {
  let base;
  try {
    base = new URL(upstream);
  } catch {
    throw new Error('Invalid upstream URL');
  }
  if (!ALLOWED_PROTOCOLS.has(base.protocol)) {
    throw new Error(`Unsupported upstream protocol: ${base.protocol}`);
  }
  if (base.username || base.password) {
    throw new Error('Upstream URL must not contain embedded credentials');
  }
  if (base.protocol === 'http:' && !isLoopbackHostname(base.hostname) && !allowInsecureHttp) {
    throw new Error('Plain HTTP upstream is forbidden for non-loopback hosts');
  }
  return base;
}

export function resolveUpstreamUrl(upstream, path = '/', opts = {}) {
  const base = validateConfiguredUpstream(upstream, opts);

  if (path != null && typeof path !== 'string') throw new Error('Proxy path must be a string');
  const rawPath = path || '/';
  if (rawPath.length > 8192 || /[\\\u0000-\u0020\u007f]/.test(rawPath)) {
    throw new Error('Proxy path contains forbidden characters or is too long');
  }
  const resolved = new URL(rawPath, base);
  if (resolved.username || resolved.password || resolved.hash) {
    throw new Error('Proxy path must not contain credentials or fragments');
  }
  // Reject ambiguous separator and double-encoding forms rather than relying
  // on the upstream's decode count. Query parameters are not path segments.
  if (/%(?:2f|5c|25)/i.test(resolved.pathname)) {
    throw new Error('Encoded separators or double-encoded paths are forbidden');
  }
  try {
    decodeURIComponent(resolved.pathname);
  } catch {
    throw new Error('Malformed path encoding');
  }

  if (resolved.origin !== base.origin) {
    throw new Error('Proxy path must stay within the configured upstream origin');
  }
  if (!ALLOWED_PROTOCOLS.has(resolved.protocol)) {
    throw new Error(`Unsupported upstream protocol: ${resolved.protocol}`);
  }

  return resolved;
}
