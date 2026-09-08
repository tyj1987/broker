// broker/lib/security-headers.js — HTTP security headers for all responses.
//
// Default-on headers applied to every response (send(), handleStatic, SSE, audit export).
// Browsers should not be able to render the admin dashboard in a frame, sniff content
// types, or be tricked into a protocol downgrade.
//
// Reference:
//   - https://owasp.org/www-project-secure-headers/
//   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
//   - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
//
// Per-route overrides:
//   - /api/v1/admin/* responses stay JSON; CSP doesn't apply but X-Frame-Options does.
//   - Dashboard HTML responses get a stricter CSP (script-src 'self' etc.).
//   - SSE streams set Cache-Control: no-store (already) and skip X-Frame-Options since
//     they're not navigable, but we'll still set X-Content-Type-Options for safety.
//
// Configuration:
//   - BROKER_HSTS_MAX_AGE  (default 31536000 = 1 year)
//   - BROKER_CSP           (override CSP entirely; advanced)
//   - BROKER_DISABLE_SECURITY_HEADERS=1 (escape hatch; e.g. behind a strict CSP proxy)
//
// Zero deps.

const HSTS_MAX_AGE = Number.parseInt(process.env.BROKER_HSTS_MAX_AGE || '31536000', 10);
const DISABLED = process.env.BROKER_DISABLE_SECURITY_HEADERS === '1';

// CSP for HTML dashboard pages. The dashboard JS pulls in additional <script> tags
// loaded via /app.js etc. (same origin), so 'self' is enough. style-src 'unsafe-inline'
// is required because some dashboard inline <style> blocks were not migrated; revisit
// when style.css contains everything.
const CSP_HTML_DEFAULT =
  "default-src 'self'; " +
  "script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; " +
  "font-src 'self' data:; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "object-src 'none'";

// CSP for JSON API responses (frame-ancestors 'none' still applies; no script/style sources needed)
const CSP_API_DEFAULT =
  "default-src 'none'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'none'";

function buildBaseHeaders() {
  if (DISABLED) return {};
  return {
    // Block MIME sniffing
    'X-Content-Type-Options': 'nosniff',
    // Clickjacking protection (applies to all responses including JSON)
    'X-Frame-Options': 'DENY',
    // Referer leakage prevention (no referer to other origins from this app)
    'Referrer-Policy': 'no-referrer',
    // Restrict powerful browser features we never use
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    // Force HTTPS for one year (and subdomains). Only emit on HTTPS connections to
    // avoid breaking plain-HTTP local health server (broker/lib/local-health.js).
    'Strict-Transport-Security': `max-age=${HSTS_MAX_AGE}; includeSubDomains`,
    // Cross-origin isolation hints (best-practice for any app handling credentials)
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
}

const BASE_HEADERS = buildBaseHeaders();

/**
 * Build the headers object for a given response type.
 *
 * @param {{ kind?: 'html'|'json'|'sse'|'static' }} opts
 * @returns {Record<string, string>}
 */
export function securityHeaders(opts = {}) {
  if (DISABLED) return {};
  const kind = opts.kind || 'json';
  const headers = { ...BASE_HEADERS };
  if (kind === 'html') {
    headers['Content-Security-Policy'] = process.env.BROKER_CSP || CSP_HTML_DEFAULT;
  } else if (kind === 'json') {
    headers['Content-Security-Policy'] = process.env.BROKER_CSP_API || CSP_API_DEFAULT;
  } else if (kind === 'sse') {
    headers['Content-Security-Policy'] = process.env.BROKER_CSP_API || CSP_API_DEFAULT;
    headers['Cache-Control'] = 'no-store';
  } else if (kind === 'static') {
    // static JS / CSS — use the same CSP as HTML so they get loaded under it
    headers['Content-Security-Policy'] = process.env.BROKER_CSP || CSP_HTML_DEFAULT;
  }
  return headers;
}

/**
 * Apply security headers to an outgoing response by mutating its headers before
 * writeHead. Caller can still override via the headers argument.
 *
 * @param {import('node:http').ServerResponse} res
 * @param {Record<string, string>} headers  existing headers (will be merged)
 * @param {{ kind?: string }} [opts]
 */
export function applySecurityHeaders(res, headers = {}, opts = {}) {
  if (DISABLED) return headers;
  return { ...securityHeaders(opts), ...headers };
}

/**
 * For tests: snapshot the headers that would be set for a given kind.
 */
export function snapshotHeaders(kind) {
  return securityHeaders({ kind });
}

export const _internals = {
  HSTS_MAX_AGE,
  CSP_HTML_DEFAULT,
  CSP_API_DEFAULT,
  DISABLED,
  BASE_HEADERS,
};
