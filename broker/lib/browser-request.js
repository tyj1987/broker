// Browser-session request boundary.
// Cookie-authenticated mutations require an exact same-origin browser request.
// mTLS, API-key and explicit x-auth-token clients are unaffected.

import { SESSION_HEADER } from './session.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function firstHeader(req, name) {
  const value = req?.headers?.[String(name).toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeOrigin(value, { configured = false } = {}) {
  if (!value || typeof value !== 'string') return null;
  try {
    const url = new URL(value.trim());
    if (url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== '/' && url.pathname !== '') return null;
    if (url.protocol !== 'https:') {
      // The public broker is HTTPS-only. Local loopback HTTP remains useful in
      // tests and development, but must never authorize a non-loopback origin.
      const loopback = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
      if (!loopback || url.protocol !== 'http:') return null;
    }
    return url.origin;
  } catch {
    return configured ? null : null;
  }
}

export function expectedBrowserOrigin(req, env = process.env) {
  const configured = env.BROKER_PUBLIC_ORIGIN || env.BROKER_BROWSER_ORIGIN;
  if (configured) return normalizeOrigin(configured, { configured: true });

  const host = firstHeader(req, 'host');
  if (!host) return null;
  const forwardedProto = String(firstHeader(req, 'x-forwarded-proto') || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  const protocol = req?.socket?.encrypted
    ? 'https'
    : forwardedProto === 'http' || forwardedProto === 'https'
      ? forwardedProto
      : 'https';
  return normalizeOrigin(`${protocol}://${host}`);
}

export function isCookieSessionRequest(req, sessionHeader = SESSION_HEADER) {
  const cookie = String(firstHeader(req, 'cookie') || '');
  const hasCookie = /(?:^|;\s*)broker_session=[^;]+/.test(cookie);
  const hasExplicitHeader = !!firstHeader(req, sessionHeader);
  return hasCookie && !hasExplicitHeader;
}

export function isBrowserRequest(req) {
  return !!(
    firstHeader(req, 'origin') ||
    firstHeader(req, 'sec-fetch-site') ||
    firstHeader(req, 'sec-fetch-mode') ||
    firstHeader(req, 'sec-fetch-dest')
  );
}

/**
 * Validate a potentially state-changing browser request.
 *
 * `requireOrigin=false` is appropriate for public login endpoints: browser
 * requests are checked when browser metadata exists, while non-browser CLI
 * clients remain compatible. Cookie-authenticated mutations use true.
 *
 * @returns {{ ok: boolean, reason: string, origin?: string, expectedOrigin?: string }}
 */
export function checkTrustedBrowserMutation(req, opts = {}) {
  const method = String(req?.method || 'GET').toUpperCase();
  if (SAFE_METHODS.has(method)) return { ok: true, reason: 'safe_method' };

  const fetchSite = String(firstHeader(req, 'sec-fetch-site') || '').toLowerCase();
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return { ok: false, reason: 'cross_origin_fetch_metadata' };
  }

  const rawOrigin = firstHeader(req, 'origin');
  if (!rawOrigin) {
    return opts.requireOrigin
      ? { ok: false, reason: 'origin_required' }
      : { ok: true, reason: 'non_browser_client' };
  }

  const origin = normalizeOrigin(String(rawOrigin));
  if (!origin) return { ok: false, reason: 'invalid_origin' };

  const expectedOrigin = expectedBrowserOrigin(req, opts.env || process.env);
  if (!expectedOrigin) return { ok: false, reason: 'trusted_origin_unavailable', origin };
  if (origin !== expectedOrigin) {
    return { ok: false, reason: 'origin_mismatch', origin, expectedOrigin };
  }
  return { ok: true, reason: 'same_origin', origin, expectedOrigin };
}
