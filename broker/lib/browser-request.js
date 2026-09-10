import { V2Error } from './operations-v2.js';

function header(req, name) {
  const value = req?.headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

export function requireTrustedBrowserMutation(req, identityContext, configuredOrigin) {
  if (identityContext?.via !== 'session'
    || !identityContext.authFactors?.includes('webauthn')) {
    throw new V2Error('step_up_required', 'a WebAuthn browser session is required', 403);
  }

  let expected;
  try {
    expected = new URL(configuredOrigin);
  } catch {
    throw new V2Error('browser_origin_unavailable', 'trusted browser origin is not configured', 503);
  }
  if (expected.protocol !== 'https:' || expected.username || expected.password
    || expected.pathname !== '/' || expected.search || expected.hash) {
    throw new V2Error('browser_origin_unavailable', 'trusted browser origin is not configured', 503);
  }

  if (header(req, 'origin') !== expected.origin) {
    throw new V2Error('origin_denied', 'browser request origin is not trusted', 403);
  }
  const fetchSite = header(req, 'sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin') {
    throw new V2Error('origin_denied', 'cross-site browser mutation is denied', 403);
  }
}
