// broker/lib/mtls.js — V4.1.1 extraction of identity resolution.
//
// Three auth sources are resolved without allowing a weaker supplied identity
// to replace a stronger one. When a bearer key accompanies mTLS or a session,
// it is intersected with that same owner rather than becoming the principal:
//   1. mTLS client cert (CLI / scripts / direct TLS) — two flavors:
//        3a. nginx forward via X-SSL-Client-Verify (when request comes via loopback)
//        3b. direct peer-cert via Node TLS API
//   2. Session cookie (dashboard login)
//   3. API Key Bearer (standalone workload, or a narrowing delegation)
//
// This module is a factory that returns { getIdentity, getApiKeyIdentity } and
// takes all dependencies via a single `deps` object so it's trivially testable
// and reusable outside of server.js.

import { X509Certificate } from 'node:crypto';

/**
 * @param {object} deps
 * @param {object} deps.config                - broker config (CONFIG.clients, CONFIG.api_keys)
 * @param {Function} deps.getSession          - (req) => session | null
 * @param {Function} deps.parseBearer         - (authHeader) => token | null
 * @param {Function} deps.findApiKey          - (apiKeys, token) => key | null
 * @param {Function} deps.isClientIpAllowed   - (apiKey, remoteIp) => boolean
 * @param {Function} deps.rateLimitApiKey     - (apiKey) => boolean
 * @param {Function} deps.recordUse           - (apiKey) => void
 * @param {Function} deps.recordClientSeen    - (clientName) => void
 * @param {Function} deps.audit               - (event) => void
 * @param {Function} [deps.requireNodeCrypto] - override for tests; defaults to node:crypto X509Certificate
 */
export function createIdentityResolver(deps) {
  const {
    config,
    getSession,
    parseBearer,
    findApiKey,
    isClientIpAllowed,
    rateLimitApiKey,
    recordUse,
    recordClientSeen,
    audit,
    requireNodeCrypto,
  } = deps;

  if (typeof getSession !== 'function') throw new Error('mtls: getSession required');
  if (typeof parseBearer !== 'function') throw new Error('mtls: parseBearer required');
  if (typeof findApiKey !== 'function') throw new Error('mtls: findApiKey required');
  if (typeof isClientIpAllowed !== 'function') throw new Error('mtls: isClientIpAllowed required');
  if (typeof rateLimitApiKey !== 'function') throw new Error('mtls: rateLimitApiKey required');
  if (typeof recordUse !== 'function') throw new Error('mtls: recordUse required');
  if (typeof recordClientSeen !== 'function') throw new Error('mtls: recordClientSeen required');
  if (typeof audit !== 'function') throw new Error('mtls: audit required');

  // config may be a getter (so we read it lazily on each request) or a static object.
  // The original server.js reads CONFIG at module-load time (line 3050) but CONFIG is
  // a `let` that is assigned later by loadConfig(). To handle both shapes, accept
  // either an object or a function returning an object.
  const getConfig = typeof config === 'function'
    ? config
    : () => config;
  // Validate lazily on first request (don't throw at construction if config is async).
  function effectiveConfig() {
    const c = getConfig();
    if (!c || typeof c !== 'object') return null;
    return c;
  }

  function getApiKeyIdentity(req) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    const secret = parseBearer(authHeader);
    if (!secret) return null;
    const config = effectiveConfig();
    if (!config) return null;
    const k = findApiKey(config.api_keys, secret);
    if (!k) return null;
    // v3.2: enforce ip_whitelist when set
    const socketIp = req.socket?.remoteAddress || '';
    const forwarded = req.headers['x-forwarded-for'];
    const remoteIp = trustedProxyConnection(req, config)
      && typeof forwarded === 'string'
      && !forwarded.includes(',')
      ? forwarded.trim()
      : socketIp;
    if (!isClientIpAllowed(k, remoteIp)) {
      audit({
        action: 'connect',
        status: 'denied',
        reason: 'api_key_ip_denied',
        cn: k.client,
        remote: remoteIp,
      });
      return null;
    }
    const owner = config.clients[k.client];
    if (!owner) return null;
    if (!rateLimitApiKey(k)) {
      return { apiKey: k, client: owner, clientName: k.client, via: 'api_key', rate_limited: true };
    }
    recordUse(k);
    return { apiKey: k, client: owner, clientName: k.client, via: 'api_key' };
  }

  /**
   * Resolve identity from a request. Returns null if no valid auth source.
   * Synchronous (matches inline behavior in server.js).
   * @param {import('node:http').IncomingMessage} req
   * @returns {null | {
   *   cn: string, fp: string, client: object, clientName: string,
   *   certSubject: object, via: 'api_key'|'session'|'mtls-header'|'mtls',
   *   apiKey?: object,
   * }}
   */
  function getIdentity(req) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    const bearerSupplied = typeof authHeader === 'string' && authHeader.trim() !== '';
    const apiKeyCtx = getApiKeyIdentity(req);
    if (bearerSupplied && !apiKeyCtx) return null;
    if (apiKeyCtx?.rate_limited) {
      audit({ action: 'connect', status: 'denied', reason: 'api_key_rate_limit', cn: apiKeyCtx.clientName });
      return null;
    }

    let primary = null;
    // 1a. nginx-forwarded mTLS. A proxy marker on any other connection is a
    // hard failure; it is never treated as ordinary caller metadata.
    const remote = req.socket?.remoteAddress || '';
    const fromLocalProxy = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
    const proxyHeaderPresent = req.headers['x-ssl-client-verify'] !== undefined;
    if (proxyHeaderPresent) {
      const config = effectiveConfig();
      if (!fromLocalProxy || !config || !trustedProxyConnection(req, config)) {
        audit({ action: 'connect', status: 'denied', reason: 'untrusted_proxy_identity', remote });
        return null;
      }
      const verify = String(req.headers['x-ssl-client-verify'] || '');
      const escaped = req.headers['x-ssl-client-cert'];
      if (verify === 'SUCCESS') {
        if (!escaped) return null;
        try {
          const pem = decodeURIComponent(String(escaped));
          const X509 = requireNodeCrypto?.X509Certificate || X509Certificate;
          const x509 = new X509(pem);
          const fp = x509.fingerprint256;
          const cnMatch = /(?:^|\n)CN=([^\n]+)/.exec(x509.subject || '');
          const cn = cnMatch ? cnMatch[1] : (x509.subject || '');
          if (!fp) return null;
          const matched = matchClientByFingerprint(config.clients, fp);
          if (!matched) return null;
          recordClientSeen(matched.name);
          primary = { cn: cn || matched.name, fp, client: matched.cfg, clientName: matched.name, certSubject: { CN: cn || matched.name }, via: 'mtls-header' };
        } catch {
          return null;
        }
      } else if (verify !== 'NONE') {
        return null;
      }
    }

    // 1b. Direct mTLS is never inferred through a marked reverse-proxy hop.
    if (!proxyHeaderPresent && req.socket?.authorized === true) {
      let cert = null;
      if (typeof req.socket.getPeerCertificate === 'function') {
        try { cert = req.socket.getPeerCertificate(true); } catch { cert = null; }
      }
      if (cert?.subject && cert.subject.CN && cert.fingerprint256) {
        const config = effectiveConfig();
        if (!config) return null;
        const matched = matchClientByFingerprint(config.clients, cert.fingerprint256);
        if (matched) {
          recordClientSeen(matched.name);
          primary = {
            cn: cert.subject.CN, fp: cert.fingerprint256, client: matched.cfg,
            clientName: matched.name, certSubject: cert.subject, via: 'mtls',
          };
        }
      }
    }

    // 2. A session is considered only when no certificate identity exists.
    if (!primary) {
      const session = getSession(req);
      if (session) {
        const config = effectiveConfig();
        const sessionClientName = session.clientName;
        const currentClient = config?.clients?.[sessionClientName];
        // Sessions are short-lived, but their embedded client snapshot must
        // never outlive a client revoke or role/policy reload. Rebind to the
        // current config on every request and fail closed if the client is
        // gone. Certificate-backed sessions also remain tied to the current
        // certificate fingerprint after a rotation.
        if (!currentClient || typeof sessionClientName !== 'string' || sessionClientName.length === 0) {
          audit({ action: 'connect', status: 'denied', reason: 'session_client_unavailable' });
          return null;
        }
        const certBound = typeof session.cn === 'string'
          && (session.cn === sessionClientName || session.cn.endsWith('@mtls'));
        if (certBound && session.fp && currentClient.cert_fingerprint_sha256
          && String(session.fp).toUpperCase() !== String(currentClient.cert_fingerprint_sha256).toUpperCase()) {
          audit({ action: 'connect', status: 'denied', reason: 'session_certificate_revoked', client: sessionClientName });
          return null;
        }
        primary = {
          cn: session.cn,
          fp: session.fp,
          client: currentClient,
          clientName: sessionClientName,
          certSubject: session.cert?.subject || { CN: session.cn },
          via: 'session',
          authFactors: Array.isArray(session.authFactors) ? [...session.authFactors] : [],
        };
      }
    }

    // A supplied API key narrows an existing identity and must belong to the
    // same subject. It cannot replace a certificate or session identity.
    if (primary && apiKeyCtx) {
      if (primary.clientName !== apiKeyCtx.clientName) {
        audit({ action: 'connect', status: 'denied', reason: 'identity_binding_mismatch', cn: primary.clientName });
        return null;
      }
      return { ...primary, apiKey: apiKeyCtx.apiKey };
    }
    if (primary) return primary;
    if (!apiKeyCtx) return null;
    return {
      cn: `apikey:${apiKeyCtx.apiKey.id}`,
      fp: apiKeyCtx.apiKey.id,
      client: apiKeyCtx.client,
      clientName: apiKeyCtx.clientName,
      certSubject: { CN: `apikey:${apiKeyCtx.apiKey.id}`, O: 'api_key' },
      via: 'api_key',
      apiKey: apiKeyCtx.apiKey,
    };
  }

  return { getIdentity, getApiKeyIdentity };
}

function trustedProxyConnection(req, config) {
  const remote = req.socket?.remoteAddress || '';
  const loopback = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
  if (!loopback || req.socket?.authorized !== true || typeof req.socket.getPeerCertificate !== 'function') return false;
  let certificate;
  try { certificate = req.socket.getPeerCertificate(true); } catch { return false; }
  const fingerprint = String(certificate?.fingerprint256 || '').toUpperCase();
  return fingerprint !== '' && (config.trusted_proxy_fingerprints || [])
    .some((value) => String(value).toUpperCase() === fingerprint);
}

function matchClientByFingerprint(clients, fp) {
  if (!clients) return null;
  const fpU = fp.toUpperCase();
  for (const [name, c] of Object.entries(clients)) {
    if (c.cert_fingerprint_sha256 && c.cert_fingerprint_sha256.toUpperCase() === fpU) {
      return { name, cfg: c };
    }
  }
  return null;
}
