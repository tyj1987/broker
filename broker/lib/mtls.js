// broker/lib/mtls.js — V4.1.1 extraction of identity resolution.
//
// Three auth sources, in priority order:
//   1. API Key Bearer  (browser / web AI client; no mTLS)
//   2. Session cookie  (dashboard login)
//   3. mTLS client cert (CLI / scripts / direct TLS) — two flavors:
//        3a. nginx forward via X-SSL-Client-Verify (when request comes via loopback)
//        3b. direct peer-cert via Node TLS API
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

  if (!config || typeof config !== 'object') throw new Error('mtls: config required');
  if (typeof getSession !== 'function') throw new Error('mtls: getSession required');
  if (typeof parseBearer !== 'function') throw new Error('mtls: parseBearer required');
  if (typeof findApiKey !== 'function') throw new Error('mtls: findApiKey required');
  if (typeof isClientIpAllowed !== 'function') throw new Error('mtls: isClientIpAllowed required');
  if (typeof rateLimitApiKey !== 'function') throw new Error('mtls: rateLimitApiKey required');
  if (typeof recordUse !== 'function') throw new Error('mtls: recordUse required');
  if (typeof recordClientSeen !== 'function') throw new Error('mtls: recordClientSeen required');
  if (typeof audit !== 'function') throw new Error('mtls: audit required');

  function getApiKeyIdentity(req) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    const secret = parseBearer(authHeader);
    if (!secret) return null;
    const k = findApiKey(config.api_keys, secret);
    if (!k) return null;
    // v3.2: enforce ip_whitelist when set
    const remoteIp = req.socket?.remoteAddress
      || req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim()
      || '';
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
    // 0. API Key Bearer (priority over session because browser may set both)
    const apiKeyCtx = getApiKeyIdentity(req);
    if (apiKeyCtx) {
      if (apiKeyCtx.rate_limited) {
        audit({ action: 'connect', status: 'denied', reason: 'api_key_rate_limit', cn: apiKeyCtx.clientName });
        return null;
      }
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
    // 1. session token
    const session = getSession(req);
    if (session) {
      return {
        cn: session.cn,
        fp: session.fp,
        client: session.client,
        clientName: session.clientName,
        certSubject: session.cert?.subject || { CN: session.cn },
        via: 'session',
      };
    }
    // 2a. nginx-forwarded mTLS (X-SSL-Client-Verify header from loopback)
    const remote = req.socket?.remoteAddress || '';
    const fromLocalProxy = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
    if (fromLocalProxy && req.headers['x-ssl-client-verify'] !== undefined) {
      const verify = String(req.headers['x-ssl-client-verify'] || '');
      const escaped = req.headers['x-ssl-client-cert'];
      if (verify !== 'SUCCESS' || !escaped) return null;
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
        return { cn: cn || matched.name, fp, client: matched.cfg, clientName: matched.name, certSubject: { CN: cn || matched.name }, via: 'mtls-header' };
      } catch (e) {
        return null;
      }
    }
    // 2b. Direct mTLS (peer-cert)
    let cert = null;
    if (typeof req.socket.getPeerCertificate === 'function') {
      try { cert = req.socket.getPeerCertificate(true); } catch { cert = null; }
    }
    if (!cert || !cert.subject) return null;
    const cn = cert.subject.CN;
    const fp = cert.fingerprint256;
    if (!cn || !fp) return null;
    const matched = matchClientByFingerprint(config.clients, fp);
    if (!matched) return null;
    recordClientSeen(matched.name);
    return {
      cn, fp, client: matched.cfg, clientName: matched.name,
      certSubject: cert.subject,
      via: 'mtls',
    };
  }

  return { getIdentity, getApiKeyIdentity };
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
