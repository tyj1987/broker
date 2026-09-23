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
 * @param {{sourceIp?: string, fingerprintSha256?: string, clientName?: string}} [deps.forwardedMtls]
 *        Optional Cloudflare Tunnel mTLS bridge. All three fields are required when enabled.
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
    forwardedMtls,
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

  const forwardedMtlsConfig = normalizeForwardedMtlsConfig(forwardedMtls);

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
   *   certSubject: object, via: 'api_key'|'session'|'mtls-header'|'mtls-forwarded-rfc9440'|'mtls',
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

    // 1a. Cloudflare-managed mTLS forwarded through the existing local nginx
    // proxy. nginx overwrites X-Forwarded-For with the immediate peer address,
    // and its workload certificate must already be trusted by Broker. This
    // path is therefore enabled only for one explicitly configured Tunnel
    // connector address and one exact Cloudflare certificate fingerprint.
    const config = effectiveConfig();
    const fromForwardedMtlsSource = forwardedMtlsConfig
      && config
      && trustedProxyConnection(req, config)
      && exactForwardedSource(req, forwardedMtlsConfig.sourceIp);
    if (fromForwardedMtlsSource) {
      const nginxVerify = String(req.headers['x-ssl-client-verify'] || '');
      if (nginxVerify === 'NONE') {
        const resolved = resolveForwardedMtlsCertificate(
          req.headers['client-cert'],
          config,
          forwardedMtlsConfig,
          requireNodeCrypto,
        );
        if (!resolved.ok) {
          audit({ action: 'connect', status: 'denied', reason: resolved.reason, remote: forwardedMtlsConfig.sourceIp });
          return null;
        }
        recordClientSeen(resolved.identity.clientName);
        primary = resolved.identity;
      } else if (nginxVerify !== 'SUCCESS') {
        audit({ action: 'connect', status: 'denied', reason: 'forwarded_mtls_proxy_verify_invalid', remote: forwardedMtlsConfig.sourceIp });
        return null;
      }
    }

    // 1b. nginx-forwarded mTLS. A proxy marker on any other connection is a
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

    // 1c. Direct mTLS is never inferred through a marked reverse-proxy hop.
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
        // A session may outlive a reload, deletion or role downgrade. Never
        // authorize using the login-time client object after policy changes.
        const liveClient = effectiveConfig()?.clients?.[session.clientName];
        if (!liveClient) return null;
        primary = {
          cn: session.cn,
          fp: session.fp,
          client: liveClient,
          clientName: session.clientName,
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

function normalizeForwardedMtlsConfig(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('mtls: forwardedMtls must be an object');
  }
  const sourceIp = String(value.sourceIp || '').trim();
  const fingerprintSha256 = String(value.fingerprintSha256 || '').replace(/:/g, '').toUpperCase();
  const clientName = String(value.clientName || '').trim();
  if (!sourceIp && !fingerprintSha256 && !clientName) return null;
  if (!sourceIp || !fingerprintSha256 || !clientName) {
    throw new Error('mtls: forwardedMtls requires sourceIp, fingerprintSha256, and clientName');
  }
  if (sourceIp.length > 128 || /[\s,\r\n\0]/.test(sourceIp)) {
    throw new Error('mtls: forwardedMtls sourceIp is invalid');
  }
  if (!/^[0-9A-F]{64}$/.test(fingerprintSha256)) {
    throw new Error('mtls: forwardedMtls fingerprintSha256 must be 64 hex characters');
  }
  if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(clientName)) {
    throw new Error('mtls: forwardedMtls clientName is invalid');
  }
  return Object.freeze({ sourceIp, fingerprintSha256, clientName });
}

function exactForwardedSource(req, expected) {
  const forwarded = req.headers['x-forwarded-for'];
  return typeof forwarded === 'string'
    && !forwarded.includes(',')
    && forwarded.trim() === expected;
}

function normalizedFingerprint(value) {
  return String(value || '').replace(/:/g, '').toUpperCase();
}

function resolveForwardedMtlsCertificate(rawHeader, config, settings, requireNodeCrypto) {
  if (typeof rawHeader !== 'string' || rawHeader.length < 4 || rawHeader.length > 16 * 1024) {
    return { ok: false, reason: 'forwarded_mtls_certificate_missing' };
  }
  const match = /^:([A-Za-z0-9+/]+={0,2}):$/.exec(rawHeader);
  if (!match || match[1].length % 4 !== 0) {
    return { ok: false, reason: 'forwarded_mtls_certificate_malformed' };
  }
  let der;
  try {
    der = Buffer.from(match[1], 'base64');
  } catch {
    return { ok: false, reason: 'forwarded_mtls_certificate_malformed' };
  }
  if (der.length === 0 || der.toString('base64') !== match[1]) {
    return { ok: false, reason: 'forwarded_mtls_certificate_malformed' };
  }
  try {
    const X509 = requireNodeCrypto?.X509Certificate || X509Certificate;
    const x509 = new X509(der);
    const fingerprint = normalizedFingerprint(x509.fingerprint256);
    if (fingerprint !== settings.fingerprintSha256) {
      return { ok: false, reason: 'forwarded_mtls_fingerprint_mismatch' };
    }
    const client = config.clients?.[settings.clientName];
    if (!client) {
      return { ok: false, reason: 'forwarded_mtls_client_missing' };
    }
    const cnMatch = /(?:^|\n)CN=([^\n]+)/.exec(x509.subject || '');
    const cn = cnMatch ? cnMatch[1] : settings.clientName;
    return {
      ok: true,
      identity: {
        cn,
        fp: x509.fingerprint256,
        client,
        clientName: settings.clientName,
        certSubject: { CN: cn },
        via: 'mtls-forwarded-rfc9440',
      },
    };
  } catch {
    return { ok: false, reason: 'forwarded_mtls_certificate_malformed' };
  }
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
