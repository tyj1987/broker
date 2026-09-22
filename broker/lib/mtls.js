// Explicit identity order: delegated API key, session, forwarded mTLS, direct mTLS.
// A transport proxy is trusted only by an exact address AND certificate binding.
import { X509Certificate } from 'node:crypto';
import {
  authorizedPeerCertificate,
  normalizeFingerprint,
  isTrustedForwardingPeer,
  isForwardingCertificate,
  hasForwardedCertificateHeaders,
  clientIpFromRequest,
} from './trusted-proxy.js';

function matchClientByFingerprint(clients, value) {
  const fingerprint = normalizeFingerprint(value);
  if (!fingerprint || !clients) return null;
  for (const [name, cfg] of Object.entries(clients)) {
    if (normalizeFingerprint(cfg?.cert_fingerprint_sha256) === fingerprint) return { name, cfg };
  }
  return null;
}

function forwardingBoundaryAllowed(req, config) {
  const forwarded = hasForwardedCertificateHeaders(req);
  const proxy = isTrustedForwardingPeer(req, config);
  if (forwarded && !proxy) return false;
  if (isForwardingCertificate(req, config) && !proxy) return false;
  if (!proxy) return true;
  // Missing forwarding metadata must not turn a proxy certificate into a user.
  const verified = req.headers?.['x-ssl-client-verify'];
  const cert = req.headers?.['x-ssl-client-cert'];
  return (
    (verified === 'NONE' && !cert) || (verified === 'SUCCESS' && typeof cert === 'string' && !!cert)
  );
}

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
  for (const [name, fn] of Object.entries({
    getSession,
    parseBearer,
    findApiKey,
    isClientIpAllowed,
    rateLimitApiKey,
    recordUse,
    recordClientSeen,
    audit,
  })) {
    if (typeof fn !== 'function') throw new Error(`mtls: ${name} required`);
  }
  const getConfig = typeof config === 'function' ? config : () => config;

  function getApiKeyIdentity(req) {
    const cfg = getConfig();
    if (!cfg || !forwardingBoundaryAllowed(req, cfg)) return null;
    const secret = parseBearer(req.headers?.authorization || req.headers?.Authorization);
    if (!secret) return null;
    const key = findApiKey(cfg.api_keys, secret);
    if (!key) return null;
    const remoteIp = clientIpFromRequest(req, cfg);
    if (!isClientIpAllowed(key, remoteIp)) {
      audit({
        action: 'connect',
        status: 'denied',
        reason: 'api_key_ip_denied',
        cn: key.client,
        remote: remoteIp,
      });
      return null;
    }
    const owner = cfg.clients?.[key.client];
    if (!owner) return null;
    const result = { apiKey: key, client: owner, clientName: key.client, via: 'api_key' };
    if (!rateLimitApiKey(key)) return { ...result, rate_limited: true };
    recordUse(key);
    return result;
  }

  function getIdentity(req) {
    const cfg = getConfig();
    if (!cfg || !forwardingBoundaryAllowed(req, cfg)) return null;
    const api = getApiKeyIdentity(req);
    if (api) {
      if (api.rate_limited) {
        audit({
          action: 'connect',
          status: 'denied',
          reason: 'api_key_rate_limit',
          cn: api.clientName,
        });
        return null;
      }
      return {
        cn: `apikey:${api.apiKey.id}`,
        fp: api.apiKey.id,
        client: { ...api.client, role: 'api_key' },
        ownerRole: api.client.role,
        clientName: api.clientName,
        certSubject: { CN: `apikey:${api.apiKey.id}`, O: 'api_key' },
        via: 'api_key',
        apiKey: api.apiKey,
      };
    }
    // Explicit but rejected credentials cannot silently fall back to a more
    // privileged cookie or client certificate.
    if (req.headers?.authorization || req.headers?.Authorization) return null;
    const session = getSession(req);
    if (session) {
      const live = cfg.clients?.[session.clientName];
      if (!live) return null;
      if (
        session.fp &&
        normalizeFingerprint(session.fp) !== normalizeFingerprint(live.cert_fingerprint_sha256)
      )
        return null;
      return {
        cn: session.cn,
        fp: session.fp,
        client: live,
        clientName: session.clientName,
        certSubject: session.cert?.subject || { CN: session.cn },
        via: 'session',
      };
    }
    if (req.headers?.['x-auth-token']) return null;

    if (isTrustedForwardingPeer(req, cfg)) {
      if (req.headers?.['x-ssl-client-verify'] !== 'SUCCESS') return null;
      try {
        const X509 = requireNodeCrypto?.X509Certificate || X509Certificate;
        const x509 = new X509(decodeURIComponent(req.headers['x-ssl-client-cert']));
        const now = Date.now();
        if (!(Date.parse(x509.validFrom) <= now && now < Date.parse(x509.validTo))) return null;
        const matched = matchClientByFingerprint(cfg.clients, x509.fingerprint256);
        if (!matched) return null;
        const cn = /(?:^|\n)CN=([^\n]+)/.exec(x509.subject || '')?.[1] || matched.name;
        recordClientSeen(matched.name);
        return {
          cn,
          fp: x509.fingerprint256,
          client: matched.cfg,
          clientName: matched.name,
          certSubject: { CN: cn },
          via: 'mtls-header',
        };
      } catch {
        return null;
      }
    }
    const cert = authorizedPeerCertificate(req);
    if (!cert?.subject?.CN || isForwardingCertificate(req, cfg)) return null;
    const matched = matchClientByFingerprint(cfg.clients, cert.fingerprint256);
    if (!matched) return null;
    recordClientSeen(matched.name);
    return {
      cn: cert.subject.CN,
      fp: cert.fingerprint256,
      client: matched.cfg,
      clientName: matched.name,
      certSubject: cert.subject,
      via: 'mtls',
    };
  }
  return { getIdentity, getApiKeyIdentity };
}
