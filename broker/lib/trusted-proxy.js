// A transport proxy is a separate identity, never a business client.
// Configuration: trusted_proxies: [{ addresses: ['172.30.0.2'],
//   cert_fingerprint_sha256: '<SHA-256 fingerprint>' }]. No wildcard/CIDR trust.
import { isIP } from 'node:net';

export function normalizeFingerprint(value) {
  if (typeof value !== 'string') return null;
  const hex = value.replaceAll(':', '').toUpperCase();
  return /^[A-F0-9]{64}$/.test(hex) ? hex : null;
}

export function normalizeIp(value) {
  if (typeof value !== 'string') return null;
  let ip = value.trim().toLowerCase();
  if (ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4) ip = ip.slice(7);
  if (!isIP(ip) || ip.includes('%')) return null;
  if (isIP(ip) === 6) {
    try {
      return new URL(`http://[${ip}]/`).hostname.slice(1, -1);
    } catch {
      return null;
    }
  }
  return ip;
}

export function authorizedPeerCertificate(req) {
  if (req?.socket?.authorized !== true) return null;
  try {
    const cert = req.socket.getPeerCertificate?.(true);
    return cert?.subject && normalizeFingerprint(cert.fingerprint256) ? cert : null;
  } catch {
    return null;
  }
}

function matchingProxy(req, config) {
  const peer = authorizedPeerCertificate(req);
  const fingerprint = normalizeFingerprint(peer?.fingerprint256);
  if (!fingerprint || !Array.isArray(config?.trusted_proxies)) return null;
  return (
    config.trusted_proxies.find(
      (p) => p && normalizeFingerprint(p.cert_fingerprint_sha256) === fingerprint,
    ) || null
  );
}

export function isForwardingCertificate(req, config) {
  return !!matchingProxy(req, config);
}

export function isTrustedForwardingPeer(req, config) {
  const proxy = matchingProxy(req, config);
  const address = normalizeIp(req?.socket?.remoteAddress);
  return !!(
    address &&
    Array.isArray(proxy?.addresses) &&
    proxy.addresses.some((ip) => normalizeIp(ip) === address)
  );
}

export function hasForwardedCertificateHeaders(req) {
  return ['x-ssl-client-verify', 'x-ssl-client-cert', 'x-ssl-client-dn'].some(
    (name) => req?.headers?.[name] !== undefined,
  );
}

export function clientIpFromRequest(req, config) {
  const socketIp = normalizeIp(req?.socket?.remoteAddress) || '';
  if (!isTrustedForwardingPeer(req, config)) return socketIp;
  // Nginx must overwrite X-Real-IP. Do not trust the leftmost X-Forwarded-For:
  // that value may have been supplied by the external caller.
  return normalizeIp(req?.headers?.['x-real-ip']) || socketIp;
}
