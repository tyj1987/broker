export function isLoopbackAddress(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

export function isTrustedProxySocket(socket, fingerprints = []) {
  if (!socket || socket.authorized !== true || !isLoopbackAddress(socket.remoteAddress || '')) return false;
  const peer = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate(true) : null;
  const peerFingerprint = String(peer?.fingerprint256 || '').toUpperCase();
  if (!peerFingerprint) return false;
  const allowed = new Set((fingerprints || []).map((value) => String(value).toUpperCase()));
  return allowed.has(peerFingerprint);
}

export function resolveSourceIp(req, trustedProxy) {
  if (trustedProxy) {
    const forwarded = req?.headers?.['x-forwarded-for'];
    const first = Array.isArray(forwarded) ? forwarded[0] : String(forwarded || '').split(',')[0];
    if (first?.trim()) return first.trim();
  }
  return req?.socket?.remoteAddress || '';
}
