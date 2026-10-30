// Ephemeral TOTP enrollment state. Plaintext recovery codes are deliberately
// never stored: they are returned once by the setup response and only hashes
// remain in memory until activation.

export const TOTP_SETUP_TTL_MS = 10 * 60 * 1000;

export function createPendingTotp(secret, recoveryHashes, opts = {}) {
  if (typeof secret !== 'string' || !secret) throw new TypeError('TOTP secret is required');
  if (!Array.isArray(recoveryHashes) || recoveryHashes.length === 0) {
    throw new TypeError('Recovery-code hashes are required');
  }
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const ttlMs = Number.isFinite(opts.ttlMs) && opts.ttlMs > 0 ? opts.ttlMs : TOTP_SETUP_TTL_MS;
  return {
    secret,
    recovery_hashes: [...recoveryHashes],
    setup_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttlMs).toISOString(),
  };
}

export function isPendingTotpExpired(pending, opts = {}) {
  if (!pending || typeof pending !== 'object') return true;
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const ttlMs = Number.isFinite(opts.ttlMs) && opts.ttlMs > 0 ? opts.ttlMs : TOTP_SETUP_TTL_MS;

  const explicitExpiry = Date.parse(pending.expires_at || '');
  if (Number.isFinite(explicitExpiry)) return now >= explicitExpiry;

  // Backward-compatible fallback for an enrollment started before expires_at
  // was introduced. Invalid or missing timestamps fail closed.
  const setupAt = Date.parse(pending.setup_at || '');
  return !Number.isFinite(setupAt) || now >= setupAt + ttlMs;
}
