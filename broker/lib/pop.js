// Compatible with the deployed v1 PoP message, without production identity pins.
// v1 signs METHOD + request-target + timestamp, not body bytes or a server nonce.
// Replay state is process-local: restart/replica-wide replay resistance requires
// a separate shared durable store and is not claimed by this implementation.
import { createHash, verify as cryptoVerify, constants } from 'node:crypto';
import { STATIC_MAP } from '../routes/static.js';

export const POP_HEADER = 'x-broker-pop';
export const POP_SCHEME = 'v1';
export const POP_WINDOW_SECONDS = 300;
export const POP_READONLY_ALLOWLIST = Object.freeze(['GET /health', 'GET /api/v1/identity', 'GET /api/v1/services']);

export function buildCanonicalMessage({ method, pathAndQuery, ts }) {
  const verb = typeof method === 'string' ? method.toUpperCase() : '';
  if (!/^[A-Z]{1,32}$/.test(verb) || typeof pathAndQuery !== 'string'
      || !pathAndQuery.startsWith('/') || pathAndQuery.length > 16384 || /[\r\n\0#]/.test(pathAndQuery)
      || !Number.isSafeInteger(ts) || ts <= 0) throw new TypeError('Invalid PoP request binding');
  return `${POP_SCHEME}\n${verb}\n${pathAndQuery}\n${ts}`;
}

export function parsePoPHeader(value) {
  if (typeof value !== 'string' || value.length > 8192) return null;
  const match = /^v1:([1-9][0-9]{0,11}):([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) return null;
  const ts = Number(match[1]);
  const sig = Buffer.from(match[2], 'base64');
  if (!Number.isSafeInteger(ts) || sig.length === 0 || sig.toString('base64') !== match[2]) return null;
  return { ts, sig };
}

export function createReplayCache({ windowSeconds = POP_WINDOW_SECONDS, maxEntries = 5000,
  maxPerKey = 32, now = () => Math.floor(Date.now() / 1000) } = {}) {
  if (![windowSeconds, maxEntries, maxPerKey].every(v => Number.isSafeInteger(v) && v > 0)
      || typeof now !== 'function') throw new TypeError('Invalid PoP replay-cache configuration');
  const entries = new Map();
  let proofs = 0;
  function pruneAt(timestamp) {
    if (!Number.isFinite(timestamp)) return;
    for (const [key, entry] of entries) {
      if (timestamp > entry.expiresAt) { proofs -= entry.digests.size; entries.delete(key); }
    }
  }
  const identityKey = (fingerprint, ts) => `${String(fingerprint).replaceAll(':', '').toUpperCase()}:${ts}`;
  return {
    windowSeconds,
    check(fingerprint, ts, digest) {
      if (!Buffer.isBuffer(digest)) return false;
      return entries.get(identityKey(fingerprint, ts))?.digests.has(digest.toString('hex')) === true;
    },
    remember(fingerprint, ts, digest) {
      const timestamp = now();
      if (typeof fingerprint !== 'string' || !fingerprint || fingerprint.length > 256
          || !Number.isSafeInteger(ts) || ts <= 0 || !Number.isFinite(timestamp)
          || Math.abs(timestamp - ts) > windowSeconds || !Buffer.isBuffer(digest) || digest.length !== 32) return false;
      pruneAt(timestamp);
      const key = identityKey(fingerprint, ts);
      const entry = entries.get(key);
      const hash = digest.toString('hex');
      if (entry?.digests.has(hash) || proofs >= maxEntries || (entry?.digests.size || 0) >= maxPerKey) return false;
      const next = entry || { expiresAt: ts + windowSeconds, digests: new Set() };
      next.digests.add(hash);
      entries.set(key, next);
      proofs++;
      return true;
    },
    pruneAt,
    get size() { return entries.size; },
    get proofCount() { return proofs; },
    clear() { entries.clear(); proofs = 0; },
  };
}

export const defaultReplayCache = createReplayCache();

export function verifyPoP({ headerValue, publicKey, fingerprint, method, pathAndQuery,
  nowSeconds = Math.floor(Date.now() / 1000), cache = defaultReplayCache, windowSeconds = POP_WINDOW_SECONDS }) {
  try {
    const parsed = parsePoPHeader(headerValue);
    if (!parsed || !publicKey || !Number.isFinite(nowSeconds)
        || !Number.isSafeInteger(windowSeconds) || windowSeconds <= 0
        || !cache || windowSeconds > cache.windowSeconds || Math.abs(nowSeconds - parsed.ts) > windowSeconds) return false;
    const type = publicKey.asymmetricKeyType;
    if (!['rsa', 'rsa-pss', 'ec'].includes(type)) return false;
    const key = type === 'rsa-pss'
      ? { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
      : publicKey;
    const message = Buffer.from(buildCanonicalMessage({ method, pathAndQuery, ts: parsed.ts }));
    if (!cryptoVerify('sha256', message, key, parsed.sig)) return false;
    // Bind replay state to the signed message, not signature bytes: ECDSA and
    // randomized signatures may have more than one valid representation.
    const digest = createHash('sha256').update(message).digest();
    if (cache.check(fingerprint, parsed.ts, digest)) return false;
    return cache.remember(fingerprint, parsed.ts, digest) === true;
  } catch { return false; }
}

export function normalizeRequirePop(value) {
  if (value === undefined || value === null || value === '') return 'off';
  if (typeof value !== 'string') return 'invalid';
  const mode = value.trim().toLowerCase();
  return ['off', 'privileged', 'all'].includes(mode) ? mode : 'invalid';
}

export function isReadOnlyAllowlisted(method, pathname) {
  return method === 'GET' && (POP_READONLY_ALLOWLIST.includes(`GET ${pathname}`)
    || Object.hasOwn(STATIC_MAP, pathname));
}

export function enforcePop({ identity, method, pathname, requirePop }) {
  const mode = normalizeRequirePop(requirePop);
  if (mode === 'off' || !identity || identity.edgeForwarded !== true
      || !['mtls-header', 'mtls-forwarded-rfc9440'].includes(identity.via)) return null;
  if (mode === 'invalid') return { mode, reason: 'pop_policy_invalid' };
  if (identity.popVerified === true || (mode === 'privileged' && isReadOnlyAllowlisted(method, pathname))) return null;
  return { mode, reason: 'pop_required' };
}
