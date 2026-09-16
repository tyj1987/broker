import { createHash, createPublicKey, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isAbsolute, normalize } from 'node:path';
import { parseDocument } from 'yaml';
import { createAuditAnchorRecoveryVerifier } from './audit-anchor-recovery.js';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const CONFIG_KEYS = ['version', 'purpose', 'stream_id', 'audit_directory', 'trusted_keys',
  'revoked_key_ids', 'store_timeout_ms', 'deadline_ms', 'page_size', 'max_anchors'];
const PIN_KEYS = ['key_id', 'public_key_spki_der_base64', 'public_key_sha256'];
const CHECKPOINT_KEYS = ['version', 'purpose', 'stream_id', 'sequence', 'payload_digest',
  'issued_at_ms', 'expires_at_ms'];
const configs = new WeakMap();
const checkpoints = new WeakSet();
const FAILURE_CODES = new Set(['recovery_config_invalid', 'recovery_checkpoint_invalid',
  'recovery_checkpoint_expired', 'recovery_checkpoint_mismatch', 'recovery_check_aborted',
  'recovery_check_timeout', 'recovery_check_failed']);

export class AuditRecoveryCheckError extends Error {
  constructor(code) {
    super('Audit recovery check failed');
    this.name = 'AuditRecoveryCheckError';
    this.code = FAILURE_CODES.has(code) ? code : 'recovery_check_failed';
  }
}
const fail = (code) => { throw new AuditRecoveryCheckError(code); };
const integer = (n, min, max) => Number.isSafeInteger(n) && n >= min && n <= max;
const id = (s) => typeof s === 'string' && ID.test(s);
const digest = (s) => typeof s === 'string' && DIGEST.test(s) && s !== '0'.repeat(64);
function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function parseJSON(bytes, maxBytes, code) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > maxBytes) fail(code);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const doc = parseDocument(text, { schema: 'json', strict: true, uniqueKeys: true });
    if (doc.errors.length || doc.warnings.length) fail(code);
    return JSON.parse(text);
  } catch { fail(code); }
}

/** Public-key pins only. No credentials, provider endpoints or private keys. */
export function parseAuditRecoveryConfig(bytes) {
  const code = 'recovery_config_invalid';
  const value = parseJSON(bytes, 32 * 1024, code);
  if (!exact(value, CONFIG_KEYS) || value.version !== 1
    || value.purpose !== 'secret-broker.audit-recovery-check' || !id(value.stream_id)
    || typeof value.audit_directory !== 'string' || value.audit_directory.length > 4096
    || /[\x00-\x1f\x7f]/.test(value.audit_directory)
    || !isAbsolute(value.audit_directory) || normalize(value.audit_directory) !== value.audit_directory
    || !Array.isArray(value.trusted_keys) || !integer(value.trusted_keys.length, 1, 8)
    || !Array.isArray(value.revoked_key_ids) || value.revoked_key_ids.length > 8
    || !integer(value.deadline_ms, 100, 60_000)
    || !integer(value.store_timeout_ms, 100, value.deadline_ms)
    || !integer(value.page_size, 1, 32) || !integer(value.max_anchors, 1, 1_000_000)) fail(code);
  const keys = new Map();
  for (const entry of value.trusted_keys) {
    if (!exact(entry, PIN_KEYS) || !id(entry.key_id) || keys.has(entry.key_id)
      || typeof entry.public_key_spki_der_base64 !== 'string'
      || !integer(entry.public_key_spki_der_base64.length, 1, 1024)
      || !digest(entry.public_key_sha256)) fail(code);
    try {
      const der = Buffer.from(entry.public_key_spki_der_base64, 'base64');
      if (!integer(der.length, 1, 512) || der.toString('base64') !== entry.public_key_spki_der_base64
        || createHash('sha256').update(der).digest('hex') !== entry.public_key_sha256) fail(code);
      const key = createPublicKey({ key: der, type: 'spki', format: 'der' });
      if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
        || !key.export({ type: 'spki', format: 'der' }).equals(der)) fail(code);
      keys.set(entry.key_id, key);
    } catch { fail(code); }
  }
  const revoked = new Set();
  for (const key of value.revoked_key_ids) {
    if (!id(key) || revoked.has(key)) fail(code);
    revoked.add(key);
  }
  const config = Object.freeze({ streamId: value.stream_id, auditDirectory: value.audit_directory,
    storeTimeoutMs: value.store_timeout_ms, deadlineMs: value.deadline_ms,
    pageSize: value.page_size, maxAnchors: value.max_anchors });
  configs.set(config, { keys, revoked });
  return config;
}

/**
 * This is an operator-supplied trust input, NOT a receipt obtained from the
 * store being verified. File protection and independent acquisition are both
 * required deployment controls; parsing cannot establish their provenance.
 */
export function parseAuditRecoveryCheckpoint(bytes) {
  const code = 'recovery_checkpoint_invalid';
  const value = parseJSON(bytes, 4096, code);
  if (!exact(value, CHECKPOINT_KEYS) || value.version !== 1
    || value.purpose !== 'secret-broker.audit-recovery-checkpoint' || !id(value.stream_id)
    || !integer(value.sequence, 1, 1_000_000) || !digest(value.payload_digest)
    || !integer(value.issued_at_ms, 1, 8.64e15) || !integer(value.expires_at_ms, 1, 8.64e15)
    || value.expires_at_ms <= value.issued_at_ms
    || value.expires_at_ms - value.issued_at_ms > 3_600_000) fail(code);
  const checkpoint = Object.freeze(value);
  checkpoints.add(checkpoint);
  return checkpoint;
}

function checkpointTime(config, checkpoint, now, earliest = 0) {
  if (!configs.has(config) || !checkpoints.has(checkpoint) || typeof now !== 'function'
    || checkpoint.stream_id !== config.streamId || checkpoint.sequence > config.maxAnchors) {
    fail('recovery_checkpoint_invalid');
  }
  let time;
  try { time = now(); } catch { fail('recovery_checkpoint_invalid'); }
  if (!integer(time, 1, 8.64e15) || time < earliest || time < checkpoint.issued_at_ms) {
    fail('recovery_checkpoint_invalid');
  }
  if (time >= checkpoint.expires_at_ms) fail('recovery_checkpoint_expired');
  return time;
}

// Enforce cancellation even if an injected backend fails to settle. Every
// backend also receives the signal; a rejected late result is always observed.
function abortable(operation, signal, abortCode) {
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new AuditRecoveryCheckError(abortCode()));
    if (signal.aborted) { onAbort(); return; }
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve().then(() => {
      if (signal.aborted) fail(abortCode());
      return operation();
    }).then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

export async function verifyAuditRecoveryCheckpoint({ config, checkpoint, store, loadChainProof,
  now = () => Date.now(), signal } = {}) {
  const started = checkpointTime(config, checkpoint, now);
  if (!store || typeof store.readHead !== 'function' || typeof store.readPage !== 'function'
    || typeof loadChainProof !== 'function' || (signal !== undefined && !(signal instanceof AbortSignal))) {
    fail('recovery_check_failed');
  }
  if (signal?.aborted) fail('recovery_check_aborted');
  const timeout = new AbortController();
  const combined = signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal;
  const deadlineAt = performance.now() + config.deadlineMs;
  const timer = setTimeout(() => timeout.abort(), config.deadlineMs);
  const abortCode = () => signal?.aborted ? 'recovery_check_aborted' : 'recovery_check_timeout';
  const check = () => {
    if (combined.aborted) fail(abortCode());
    if (performance.now() >= deadlineAt) fail('recovery_check_timeout');
    checkpointTime(config, checkpoint, now, started);
  };
  try {
    const head = structuredClone(await abortable(
      () => store.readHead({ streamId: config.streamId, signal: combined }), combined, abortCode));
    check();
    if (!exact(head, ['current', 'previous']) || head.current?.payload?.stream_id !== config.streamId
      || head.current?.payload?.sequence !== checkpoint.sequence
      || head.current?.payload_digest !== checkpoint.payload_digest) fail('recovery_checkpoint_mismatch');
    const { keys, revoked } = configs.get(config);
    const verifier = createAuditAnchorRecoveryVerifier({
      streamId: config.streamId,
      store: {
        readHead: async () => structuredClone(head),
        readPage: async (request) => {
          check();
          const page = await abortable(() => store.readPage(request), combined, abortCode);
          check();
          return structuredClone(page);
        },
      },
      loadChainProof: async (count, options) => {
        check();
        const proof = await abortable(() => loadChainProof(count, options), combined, abortCode);
        check();
        return structuredClone(proof);
      },
      trustedKeyIds: new Set(keys.keys()), revokedKeyIds: new Set(revoked),
      verifySignature: ({ algorithm, keyId, signingInput, signature }) => {
        if (algorithm !== 'ecdsa-p256-sha256' || !keys.has(keyId)) return false;
        return verify('sha256', signingInput, keys.get(keyId), signature);
      },
      pageSize: config.pageSize, maxAnchors: config.maxAnchors,
    });
    const result = await abortable(() => verifier.verifyRecovery({ signal: combined }), combined, abortCode);
    check();
    if (result.status !== 'verified' || result.sequence !== checkpoint.sequence
      || result.payload_digest !== checkpoint.payload_digest) fail('recovery_checkpoint_mismatch');
    return Object.freeze({ status: 'checkpoint_verified', anchors_verified: result.count,
      sequence: result.sequence, checkpoint_match: true });
  } catch (error) {
    check();
    if (error instanceof AuditRecoveryCheckError) throw error;
    fail('recovery_check_failed');
  } finally { clearTimeout(timer); }
}

export function safeAuditRecoveryCheckCode(error) {
  return error instanceof AuditRecoveryCheckError && FAILURE_CODES.has(error.code)
    ? error.code : 'recovery_check_failed';
}

export const AUDIT_RECOVERY_CHECK_LIMITS = Object.freeze({ config_bytes: 32 * 1024,
  checkpoint_bytes: 4096, checkpoint_validity_ms: 3_600_000, maximum_deadline_ms: 60_000,
  accepts_credentials: false, accepts_provider_endpoints: false, grants_production_readiness: false });
