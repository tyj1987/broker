import { computeHash, GENESIS_HASH } from './audit-hash-chain.js';

const ANCHOR_VERSION = 1;
const ANCHOR_PURPOSE = 'secret-broker.audit-chain-head';
const SIGNATURE_CONTEXT = 'secret-broker.audit-anchor-signature.v2';
const HASH_RE = /^[a-f0-9]{64}$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{43,4096}$/;
const SIGNATURE_ALGORITHMS = new Set([
  'ed25519',
  'ecdsa-p256-sha256',
  'rsa-pss-sha256',
]);
const REQUEST_KEYS = new Set(['version', 'payload', 'payload_digest']);
const PAYLOAD_KEYS = new Set([
  'purpose',
  'version',
  'stream_id',
  'sequence',
  'captured_at',
  'chain_head',
  'event_count',
  'file_count',
  'previous_anchor_digest',
]);
const SIGNATURE_KEYS = new Set(['algorithm', 'key_id', 'value']);
const ENVELOPE_KEYS = new Set([...REQUEST_KEYS, 'signature']);

export class AuditAnchorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AuditAnchorError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditAnchorError(code, message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validSignatureValue(value) {
  if (typeof value !== 'string' || !SIGNATURE_RE.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length >= 32
    && decoded.length <= 3072
    && decoded.toString('base64url') === value;
}

function validateChainState(state) {
  if (
    !state ||
    typeof state !== 'object' ||
    Array.isArray(state) ||
    !Number.isSafeInteger(state.files) ||
    state.files < 0 ||
    !Number.isSafeInteger(state.count) ||
    state.count < 0 ||
    !HASH_RE.test(state.lastHash || '') ||
    (state.count === 0 && state.files !== 0) ||
    (state.count > 0 && state.files < 1) ||
    (state.count === 0 && state.lastHash !== GENESIS_HASH) ||
    (state.count > 0 && state.lastHash === GENESIS_HASH)
  ) {
    fail('invalid_chain_state', 'audit chain state is invalid');
  }
}

function validateChainProof(proof) {
  if (
    !proof ||
    typeof proof !== 'object' ||
    Array.isArray(proof) ||
    !Number.isSafeInteger(proof.files) ||
    proof.files < 0 ||
    !Number.isSafeInteger(proof.count) ||
    proof.count < 0 ||
    !HASH_RE.test(proof.lastHash || '') ||
    !Number.isSafeInteger(proof.anchoredEventCount) ||
    proof.anchoredEventCount < 0 ||
    proof.anchoredEventCount > proof.count ||
    !HASH_RE.test(proof.hashAtAnchor || '') ||
    !Number.isSafeInteger(proof.filesAtAnchor) ||
    proof.filesAtAnchor < 0 ||
    proof.filesAtAnchor > proof.files ||
    (proof.count === 0 && proof.lastHash !== GENESIS_HASH) ||
    (proof.count > 0 && proof.lastHash === GENESIS_HASH) ||
    (proof.anchoredEventCount === 0 &&
      (proof.hashAtAnchor !== GENESIS_HASH || proof.filesAtAnchor !== 0)) ||
    (proof.anchoredEventCount > 0 &&
      (proof.hashAtAnchor === GENESIS_HASH || proof.filesAtAnchor < 1))
  ) {
    fail('invalid_chain_state', 'audit chain proof is invalid');
  }
}

function validatePayload(payload) {
  if (
    !exactKeys(payload, PAYLOAD_KEYS) ||
    payload.purpose !== ANCHOR_PURPOSE ||
    payload.version !== ANCHOR_VERSION ||
    !ID_RE.test(payload.stream_id || '') ||
    !Number.isSafeInteger(payload.sequence) ||
    payload.sequence < 1 ||
    !validTimestamp(payload.captured_at) ||
    !HASH_RE.test(payload.chain_head || '') ||
    !Number.isSafeInteger(payload.event_count) ||
    payload.event_count < 0 ||
    !Number.isSafeInteger(payload.file_count) ||
    payload.file_count < 0 ||
    !HASH_RE.test(payload.previous_anchor_digest || '') ||
    (payload.event_count === 0 &&
      (payload.chain_head !== GENESIS_HASH || payload.file_count !== 0)) ||
    (payload.event_count > 0 &&
      (payload.chain_head === GENESIS_HASH || payload.file_count < 1)) ||
    (payload.sequence === 1 && payload.previous_anchor_digest !== GENESIS_HASH) ||
    (payload.sequence > 1 && payload.previous_anchor_digest === GENESIS_HASH)
  ) {
    fail('invalid_anchor', 'audit anchor payload is invalid');
  }
}

function validateRequest(request) {
  if (!exactKeys(request, REQUEST_KEYS) || request.version !== ANCHOR_VERSION) {
    fail('invalid_anchor', 'audit anchor signing request is invalid');
  }
  validatePayload(request.payload);
  const expected = computeHash(request.payload);
  if (request.payload_digest !== expected) {
    fail('anchor_digest_mismatch', 'audit anchor payload digest does not match');
  }
}

function validateSignature(signature) {
  if (
    !exactKeys(signature, SIGNATURE_KEYS) ||
    !SIGNATURE_ALGORITHMS.has(signature.algorithm) ||
    !ID_RE.test(signature.key_id || '') ||
    !validSignatureValue(signature.value)
  ) {
    fail('invalid_signature', 'audit anchor signature is invalid');
  }
}

function validateEnvelope(envelope) {
  if (!exactKeys(envelope, ENVELOPE_KEYS)) {
    fail('invalid_anchor', 'signed audit anchor envelope is invalid');
  }
  validateRequest({
    version: envelope.version,
    payload: envelope.payload,
    payload_digest: envelope.payload_digest,
  });
  validateSignature(envelope.signature);
}

export function createAuditAnchorRequest(
  chainState,
  {
    streamId,
    sequence,
    previousAnchorDigest = GENESIS_HASH,
    now = () => Date.now(),
  } = {},
) {
  validateChainState(chainState);
  if (typeof now !== 'function') fail('invalid_anchor', 'audit anchor clock is invalid');
  const capturedAtMs = now();
  if (!Number.isFinite(capturedAtMs) || Math.abs(capturedAtMs) > 8.64e15) {
    fail('invalid_anchor', 'audit anchor clock is invalid');
  }
  const payload = {
    purpose: ANCHOR_PURPOSE,
    version: ANCHOR_VERSION,
    stream_id: streamId,
    sequence,
    captured_at: new Date(capturedAtMs).toISOString(),
    chain_head: chainState.lastHash,
    event_count: chainState.count,
    file_count: chainState.files,
    previous_anchor_digest: previousAnchorDigest,
  };
  validatePayload(payload);
  return {
    version: ANCHOR_VERSION,
    payload,
    payload_digest: computeHash(payload),
  };
}

export function createAuditAnchorSigningInput(request, { algorithm, keyId } = {}) {
  validateRequest(request);
  if (!SIGNATURE_ALGORITHMS.has(algorithm) || !ID_RE.test(keyId || '')) {
    fail('invalid_signature', 'audit anchor signature metadata is invalid');
  }
  return Buffer.from(
    `${SIGNATURE_CONTEXT}\0${algorithm}\0${keyId}\0${request.payload.stream_id}`
      + `\0${request.payload.sequence}\0${request.payload.previous_anchor_digest}`
      + `\0${request.payload_digest}`,
    'utf8',
  );
}

export function attachAuditAnchorSignature(request, signature) {
  validateRequest(request);
  validateSignature(signature);
  return {
    version: request.version,
    payload: structuredClone(request.payload),
    payload_digest: request.payload_digest,
    signature: structuredClone(signature),
  };
}

function validatePreviousAnchor(envelope, previousEnvelope) {
  if (!previousEnvelope) {
    if (
      envelope.payload.sequence !== 1 ||
      envelope.payload.previous_anchor_digest !== GENESIS_HASH
    ) {
      fail('previous_anchor_required', 'previous signed audit anchor is required');
    }
    return;
  }
  validateEnvelope(previousEnvelope);
  if (envelope.payload.stream_id !== previousEnvelope.payload.stream_id) {
    fail('anchor_stream_mismatch', 'audit anchor stream does not match its predecessor');
  }
  if (envelope.payload.sequence !== previousEnvelope.payload.sequence + 1) {
    fail('anchor_sequence_mismatch', 'audit anchor sequence is not contiguous');
  }
  if (envelope.payload.previous_anchor_digest !== previousEnvelope.payload_digest) {
    fail('previous_anchor_mismatch', 'previous audit anchor digest does not match');
  }
  if (Date.parse(envelope.payload.captured_at) <= Date.parse(previousEnvelope.payload.captured_at)) {
    fail('anchor_clock_rollback', 'audit anchor timestamp did not advance');
  }
  if (envelope.payload.event_count < previousEnvelope.payload.event_count) {
    fail('anchor_count_rollback', 'audit event count moved backwards');
  }
}

export function verifyAuditAnchorEnvelope(
  envelope,
  {
    chainState = null,
    chainProof = null,
    previousEnvelope = null,
    trustedKeyIds,
    revokedKeyIds = new Set(),
    verifySignature,
  } = {},
) {
  validateEnvelope(envelope);
  if ((chainState === null) === (chainProof === null)) {
    fail('invalid_chain_state', 'exactly one audit chain verification input is required');
  }
  if (chainState !== null) validateChainState(chainState);
  else validateChainProof(chainProof);
  if (!(trustedKeyIds instanceof Set) || trustedKeyIds.size === 0) {
    fail('trust_unavailable', 'trusted audit anchor signing keys are unavailable');
  }
  if (!(revokedKeyIds instanceof Set)) {
    fail('trust_unavailable', 'audit anchor revocation set is invalid');
  }
  if (!trustedKeyIds.has(envelope.signature.key_id)) {
    fail('untrusted_signer', 'audit anchor signer is not trusted');
  }
  if (revokedKeyIds.has(envelope.signature.key_id)) {
    fail('revoked_signer', 'audit anchor signer is revoked');
  }
  if (typeof verifySignature !== 'function') {
    fail('verifier_unavailable', 'audit anchor signature verifier is unavailable');
  }
  let verified;
  try {
    verified = verifySignature({
      algorithm: envelope.signature.algorithm,
      keyId: envelope.signature.key_id,
      digest: Buffer.from(envelope.payload_digest, 'hex'),
      signingInput: createAuditAnchorSigningInput(
        {
          version: envelope.version,
          payload: envelope.payload,
          payload_digest: envelope.payload_digest,
        },
        { algorithm: envelope.signature.algorithm, keyId: envelope.signature.key_id },
      ),
      signature: Buffer.from(envelope.signature.value, 'base64url'),
    });
  } catch {
    fail('signature_invalid', 'audit anchor signature verification failed');
  }
  if (verified && typeof verified.then === 'function') {
    Promise.resolve(verified).catch(() => {});
    fail('verifier_invalid', 'audit anchor signature verifier must be synchronous');
  }
  if (verified !== true) fail('signature_invalid', 'audit anchor signature verification failed');
  validatePreviousAnchor(envelope, previousEnvelope);
  const chainMatches = chainState !== null
    ? envelope.payload.chain_head === chainState.lastHash
      && envelope.payload.event_count === chainState.count
      && envelope.payload.file_count === chainState.files
    : envelope.payload.event_count === chainProof.anchoredEventCount
      && envelope.payload.chain_head === chainProof.hashAtAnchor
      && envelope.payload.file_count === chainProof.filesAtAnchor;
  if (!chainMatches) {
    fail('chain_state_mismatch', 'local audit chain does not match the signed anchor');
  }
  return {
    ok: true,
    stream_id: envelope.payload.stream_id,
    sequence: envelope.payload.sequence,
    payload_digest: envelope.payload_digest,
    key_id: envelope.signature.key_id,
  };
}

export { ANCHOR_PURPOSE, ANCHOR_VERSION, SIGNATURE_ALGORITHMS, SIGNATURE_CONTEXT };
