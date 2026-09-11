import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import {
  ANCHOR_PURPOSE,
  AuditAnchorError,
  attachAuditAnchorSignature,
  createAuditAnchorRequest,
  createAuditAnchorSigningInput,
  verifyAuditAnchorEnvelope,
} from '../broker/lib/audit-anchor.js';
import { computeHash, GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

const expectCode = (code) =>
  (error) => error instanceof AuditAnchorError && error.code === code;
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const keyId = 'audit-anchor-key-2026-01';
const chainState = {
  files: 3,
  count: 42,
  lastHash: 'a'.repeat(64),
};

function signedRequest(request, overrides = {}) {
  const metadata = {
    algorithm: 'ed25519',
    key_id: keyId,
    ...overrides,
  };
  const signingInput = createAuditAnchorSigningInput(request, {
    algorithm: metadata.algorithm,
    keyId: metadata.key_id,
  });
  return attachAuditAnchorSignature(request, {
    ...metadata,
    value: sign(null, signingInput, privateKey).toString('base64url'),
  });
}

function verifier({ algorithm, keyId: observedKeyId, signingInput, signature }) {
  return algorithm === 'ed25519'
    && observedKeyId === keyId
    && verify(null, signingInput, publicKey, signature);
}

const firstRequest = createAuditAnchorRequest(chainState, {
  streamId: 'broker-production',
  sequence: 1,
  now: () => 1_900_000_000_000,
});
assert.equal(firstRequest.payload.purpose, ANCHOR_PURPOSE);
assert.equal(firstRequest.payload.previous_anchor_digest, GENESIS_HASH);
assert.equal(firstRequest.payload.event_count, chainState.count);
const first = signedRequest(firstRequest);
const firstResult = verifyAuditAnchorEnvelope(first, {
  chainState,
  trustedKeyIds: new Set([keyId]),
  verifySignature: verifier,
});
assert.deepEqual(firstResult, {
  ok: true,
  stream_id: 'broker-production',
  sequence: 1,
  payload_digest: first.payload_digest,
  key_id: keyId,
});

const nextChainState = { files: 4, count: 43, lastHash: 'b'.repeat(64) };
const secondRequest = createAuditAnchorRequest(nextChainState, {
  streamId: 'broker-production',
  sequence: 2,
  previousAnchorDigest: first.payload_digest,
  now: () => 1_900_000_060_000,
});
const second = signedRequest(secondRequest);
assert.equal(
  verifyAuditAnchorEnvelope(second, {
    chainState: nextChainState,
    previousEnvelope: first,
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }).sequence,
  2,
);

assert.throws(
  () => verifyAuditAnchorEnvelope(second, {
    chainState: { ...nextChainState, count: 42 },
    previousEnvelope: first,
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('chain_state_mismatch'),
  'a deleted suffix or incomplete recovery must not satisfy the retained anchor',
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState: { files: 0, count: 0, lastHash: GENESIS_HASH },
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('chain_state_mismatch'),
  'complete local-chain deletion must not satisfy an external signed anchor',
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set(['another-key']),
    verifySignature: verifier,
  }),
  expectCode('untrusted_signer'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    revokedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('revoked_signer'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: () => false,
  }),
  expectCode('signature_invalid'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: () => Promise.resolve(true),
  }),
  expectCode('verifier_invalid'),
);

const tampered = structuredClone(first);
tampered.payload.event_count += 1;
assert.throws(
  () => verifyAuditAnchorEnvelope(tampered, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('anchor_digest_mismatch'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set(),
    verifySignature: verifier,
  }),
  expectCode('trust_unavailable'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
  }),
  expectCode('verifier_unavailable'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    revokedKeyIds: [],
    verifySignature: verifier,
  }),
  expectCode('trust_unavailable'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope(first, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: () => { throw new Error('verifier detail must not escape'); },
  }),
  expectCode('signature_invalid'),
);
assert.throws(
  () => verifyAuditAnchorEnvelope({ ...first, unexpected: true }, {
    chainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('invalid_anchor'),
);
assert.throws(
  () => attachAuditAnchorSignature({ ...firstRequest, unexpected: true }, first.signature),
  expectCode('invalid_anchor'),
);

for (const [mutate, code] of [
  [(payload) => { payload.stream_id = 'another-stream'; }, 'anchor_stream_mismatch'],
  [(payload) => { payload.sequence = 3; }, 'anchor_sequence_mismatch'],
  [(payload) => { payload.previous_anchor_digest = 'c'.repeat(64); }, 'previous_anchor_mismatch'],
  [(payload) => { payload.captured_at = first.payload.captured_at; }, 'anchor_clock_rollback'],
  [(payload) => { payload.event_count = 41; }, 'anchor_count_rollback'],
]) {
  const changedRequest = structuredClone(secondRequest);
  mutate(changedRequest.payload);
  changedRequest.payload_digest = computeHash(changedRequest.payload);
  const changed = signedRequest(changedRequest);
  assert.throws(
    () => verifyAuditAnchorEnvelope(changed, {
      chainState: {
        files: changed.payload.file_count,
        count: changed.payload.event_count,
        lastHash: changed.payload.chain_head,
      },
      previousEnvelope: first,
      trustedKeyIds: new Set([keyId]),
      verifySignature: verifier,
    }),
    expectCode(code),
  );
}

assert.throws(
  () => verifyAuditAnchorEnvelope(second, {
    chainState: nextChainState,
    trustedKeyIds: new Set([keyId]),
    verifySignature: verifier,
  }),
  expectCode('previous_anchor_required'),
);
assert.throws(
  () => createAuditAnchorRequest({ ...chainState, lastHash: GENESIS_HASH }, {
    streamId: 'broker-production', sequence: 1,
  }),
  expectCode('invalid_chain_state'),
);
assert.throws(
  () => createAuditAnchorRequest(chainState, {
    streamId: 'bad stream', sequence: 1,
  }),
  expectCode('invalid_anchor'),
);
assert.throws(
  () => createAuditAnchorRequest(chainState, {
    streamId: 'broker-production', sequence: 2,
  }),
  expectCode('invalid_anchor'),
);
assert.throws(
  () => createAuditAnchorRequest(chainState, {
    streamId: 'broker-production', sequence: 1, now: () => Number.NaN,
  }),
  expectCode('invalid_anchor'),
);
assert.throws(
  () => createAuditAnchorRequest(chainState, {
    streamId: 'broker-production', sequence: 1, now: () => 8.64e15 + 1,
  }),
  expectCode('invalid_anchor'),
);
assert.throws(
  () => attachAuditAnchorSignature(firstRequest, {
    algorithm: 'unknown', key_id: keyId, value: 'a'.repeat(64),
  }),
  expectCode('invalid_signature'),
);
assert.throws(
  () => attachAuditAnchorSignature(firstRequest, {
    algorithm: 'ed25519', key_id: keyId, value: `${'a'.repeat(43)}=`,
  }),
  expectCode('invalid_signature'),
);
assert.throws(
  () => createAuditAnchorSigningInput(firstRequest, {
    algorithm: 'unknown', keyId,
  }),
  expectCode('invalid_signature'),
);

console.log('audit anchor: signed chain heads, continuity, revocation and deletion checks passed');
