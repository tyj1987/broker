import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import {
  AUDIT_ANCHOR_RECOVERY_LIMITS,
  AuditAnchorRecoveryError,
  createAuditAnchorRecoveryVerifier,
} from '../broker/lib/audit-anchor-recovery.js';
import {
  attachAuditAnchorSignature,
  createAuditAnchorRequest,
  createAuditAnchorSigningInput,
} from '../broker/lib/audit-anchor.js';
import { GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

const streamId = 'broker-production';
const algorithm = 'ed25519';
const keyId = 'audit-anchor-key-2026-01';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const trustedKeyIds = new Set([keyId]);
const verifier = ({ signingInput, signature }) => verify(null, signingInput, publicKey, signature);
const expectCode = (code) =>
  (error) => error instanceof AuditAnchorRecoveryError && error.code === code;

function signedAnchor(state, sequence, previous, time) {
  const request = createAuditAnchorRequest(state, {
    streamId,
    sequence,
    previousAnchorDigest: previous?.payload_digest || GENESIS_HASH,
    now: () => time,
  });
  return attachAuditAnchorSignature(request, {
    algorithm,
    key_id: keyId,
    value: sign(
      null,
      createAuditAnchorSigningInput(request, { algorithm, keyId }),
      privateKey,
    ).toString('base64url'),
  });
}

const states = [
  { files: 1, count: 2, lastHash: 'a'.repeat(64) },
  { files: 2, count: 4, lastHash: 'b'.repeat(64) },
  { files: 3, count: 5, lastHash: 'c'.repeat(64) },
];
const anchors = [];
for (const [index, state] of states.entries()) {
  anchors.push(signedAnchor(state, index + 1, anchors.at(-1), 1_900_000_000_000 + index * 1_000));
}
const proofByCount = new Map(states.map((state) => [state.count, {
  files: states.at(-1).files,
  count: states.at(-1).count,
  lastHash: states.at(-1).lastHash,
  anchoredEventCount: state.count,
  hashAtAnchor: state.lastHash,
  filesAtAnchor: state.files,
}]));

function memoryStore(values = anchors) {
  return {
    async readHead() {
      return { current: values.at(-1) || null, previous: values.at(-2) || null };
    },
    async readPage({ afterSequence, throughSequence, limit }) {
      return {
        anchors: values
          .filter((value) => value.payload.sequence > afterSequence
            && value.payload.sequence <= throughSequence)
          .slice(0, limit),
      };
    },
  };
}

function recovery({
  store = memoryStore(),
  loadProof = async (count) => structuredClone(proofByCount.get(count)),
  verifySignature = verifier,
  pageSize = 2,
  maxAnchors = 100,
  revokedKeyIds = new Set(),
} = {}) {
  return createAuditAnchorRecoveryVerifier({
    streamId,
    store,
    loadChainProof: loadProof,
    trustedKeyIds,
    revokedKeyIds,
    verifySignature,
    pageSize,
    maxAnchors,
  });
}

const calls = [];
const pagedStore = memoryStore();
const verified = await recovery({
  store: {
    readHead: pagedStore.readHead,
    readPage: async (input) => { calls.push(input); return pagedStore.readPage(input); },
  },
}).verifyRecovery();
assert.deepEqual(verified, {
  status: 'verified', count: 3, sequence: 3, payload_digest: anchors.at(-1).payload_digest,
});
assert.deepEqual(calls.map(({ afterSequence, throughSequence, limit }) => ({
  afterSequence, throughSequence, limit,
})), [
  { afterSequence: 0, throughSequence: 3, limit: 2 },
  { afterSequence: 2, throughSequence: 3, limit: 2 },
]);
assert.equal(JSON.stringify(calls).includes('audit_event'), false);

assert.deepEqual(await recovery({ store: memoryStore([]) }).verifyRecovery(), {
  status: 'empty', count: 0, sequence: 0, payload_digest: null,
});

const tampered = structuredClone(anchors);
tampered[1].signature.value = Buffer.alloc(64).toString('base64url');
await assert.rejects(
  recovery({ store: memoryStore(tampered) }).verifyRecovery(),
  expectCode('anchor_recovery_invalid'),
);
await assert.rejects(
  recovery({ revokedKeyIds: new Set([keyId]) }).verifyRecovery(),
  expectCode('anchor_recovery_invalid'),
);
await assert.rejects(
  recovery({ verifySignature: () => false }).verifyRecovery(),
  expectCode('anchor_recovery_invalid'),
);
await assert.rejects(
  recovery({ loadProof: async () => { throw new Error('detail'); } }).verifyRecovery(),
  expectCode('anchor_chain_unavailable'),
);

const missing = [anchors[0], anchors[2]];
await assert.rejects(
  recovery({ store: memoryStore(missing) }).verifyRecovery(),
  expectCode('anchor_store_invalid'),
);
await assert.rejects(
  recovery({
    store: {
      readHead: memoryStore().readHead,
      readPage: async () => ({ anchors: [] }),
    },
  }).verifyRecovery(),
  expectCode('anchor_recovery_incomplete'),
);
await assert.rejects(
  recovery({ maxAnchors: 2 }).verifyRecovery(),
  expectCode('anchor_recovery_limit'),
);

const wrongHead = memoryStore();
await assert.rejects(
  recovery({
    store: {
      readHead: async () => ({ current: anchors.at(-1), previous: anchors[0] }),
      readPage: wrongHead.readPage,
    },
  }).verifyRecovery(),
  expectCode('anchor_store_invalid'),
);

for (const [store, code] of [
  [{ readHead: async () => { throw new Error('detail'); }, readPage() {} }, 'anchor_store_unavailable'],
  [{ readHead: async () => null, readPage() {} }, 'anchor_store_invalid'],
  [{ readHead: async () => ({ current: null, previous: anchors[0] }), readPage() {} }, 'anchor_store_invalid'],
  [{ readHead: async () => ({ current: { ...anchors[0], payload: { ...anchors[0].payload, sequence: 0 } }, previous: null }), readPage() {} }, 'anchor_store_invalid'],
  [{ readHead: memoryStore().readHead, readPage: async () => { throw new Error('detail'); } }, 'anchor_store_unavailable'],
  [{ readHead: memoryStore().readHead, readPage: async () => ({ anchors: 'invalid' }) }, 'anchor_store_invalid'],
  [{ readHead: memoryStore().readHead, readPage: async () => ({ anchors: [], extra: true }) }, 'anchor_store_invalid'],
]) {
  await assert.rejects(recovery({ store }).verifyRecovery(), expectCode(code));
}

for (const invalid of [
  {},
  { streamId: '../stream' },
  {
    streamId,
    store: {},
    loadChainProof() {},
    trustedKeyIds,
    verifySignature: verifier,
  },
  {
    streamId,
    store: memoryStore(),
    loadChainProof() {},
    trustedKeyIds,
    verifySignature: verifier,
    pageSize: 0,
  },
  {
    streamId,
    store: memoryStore(),
    loadChainProof() {},
    trustedKeyIds,
    verifySignature: verifier,
    maxAnchors: 1_000_001,
  },
]) {
  assert.throws(() => createAuditAnchorRecoveryVerifier(invalid), TypeError);
}

const instance = recovery();
await assert.rejects(
  instance.verifyRecovery({ signal: {} }),
  expectCode('anchor_recovery_request_invalid'),
);
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  instance.verifyRecovery({ signal: aborted.signal }),
  expectCode('anchor_recovery_aborted'),
);
const abortDuringStore = new AbortController();
await assert.rejects(
  recovery({
    store: {
      readHead: async () => {
        abortDuringStore.abort();
        throw new Error('detail');
      },
      readPage() {},
    },
  }).verifyRecovery({ signal: abortDuringStore.signal }),
  expectCode('anchor_recovery_aborted'),
);
assert.deepEqual(AUDIT_ANCHOR_RECOVERY_LIMITS, {
  default_page_size: 100,
  maximum_page_size: 1_000,
  default_maximum_anchors: 100_000,
  maximum_anchors: 1_000_000,
});

console.log('audit anchor recovery: fixed-head pagination and full-chain verification passed');
