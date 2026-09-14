import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import {
  AuditAnchorExporterError,
  createAuditAnchorExporter,
} from '../broker/lib/audit-anchor-exporter.js';
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
const expectCode = (code) =>
  (error) => error instanceof AuditAnchorExporterError && error.code === code;
const verifier = ({ signingInput, signature }) => verify(null, signingInput, publicKey, signature);
const signRequest = (request) => ({
  algorithm,
  key_id: keyId,
  value: sign(
    null,
    createAuditAnchorSigningInput(request, { algorithm, keyId }),
    privateKey,
  ).toString('base64url'),
});

function proofFor(state, anchoredEventCount) {
  return {
    files: state.files,
    count: state.count,
    lastHash: state.lastHash,
    anchoredEventCount,
    hashAtAnchor: anchoredEventCount === state.count ? state.lastHash : GENESIS_HASH,
    filesAtAnchor: anchoredEventCount === state.count ? state.files : 0,
  };
}

function memoryStore() {
  const records = [];
  return {
    records,
    async readHead() {
      return {
        current: records.at(-1) || null,
        previous: records.at(-2) || null,
      };
    },
    async publish({ expectedPreviousDigest, envelope }) {
      const actual = records.at(-1)?.payload_digest || GENESIS_HASH;
      if (actual !== expectedPreviousDigest) {
        return { status: 'conflict', current: records.at(-1) };
      }
      records.push(structuredClone(envelope));
      return { status: 'published' };
    },
  };
}

function exporter({
  state,
  loadState = async () => structuredClone(state),
  store = memoryStore(),
  signer = { signAnchor: async (request) => signRequest(request) },
  proof = (count) => proofFor(state, count),
  clock = (() => { let value = 1_900_000_000_000; return () => value += 1_000; })(),
  verifySignature = verifier,
} = {}) {
  return {
    store,
    value: createAuditAnchorExporter({
      streamId,
      signer,
      store,
      loadChainState: loadState,
      loadChainProof: async (count) => proof(count),
      trustedKeyIds,
      verifySignature,
      now: clock,
    }),
  };
}

const firstState = { files: 1, count: 2, lastHash: 'a'.repeat(64) };
const firstHarness = exporter({ state: firstState });
const first = await firstHarness.value.exportAnchor();
assert.equal(first.status, 'published');
assert.equal(first.envelope.payload.sequence, 1);
assert.equal(firstHarness.store.records.length, 1);
const retry = await firstHarness.value.exportAnchor();
assert.equal(retry.status, 'already_published');
assert.equal(retry.envelope.payload_digest, first.envelope.payload_digest);
assert.equal(firstHarness.store.records.length, 1, 'an idempotent retry must not store again');

const laterState = { files: 2, count: 3, lastHash: 'b'.repeat(64) };
const growing = exporter({
  state: laterState,
  store: firstHarness.store,
  clock: () => 1_900_000_010_000,
  proof: (count) => count === 2
    ? {
        files: 2, count: 3, lastHash: laterState.lastHash,
        anchoredEventCount: 2, hashAtAnchor: firstState.lastHash, filesAtAnchor: 1,
      }
    : proofFor(laterState, count),
});
const second = await growing.value.exportAnchor();
assert.equal(second.status, 'published');
assert.equal(second.envelope.payload.sequence, 2);
assert.equal(second.envelope.payload.previous_anchor_digest, first.envelope.payload_digest);

const rollbackStore = memoryStore();
rollbackStore.records.push(first.envelope);
const clockRollback = exporter({
  state: laterState,
  store: rollbackStore,
  proof: (count) => count === 2
    ? {
        files: 2, count: 3, lastHash: laterState.lastHash,
        anchoredEventCount: 2, hashAtAnchor: firstState.lastHash, filesAtAnchor: 1,
      }
    : proofFor(laterState, count),
  clock: () => 1_800_000_000_000,
});
await assert.rejects(
  clockRollback.value.exportAnchor(),
  expectCode('anchor_signature_invalid'),
  'a non-advancing anchor clock must fail closed before publication',
);

let signingRequest;
let publishInput;
const boundaryStore = memoryStore();
const boundary = exporter({
  state: firstState,
  store: {
    readHead: boundaryStore.readHead,
    publish: async (input) => { publishInput = input; return boundaryStore.publish(input); },
  },
  signer: {
    signAnchor: async (request) => { signingRequest = request; return signRequest(request); },
  },
});
await boundary.value.exportAnchor();
assert.doesNotMatch(JSON.stringify(signingRequest), /audit_event|authorization|credential|private_key/i);
assert.doesNotMatch(JSON.stringify(publishInput), /audit_event|authorization|credential|private_key/i);

const winningRequest = createAuditAnchorRequest(firstState, {
  streamId, sequence: 1, now: () => 1_900_000_010_000,
});
const winner = attachAuditAnchorSignature(winningRequest, signRequest(winningRequest));
const idempotentConflict = exporter({
  state: firstState,
  store: {
    readHead: async () => ({ current: null, previous: null }),
    publish: async () => ({ status: 'conflict', current: winner }),
  },
});
assert.equal((await idempotentConflict.value.exportAnchor()).status, 'already_published');

const otherState = { files: 1, count: 3, lastHash: 'c'.repeat(64) };
const otherRequest = createAuditAnchorRequest(otherState, {
  streamId, sequence: 1, now: () => 1_900_000_010_000,
});
const otherWinner = attachAuditAnchorSignature(otherRequest, signRequest(otherRequest));
const conflicting = exporter({
  state: firstState,
  store: {
    readHead: async () => ({ current: null, previous: null }),
    publish: async () => ({ status: 'conflict', current: otherWinner }),
  },
});
await assert.rejects(conflicting.value.exportAnchor(), expectCode('anchor_publish_conflict'));

for (const [overrides, code] of [
  [{ store: { readHead: async () => { throw new Error('detail'); }, publish() {} } }, 'anchor_store_unavailable'],
  [{ store: { readHead: async () => ({ current: null, previous: null }), publish: async () => { throw new Error('detail'); } } }, 'anchor_store_unavailable'],
  [{ store: { readHead: async () => ({ current: null, previous: first.envelope }), publish() {} } }, 'anchor_store_invalid'],
  [{ store: { readHead: async () => ({ current: { ...first.envelope, payload: { ...first.envelope.payload, stream_id: 'other' } }, previous: null }), publish() {} } }, 'anchor_store_invalid'],
  [{ store: { readHead: async () => ({ current: { ...first.envelope, signature: { ...first.envelope.signature, value: Buffer.alloc(64).toString('base64url') } }, previous: null }), publish() {} } }, 'anchor_store_invalid'],
  [{ store: { readHead: async () => ({ current: null, previous: null }), publish: async () => ({ status: 'unknown' }) } }, 'anchor_store_invalid'],
  [{ signer: { signAnchor: async () => { throw new Error('detail'); } } }, 'anchor_signer_unavailable'],
  [{ signer: { signAnchor: async () => ({ ...signRequest(winningRequest), value: Buffer.alloc(64).toString('base64url') }) } }, 'anchor_signature_invalid'],
  [{ verifySignature: () => false }, 'anchor_signature_invalid'],
  [{ clock: () => Number.NaN }, 'anchor_export_request_invalid'],
  [{ clock: () => { throw new Error('detail'); } }, 'anchor_export_request_invalid'],
  [{ loadState: async () => { throw new Error('detail'); } }, 'anchor_chain_unavailable'],
]) {
  const failing = exporter({ state: firstState, ...overrides });
  await assert.rejects(failing.value.exportAnchor(), expectCode(code));
}

const invalidChain = exporter({ state: { files: 0, count: 1, lastHash: 'd'.repeat(64) } });
await assert.rejects(invalidChain.value.exportAnchor(), expectCode('anchor_chain_invalid'));
const unavailableProof = exporter({
  state: laterState,
  store: firstHarness.store,
  proof: () => { throw new Error('detail'); },
});
await assert.rejects(unavailableProof.value.exportAnchor(), expectCode('anchor_chain_unavailable'));

for (const invalid of [
  {},
  { streamId: '../stream' },
  {
    streamId,
    signer: {},
    store: {},
    loadChainState() {},
    loadChainProof() {},
    trustedKeyIds,
    verifySignature: verifier,
  },
]) {
  assert.throws(() => createAuditAnchorExporter(invalid), TypeError);
}
await assert.rejects(
  firstHarness.value.exportAnchor({ signal: {} }),
  expectCode('anchor_export_request_invalid'),
);
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  firstHarness.value.exportAnchor({ signal: aborted.signal }),
  expectCode('anchor_export_aborted'),
);
const abortDuringSigning = new AbortController();
const abortingSigner = exporter({
  state: firstState,
  signer: {
    signAnchor: async () => {
      abortDuringSigning.abort();
      throw new Error('detail');
    },
  },
});
await assert.rejects(
  abortingSigner.value.exportAnchor({ signal: abortDuringSigning.signal }),
  expectCode('anchor_export_aborted'),
);
const abortDuringStore = new AbortController();
const abortingStore = exporter({
  state: firstState,
  store: {
    readHead: async () => {
      abortDuringStore.abort();
      throw new Error('detail');
    },
    publish() {},
  },
});
await assert.rejects(
  abortingStore.value.exportAnchor({ signal: abortDuringStore.signal }),
  expectCode('anchor_export_aborted'),
);

console.log('audit anchor exporter: verified CAS publication, idempotency and safe failures passed');
