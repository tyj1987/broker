import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  createAuditAnchorExporterRuntime,
  parseAuditAnchorExporterConfig,
  readAuditAnchorExporterConfig,
  runAuditAnchorExporterService,
} from '../broker/lib/audit-anchor-exporter-runtime.js';
import { createAuditAnchorSigningInput } from '../broker/lib/audit-anchor.js';
import { GENESIS_HASH } from '../broker/lib/audit-hash-chain.js';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
const publicKeyHash = createHash('sha256').update(publicKeyDer).digest('hex');
const validDocument = {
  version: 1,
  purpose: 'secret-broker.audit-anchor-exporter',
  audit_directory: '/var/lib/secret-broker/audit',
  stream_id: 'production-audit',
  algorithm: 'ecdsa-p256-sha256',
  active_key_id: 'kms-audit-key-1',
  trusted_keys: [
    {
      key_id: 'kms-audit-key-1',
      public_key_spki_der_base64: publicKeyDer.toString('base64'),
      public_key_sha256: publicKeyHash,
    },
  ],
  revoked_key_ids: [],
  signer_timeout_ms: 2_000,
  store_timeout_ms: 40_000,
  export_deadline_ms: 50_000,
  interval_ms: 60_000,
};

const config = parseAuditAnchorExporterConfig(JSON.stringify(validDocument));
assert.equal(config.streamId, 'production-audit');
assert.equal(config.activeKeyId, 'kms-audit-key-1');
assert.equal(config.trustedKeyIds.size, 1);
assert.equal(config.revokedKeyIds.size, 0);
assert.equal(config.auditDirectory, '/var/lib/secret-broker/audit');

for (const [name, document] of [
  ['unknown field', { ...validDocument, token: 'forbidden' }],
  ['relative audit path', { ...validDocument, audit_directory: '../audit' }],
  ['wrong audit path', { ...validDocument, audit_directory: '/tmp/audit' }],
  ['wrong algorithm', { ...validDocument, algorithm: 'ed25519' }],
  ['untrusted active key', { ...validDocument, active_key_id: 'kms-audit-key-2' }],
  ['revoked active key', { ...validDocument, revoked_key_ids: ['kms-audit-key-1'] }],
  [
    'bad public key hash',
    {
      ...validDocument,
      trusted_keys: [{ ...validDocument.trusted_keys[0], public_key_sha256: '0'.repeat(64) }],
    },
  ],
  [
    'duplicate trusted key',
    {
      ...validDocument,
      trusted_keys: [validDocument.trusted_keys[0], validDocument.trusted_keys[0]],
    },
  ],
  ['unsafe deadline', { ...validDocument, export_deadline_ms: 60_001 }],
  ['unsafe interval', { ...validDocument, interval_ms: 59_999 }],
]) {
  assert.throws(
    () => parseAuditAnchorExporterConfig(JSON.stringify(document)),
    { code: 'anchor_exporter_config_invalid' },
    name,
  );
}
assert.throws(
  () =>
    parseAuditAnchorExporterConfig(
      JSON.stringify(validDocument).replace('"version":1', '"version":1,"version":1'),
    ),
  { code: 'anchor_exporter_config_invalid' },
  'duplicate JSON keys must fail closed',
);
assert.throws(() => parseAuditAnchorExporterConfig('{'), {
  code: 'anchor_exporter_config_invalid',
});
const { publicKey: rsaPublicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaDer = rsaPublicKey.export({ format: 'der', type: 'spki' });
assert.throws(
  () =>
    parseAuditAnchorExporterConfig(
      JSON.stringify({
        ...validDocument,
        trusted_keys: [
          {
            key_id: 'kms-audit-key-1',
            public_key_spki_der_base64: rsaDer.toString('base64'),
            public_key_sha256: createHash('sha256').update(rsaDer).digest('hex'),
          },
        ],
      }),
    ),
  { code: 'anchor_exporter_config_invalid' },
);

let configClosed = false;
const fileMetadata = {
  isFile: () => true,
  uid: 0,
  gid: 1202,
  mode: 0o100440,
  size: Buffer.byteLength(JSON.stringify(validDocument)),
};
const loaded = await readAuditAnchorExporterConfig('/etc/secret-broker/audit/exporter.json', {
  processGroups: [1202],
  statPath: async () => ({
    isDirectory: () => true,
    isSymbolicLink: () => false,
    uid: 0,
    mode: 0o040755,
  }),
  resolvePath: async (path) => path,
  openFile: async () => ({
    stat: async () => fileMetadata,
    readFile: async () => JSON.stringify(validDocument),
    close: async () => {
      configClosed = true;
    },
  }),
});
assert.equal(loaded.streamId, validDocument.stream_id);
assert.equal(configClosed, true);
for (const [name, overrides] of [
  ['wrong path', { path: '/tmp/exporter.json' }],
  [
    'unsafe directory',
    {
      statPath: async () => ({
        isDirectory: () => true,
        isSymbolicLink: () => false,
        uid: 0,
        mode: 0o040777,
      }),
    },
  ],
  [
    'unsafe file',
    {
      openFile: async () => ({
        stat: async () => ({ ...fileMetadata, mode: 0o100640 }),
        readFile: async () => JSON.stringify(validDocument),
        close: async () => {},
      }),
    },
  ],
  [
    'open failure',
    {
      openFile: async () => {
        throw new Error('detail');
      },
    },
  ],
]) {
  await assert.rejects(
    readAuditAnchorExporterConfig(overrides.path || '/etc/secret-broker/audit/exporter.json', {
      processGroups: [1202],
      statPath:
        overrides.statPath ||
        (async () => ({
          isDirectory: () => true,
          isSymbolicLink: () => false,
          uid: 0,
          mode: 0o040755,
        })),
      resolvePath: async (path) => path,
      openFile:
        overrides.openFile ||
        (async () => ({
          stat: async () => fileMetadata,
          readFile: async () => JSON.stringify(validDocument),
          close: async () => {},
        })),
    }),
    { code: 'anchor_exporter_config_untrusted' },
    name,
  );
}

const state = { files: 1, count: 2, lastHash: 'a'.repeat(64) };
const records = [];
const signer = {
  async signAnchor(request) {
    const signingInput = createAuditAnchorSigningInput(request, {
      algorithm: config.algorithm,
      keyId: config.activeKeyId,
    });
    return {
      algorithm: config.algorithm,
      key_id: config.activeKeyId,
      value: sign('sha256', signingInput, privateKey).toString('base64url'),
    };
  },
};
const store = {
  async readHead() {
    return { current: records.at(-1) || null, previous: records.at(-2) || null };
  },
  async publish({ expectedPreviousDigest, envelope }) {
    assert.equal(expectedPreviousDigest, records.at(-1)?.payload_digest || GENESIS_HASH);
    records.push(structuredClone(envelope));
    return { status: 'published' };
  },
};
const runtime = createAuditAnchorExporterRuntime({
  config,
  signer,
  store,
  loadChainState: async () => structuredClone(state),
  loadChainProof: async (count) => ({
    ...state,
    anchoredEventCount: count,
    hashAtAnchor: state.lastHash,
    filesAtAnchor: state.files,
  }),
  now: () => 1_900_000_000_000,
});
const published = await runtime.exportOnce();
assert.equal(published.status, 'published');
assert.equal(records.length, 1);
assert.throws(() => createAuditAnchorExporterRuntime({ config: {}, signer, store }), TypeError);
const wrongKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
const invalidSignatureRuntime = createAuditAnchorExporterRuntime({
  config,
  signer: {
    async signAnchor(request) {
      return {
        algorithm: config.algorithm,
        key_id: config.activeKeyId,
        value: sign(
          'sha256',
          createAuditAnchorSigningInput(request, {
            algorithm: config.algorithm,
            keyId: config.activeKeyId,
          }),
          wrongKey,
        ).toString('base64url'),
      };
    },
  },
  store: {
    readHead: async () => ({ current: null, previous: null }),
    publish: async () => ({ status: 'published' }),
  },
  loadChainState: async () => state,
  loadChainProof: async () => {
    throw new Error('not used');
  },
});
await assert.rejects(invalidSignatureRuntime.exportOnce(), { code: 'anchor_signature_invalid' });
assert.equal((await runtime.exportOnce()).status, 'already_published');
assert.equal(records.length, 1);

const log = [];
const stop = new AbortController();
let calls = 0;
await runAuditAnchorExporterService({
  runtime: {
    async exportOnce() {
      calls += 1;
      stop.abort();
      return { status: 'published', envelope: records[0] };
    },
  },
  intervalMs: 60_000,
  signal: stop.signal,
  writeStatus: (value) => log.push(value),
});
assert.equal(calls, 1);
assert.deepEqual(log, [], 'cancellation during export must suppress the late status');

const delayedStop = new AbortController();
setImmediate(() => delayedStop.abort());
await runAuditAnchorExporterService({
  runtime: { exportOnce: async () => ({ status: 'already_published', envelope: records[0] }) },
  intervalMs: 60_000,
  signal: delayedStop.signal,
  writeStatus: () => {},
});

const abortOnFailure = new AbortController();
await runAuditAnchorExporterService({
  runtime: {
    exportOnce: async () => {
      abortOnFailure.abort();
      throw new Error('detail');
    },
  },
  intervalMs: 60_000,
  signal: abortOnFailure.signal,
});

await assert.rejects(
  runAuditAnchorExporterService({ runtime: {}, intervalMs: 1, signal: {} }),
  TypeError,
);

await assert.rejects(
  runAuditAnchorExporterService({
    runtime: {
      exportOnce: async () => {
        throw Object.assign(new Error('secret detail'), { code: 'anchor_store_unavailable' });
      },
    },
    intervalMs: 60_000,
    signal: new AbortController().signal,
  }),
  (error) => error.code === 'anchor_store_unavailable' && !error.message.includes('secret detail'),
);
await assert.rejects(
  runAuditAnchorExporterService({
    runtime: {
      exportOnce: async () => {
        throw new Error('detail');
      },
    },
    intervalMs: 60_000,
    signal: new AbortController().signal,
  }),
  (error) =>
    error.code === 'anchor_export_failed' && error.message === 'Audit anchor export failed',
);

// Source-only rejection and cleanup coverage. All keys and file metadata are
// synthetic; these tests never read production paths or contact a provider.
for (const input of [null, undefined, 42, '', ' '.repeat(32 * 1024 + 1), 'version: 1']) {
  assert.throws(() => parseAuditAnchorExporterConfig(input), {
    code: 'anchor_exporter_config_invalid',
  });
}

const invalidDocuments = [
  null,
  [],
  {},
  { ...validDocument, version: 2 },
  { ...validDocument, purpose: 'other-purpose' },
  { ...validDocument, stream_id: '' },
  { ...validDocument, active_key_id: '' },
  { ...validDocument, trusted_keys: null },
  { ...validDocument, trusted_keys: [] },
  { ...validDocument, trusted_keys: Array(9).fill(validDocument.trusted_keys[0]) },
  { ...validDocument, revoked_key_ids: null },
  { ...validDocument, revoked_key_ids: Array(9).fill('retired-key') },
  { ...validDocument, revoked_key_ids: [''] },
  { ...validDocument, revoked_key_ids: ['retired-key', 'retired-key'] },
  { ...validDocument, export_deadline_ms: 60_000, interval_ms: 60_000 },
];
for (const [field, minimum, maximum] of [
  ['signer_timeout_ms', 100, 10_000],
  ['store_timeout_ms', 100, 60_000],
  ['export_deadline_ms', 1_000, 60_000],
  ['interval_ms', 60_000, 3_600_000],
]) {
  for (const invalid of [minimum - 1, maximum + 1, minimum + 0.5, String(minimum)]) {
    invalidDocuments.push({ ...validDocument, [field]: invalid });
  }
}
for (const document of invalidDocuments) {
  assert.throws(() => parseAuditAnchorExporterConfig(JSON.stringify(document)), {
    code: 'anchor_exporter_config_invalid',
  });
}

const entry = validDocument.trusted_keys[0];
const invalidDer = Buffer.from('synthetic non-DER public data');
const oversizedDer = Buffer.alloc(513, 1);
const p384Der = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({
  format: 'der', type: 'spki',
});
for (const candidateKey of [
  null,
  [],
  { ...entry, key_id: '' },
  { ...entry, unexpected: true },
  { ...entry, public_key_spki_der_base64: null },
  { ...entry, public_key_spki_der_base64: '' },
  { ...entry, public_key_spki_der_base64: 'A'.repeat(1_025) },
  { ...entry, public_key_sha256: 'invalid-digest' },
  { ...entry, public_key_spki_der_base64: '====' },
  { ...entry, public_key_spki_der_base64: entry.public_key_spki_der_base64 + '\n' },
  ...[invalidDer, oversizedDer, p384Der].map((der) => ({
    ...entry,
    public_key_spki_der_base64: der.toString('base64'),
    public_key_sha256: createHash('sha256').update(der).digest('hex'),
  })),
]) {
  assert.throws(
    () => parseAuditAnchorExporterConfig(JSON.stringify({
      ...validDocument, trusted_keys: [candidateKey],
    })),
    { code: 'anchor_exporter_config_invalid' },
  );
}
const historicalConfig = parseAuditAnchorExporterConfig(JSON.stringify({
  ...validDocument, revoked_key_ids: ['retired-key'],
}));
historicalConfig.trustedKeyIds.clear();
historicalConfig.revokedKeyIds.clear();
assert.deepEqual([...historicalConfig.trustedKeyIds], [validDocument.active_key_id]);
assert.deepEqual([...historicalConfig.revokedKeyIds], ['retired-key']);

const trustedDirectory = {
  isDirectory: () => true,
  isSymbolicLink: () => false,
  uid: 0,
  mode: 0o040755,
};
const readerOptions = {
  processGroups: [1202],
  statPath: async () => trustedDirectory,
  resolvePath: async (path) => path,
  openFile: async () => ({
    stat: async () => fileMetadata,
    readFile: async () => JSON.stringify(validDocument),
    close: async () => {},
  }),
};
for (const overrides of [
  { processGroups: null },
  { ownerUid: -1 },
  { ownerUid: 0.5 },
  { statPath: null },
  { resolvePath: null },
  { openFile: null },
  { statPath: async () => ({ ...trustedDirectory, isDirectory: () => false }) },
  { statPath: async () => ({ ...trustedDirectory, isSymbolicLink: () => true }) },
  { statPath: async () => ({ ...trustedDirectory, uid: 1 }) },
  { resolvePath: async () => '/synthetic/redirect' },
]) {
  await assert.rejects(
    readAuditAnchorExporterConfig('/etc/secret-broker/audit/exporter.json', {
      ...readerOptions, ...overrides,
    }),
    { code: 'anchor_exporter_config_untrusted' },
  );
}
for (const metadata of [
  { ...fileMetadata, isFile: () => false },
  { ...fileMetadata, uid: 1 },
  { ...fileMetadata, gid: 9999 },
  { ...fileMetadata, size: 0 },
  { ...fileMetadata, size: 32 * 1024 + 1 },
]) {
  let closed = 0;
  let reads = 0;
  await assert.rejects(
    readAuditAnchorExporterConfig('/etc/secret-broker/audit/exporter.json', {
      ...readerOptions,
      openFile: async () => ({
        stat: async () => metadata,
        readFile: async () => { reads += 1; return JSON.stringify(validDocument); },
        close: async () => { closed += 1; },
      }),
    }),
    { code: 'anchor_exporter_config_untrusted' },
  );
  assert.equal(reads, 0, 'untrusted file metadata must block content reads');
  assert.equal(closed, 1, 'rejected handles must be closed exactly once');
}
let cleanupCalls = 0;
const cleanupConfig = await readAuditAnchorExporterConfig('/etc/secret-broker/audit/exporter.json', {
  ...readerOptions,
  openFile: async () => ({
    stat: async () => fileMetadata,
    readFile: async () => JSON.stringify(validDocument),
    close: async () => { cleanupCalls += 1; throw new Error('synthetic cleanup error'); },
  }),
});
assert.equal(cleanupConfig.streamId, validDocument.stream_id);
assert.equal(cleanupCalls, 1);

let serviceCalls = 0;
const serviceOptions = {
  runtime: { exportOnce: async () => { serviceCalls += 1; throw new Error('must not execute'); } },
  intervalMs: 60_000,
  exportDeadlineMs: 1_000,
  signal: new AbortController().signal,
  writeStatus: () => {},
};
for (const overrides of [
  { runtime: null },
  { runtime: { exportOnce: null } },
  { intervalMs: 59_999 },
  { exportDeadlineMs: 999 },
  { exportDeadlineMs: 60_000 },
  { signal: {} },
  { writeStatus: null },
]) {
  await assert.rejects(runAuditAnchorExporterService({ ...serviceOptions, ...overrides }), TypeError);
}
assert.equal(serviceCalls, 0, 'invalid service configuration must fail before exporting');
for (const code of [42, '', 'UNSAFE-code', 'x'.repeat(65)]) {
  await assert.rejects(
    runAuditAnchorExporterService({
      ...serviceOptions,
      runtime: { exportOnce: async () => { throw Object.assign(new Error('synthetic detail'), { code }); } },
    }),
    (error) => error.code === 'anchor_export_failed' && error.message === 'Audit anchor export failed',
  );
}


// A stopped service must not begin work or report a late result as successful.
const alreadyStopped = new AbortController();
alreadyStopped.abort(new Error('synthetic-private-reason'));
let stoppedCalls = 0;
await runAuditAnchorExporterService({
  runtime: { exportOnce: async () => { stoppedCalls += 1; return { status: 'published', envelope: records[0] }; } },
  intervalMs: 60_000, signal: alreadyStopped.signal,
  writeStatus: () => assert.fail('pre-aborted service emitted output'),
});
assert.equal(stoppedCalls, 0, 'pre-aborted service must not invoke runtime');

const beforeInvocation = new AbortController();
let earlyCalls = 0;
queueMicrotask(() => beforeInvocation.abort());
await runAuditAnchorExporterService({
  runtime: { exportOnce: async () => { earlyCalls += 1; return { status: 'published', envelope: records[0] }; } },
  intervalMs: 60_000, signal: beforeInvocation.signal,
  writeStatus: () => assert.fail('cancelled queued invocation emitted output'),
});
assert.equal(earlyCalls, 0, 'queued invocation must recheck cancellation');

async function withSettlementGuard(promise) {
  let guard;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      guard = setTimeout(() => reject(new Error('service did not settle within its bound')), 4_000);
    })]);
  } finally { clearTimeout(guard); }
}

for (const mode of ['cancel_resolve', 'cancel_reject', 'timeout_resolve', 'timeout_reject']) {
  const shutdown = new AbortController();
  const status = [];
  let childSignal, complete, failPending, iterations = 0;
  const service = runAuditAnchorExporterService({
    runtime: { exportOnce: ({ signal: received }) => {
      iterations += 1;
      childSignal = received;
      if (mode.startsWith('cancel_')) queueMicrotask(() => shutdown.abort(new Error('synthetic-private-reason')));
      // Deliberately ignore the signal to verify the caller's own wait bound.
      return new Promise((resolve, reject) => { complete = resolve; failPending = reject; });
    } },
    intervalMs: 60_000, exportDeadlineMs: 1_000, signal: shutdown.signal,
    writeStatus: value => status.push(value),
  });
  try {
    if (mode.startsWith('timeout_')) {
      await assert.rejects(withSettlementGuard(service), error =>
        error.code === 'anchor_export_timeout' && error.message === 'Audit anchor export failed');
    } else {
      await withSettlementGuard(service);
    }
    assert.equal(childSignal.aborted, true, mode + ': cancellation forwarded');
    assert.equal(iterations, 1, mode + ': no automatic retry');
    assert.deepEqual(status, [], mode + ': no premature status');
    if (mode.endsWith('_resolve')) complete({ status: 'published', envelope: records[0] });
    else failPending(new Error('synthetic-private-late-rejection'));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(status, [], mode + ': late outcome ignored');
    assert.equal(iterations, 1, mode + ': late outcome cannot restart service');
  } finally {
    shutdown.abort();
    complete?.({ status: 'published', envelope: records[0] });
  }
}


// A blocked event loop can delay timer dispatch. The monotonic deadline must
// still reject a success returned after that deadline without accepting it.
let delayedChildSignal;
const delayedReports = [];
await assert.rejects(withSettlementGuard(runAuditAnchorExporterService({
  runtime: { exportOnce: ({ signal: received }) => {
    delayedChildSignal = received;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_100);
    return { status: 'published', envelope: records[0] };
  } },
  intervalMs: 60_000, exportDeadlineMs: 1_000, signal: new AbortController().signal,
  writeStatus: value => delayedReports.push(value),
})), error => error.code === 'anchor_export_timeout');
assert.equal(delayedChildSignal.aborted, true);
assert.deepEqual(delayedReports, []);

// A healthy result still produces one report before an operator stops the loop.
const stopAfterSuccess = new AbortController();
const successfulReports = [];
await runAuditAnchorExporterService({
  runtime: { exportOnce: async () => ({ status: 'already_published', envelope: records[0] }) },
  intervalMs: 60_000, signal: stopAfterSuccess.signal,
  writeStatus: value => { successfulReports.push(value); stopAfterSuccess.abort(); },
});
assert.equal(successfulReports.length, 1);
assert.equal(successfulReports[0].status, 'already_published');
console.log('audit exporter service: pre-abort, queued abort, pending cancel/timeout and late outcomes passed');

console.log('audit anchor exporter runtime: strict config and complete local closure passed');
