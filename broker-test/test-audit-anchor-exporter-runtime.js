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
assert.deepEqual(log, [
  {
    status: 'published',
    stream_id: 'production-audit',
    sequence: 1,
    payload_digest: records[0].payload_digest,
  },
]);

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

console.log('audit anchor exporter runtime: strict config and complete local closure passed');
