import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  LOCAL_AUDIT_ANCHOR_STORE_CONTRACT,
  LocalAuditAnchorStoreError,
  createLocalAuditAnchorStoreClient,
} from '../broker/lib/local-audit-anchor-store-client.js';
import {
  attachAuditAnchorSignature,
  createAuditAnchorRequest,
} from '../broker/lib/audit-anchor.js';

const STREAM_ID = 'broker-production';
const SOCKET_DIRECTORY = '/run/secret-broker-audit-store';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/store.sock`;
const KEY_ID = 'audit-anchor-key-2026-01';
const signature = {
  algorithm: 'ecdsa-p256-sha256',
  key_id: KEY_ID,
  value: Buffer.alloc(64, 7).toString('base64url'),
};
const first = attachAuditAnchorSignature(
  createAuditAnchorRequest(
    { files: 1, count: 4, lastHash: 'a'.repeat(64) },
    { streamId: STREAM_ID, sequence: 1, now: () => 1_900_000_000_000 },
  ),
  signature,
);
const second = attachAuditAnchorSignature(
  createAuditAnchorRequest(
    { files: 1, count: 8, lastHash: 'b'.repeat(64) },
    {
      streamId: STREAM_ID,
      sequence: 2,
      previousAnchorDigest: first.payload_digest,
      now: () => 1_900_000_001_000,
    },
  ),
  signature,
);
const expectCode = (code) => (error) =>
  error instanceof LocalAuditAnchorStoreError && error.code === code;
const safeStat = async (path) =>
  path === SOCKET_DIRECTORY
    ? {
        isDirectory: () => true,
        isSymbolicLink: () => false,
        mode: 0o040750,
        uid: 2000,
        gid: 3000,
      }
    : {
        isSocket: () => true,
        isSymbolicLink: () => false,
        mode: 0o140660,
        uid: 2000,
        gid: 3000,
      };

function success(request, result) {
  return `${JSON.stringify({
    version: 1,
    purpose: 'secret-broker.audit-anchor-store',
    request_id: request.request_id,
    operation: request.operation,
    status: 'ok',
    stream_id: STREAM_ID,
    result,
  })}\n`;
}

function socketHarness({
  respond,
  error = false,
  timeout = false,
  throwOnConnect = false,
  onConnect,
} = {}) {
  const state = { requests: [] };
  const connect = (options, connected) => {
    if (throwOnConnect) throw new Error('connect detail must not escape');
    state.options = options;
    const socket = new EventEmitter();
    socket.setTimeout = (value, handler) => {
      state.timeoutMs = value;
      state.timeoutHandler = handler;
    };
    socket.destroy = () => {
      state.destroyed = true;
    };
    socket.end = (payload) => {
      state.payload = payload;
      const request = JSON.parse(payload.trim());
      state.requests.push(request);
      if (error) queueMicrotask(() => socket.emit('error', new Error('socket detail')));
      else if (timeout) queueMicrotask(() => state.timeoutHandler());
      else {
        const body = respond?.(request) ?? success(request, {});
        queueMicrotask(() => {
          for (const chunk of Array.isArray(body) ? body : [body]) socket.emit('data', chunk);
          socket.emit('end');
        });
      }
    };
    onConnect?.();
    queueMicrotask(connected);
    return socket;
  };
  return { connect, state };
}

function clientFor(harness, overrides = {}) {
  return createLocalAuditAnchorStoreClient({
    streamId: STREAM_ID,
    connect: harness.connect,
    stat: safeStat,
    timeoutMs: 500,
    createRequestId: () => 'req-fixed-1',
    processUid: 1000,
    processGroups: [3000],
    ...overrides,
  });
}

const harness = socketHarness({
  respond: (request) => {
    switch (request.operation) {
      case 'read_head':
        return success(request, { current: second, previous: first });
      case 'publish':
        return success(request, { status: 'published' });
      case 'read_page':
        return success(request, {
          after_sequence: request.parameters.after_sequence,
          through_sequence: request.parameters.through_sequence,
          anchors: [first, second].slice(request.parameters.after_sequence),
        });
      case 'health':
        return success(request, {
          status: 'ready',
          lock_contract: 'verified',
          mirror_state: 'in_sync',
          common_sequence: 2,
          reason_code: 'ok',
        });
      default:
        throw new Error('unexpected operation');
    }
  },
});
const client = clientFor(harness);
assert.equal(await client.probe(), true);
assert.deepEqual(await client.readHead({ streamId: STREAM_ID }), {
  current: second,
  previous: first,
});
assert.deepEqual(
  await client.publish({
    streamId: STREAM_ID,
    expectedPreviousDigest: first.payload_digest,
    envelope: second,
  }),
  { status: 'published' },
);
assert.deepEqual(
  await client.readPage({
    streamId: STREAM_ID,
    afterSequence: 0,
    throughSequence: 2,
    limit: 100,
  }),
  { anchors: [first, second] },
);
assert.deepEqual(await client.health({ streamId: STREAM_ID }), {
  status: 'ready',
  lock_contract: 'verified',
  mirror_state: 'in_sync',
  common_sequence: 2,
  reason_code: 'ok',
});
assert.equal(harness.state.options.path, SOCKET_PATH);
assert.equal(harness.state.timeoutMs, 500);
assert.equal(harness.state.destroyed, true);
assert.equal(harness.state.requests[2].parameters.limit, 32);
assert.equal(harness.state.requests[0].purpose, 'secret-broker.audit-anchor-store');
assert.equal(harness.state.requests[0].version, 1);
assert.equal(harness.state.requests[0].request_id, 'req-fixed-1');
assert.doesNotMatch(harness.state.payload, /access_key|private_key|authorization|credential/i);

const conflictHarness = socketHarness({
  respond: (request) => success(request, { status: 'conflict', current: second }),
});
assert.deepEqual(
  await clientFor(conflictHarness).publish({
    streamId: STREAM_ID,
    expectedPreviousDigest: first.payload_digest,
    envelope: second,
  }),
  { status: 'conflict', current: second },
);

for (const options of [
  { streamId: '' },
  { streamId: '../stream' },
  { streamId: STREAM_ID, connect: null },
  { streamId: STREAM_ID, stat: null },
  { streamId: STREAM_ID, createRequestId: null },
  { streamId: STREAM_ID, timeoutMs: 99 },
  { streamId: STREAM_ID, timeoutMs: 60_001 },
  { streamId: STREAM_ID, processUid: -1 },
  { streamId: STREAM_ID, processGroups: [1.5] },
]) {
  assert.throws(() => createLocalAuditAnchorStoreClient(options), TypeError);
}

for (const directoryMetadata of [
  null,
  { isDirectory: () => false, isSymbolicLink: () => false, mode: 0o040750, uid: 2000, gid: 3000 },
  { isDirectory: () => true, isSymbolicLink: () => true, mode: 0o040750, uid: 2000, gid: 3000 },
  { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040770, uid: 2000, gid: 3000 },
  { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040740, uid: 2000, gid: 3000 },
  { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040750, uid: 1000, gid: 3000 },
  { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040750, uid: 2000, gid: 3001 },
]) {
  const boundaryClient = createLocalAuditAnchorStoreClient({
    streamId: STREAM_ID,
    stat: async (path) => (path === SOCKET_DIRECTORY ? directoryMetadata : safeStat(path)),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('anchor_store_boundary_invalid'));
}

for (const socketMetadata of [
  null,
  { isSocket: () => false, isSymbolicLink: () => false, mode: 0o100660, uid: 2000, gid: 3000 },
  { isSocket: () => true, isSymbolicLink: () => true, mode: 0o140660, uid: 2000, gid: 3000 },
  { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140666, uid: 2000, gid: 3000 },
  { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 1000, gid: 3000 },
  { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2001, gid: 3000 },
  { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2000, gid: 3001 },
  { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140640, uid: 2000, gid: 3000 },
]) {
  const boundaryClient = createLocalAuditAnchorStoreClient({
    streamId: STREAM_ID,
    stat: async (path) => (path === SOCKET_DIRECTORY ? safeStat(path) : socketMetadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('anchor_store_boundary_invalid'));
}

await assert.rejects(
  createLocalAuditAnchorStoreClient({
    streamId: STREAM_ID,
    stat: async () => {
      throw new Error('stat detail must not escape');
    },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('anchor_store_unavailable'),
);

for (const invoke of [
  () => client.readHead({ streamId: 'other' }),
  () => client.publish({ streamId: STREAM_ID, expectedPreviousDigest: 'bad', envelope: second }),
  () =>
    client.publish({
      streamId: STREAM_ID,
      expectedPreviousDigest: 'c'.repeat(64),
      envelope: second,
    }),
  () => client.readPage({ streamId: STREAM_ID, afterSequence: 2, throughSequence: 2, limit: 1 }),
  () => client.readPage({ streamId: STREAM_ID, afterSequence: 0, throughSequence: 2, limit: 1001 }),
  () => client.health({ streamId: 'other' }),
]) {
  await assert.rejects(invoke(), expectCode('anchor_store_request_invalid'));
}

const invalidEnvelope = structuredClone(second);
invalidEnvelope.signature.value = '*';
await assert.rejects(
  client.publish({
    streamId: STREAM_ID,
    expectedPreviousDigest: first.payload_digest,
    envelope: invalidEnvelope,
  }),
  expectCode('anchor_store_envelope_invalid'),
);
for (const mutate of [
  (value) => {
    value.payload.captured_at = null;
  },
  (value) => {
    value.payload.chain_head = 'bad';
  },
  (value) => {
    value.payload.event_count = -1;
  },
  (value) => {
    value.payload.file_count = Number.MAX_SAFE_INTEGER + 1;
  },
  (value) => {
    value.payload.previous_anchor_digest = 'bad';
  },
  (value) => {
    value.payload_digest = 'bad';
  },
  (value) => {
    value.signature.key_id = '../key';
  },
]) {
  const malformed = structuredClone(second);
  mutate(malformed);
  await assert.rejects(
    client.publish({
      streamId: STREAM_ID,
      expectedPreviousDigest: first.payload_digest,
      envelope: malformed,
    }),
    expectCode('anchor_store_envelope_invalid'),
  );
}

const errorHarness = socketHarness({
  respond: (request) =>
    `${JSON.stringify({
      version: 1,
      purpose: 'secret-broker.audit-anchor-store',
      request_id: request.request_id,
      operation: request.operation,
      status: 'error',
      error_code: 'store_unavailable',
    })}\n`,
});
await assert.rejects(
  clientFor(errorHarness).readHead({ streamId: STREAM_ID }),
  expectCode('anchor_store_unavailable'),
);

for (const body of [
  '{invalid-json\n',
  'null\n',
  '{}\n',
  `${JSON.stringify({ version: 1, purpose: 'other' })}\n`,
  `${JSON.stringify({
    version: 1,
    purpose: 'secret-broker.audit-anchor-store',
    request_id: 'wrong',
    operation: 'read_head',
    status: 'ok',
    stream_id: STREAM_ID,
    result: { current: null, previous: null },
  })}\n`,
  success(
    { request_id: 'req-fixed-1', operation: 'read_head' },
    { current: null, previous: first },
  ),
  success(
    { request_id: 'req-fixed-1', operation: 'health' },
    {
      status: 'ready',
      lock_contract: 'verified',
      mirror_state: 'lagging',
      common_sequence: 2,
      reason_code: 'ok',
    },
  ),
  `${success({ request_id: 'req-fixed-1', operation: 'read_head' }, { current: null, previous: null })}\n`,
]) {
  const invalidClient = clientFor(socketHarness({ respond: () => body }));
  const operation = body.includes('"operation":"health"') ? 'health' : 'readHead';
  await assert.rejects(
    operation === 'health'
      ? invalidClient.health({ streamId: STREAM_ID })
      : invalidClient.readHead({ streamId: STREAM_ID }),
    expectCode('anchor_store_response_invalid'),
  );
}

for (const [method, result] of [
  ['publish', { status: 'unknown' }],
  ['publish', { status: 'conflict', current: first }],
  ['readPage', { after_sequence: 1, through_sequence: 2, anchors: [first] }],
  ['readPage', { after_sequence: 0, through_sequence: 2, anchors: [second] }],
  [
    'health',
    {
      status: 'repair_required',
      lock_contract: 'verified',
      mirror_state: 'in_sync',
      common_sequence: 2,
      reason_code: 'mirror_lag',
    },
  ],
]) {
  const invalidClient = clientFor(
    socketHarness({ respond: (request) => success(request, result) }),
  );
  const invocation =
    method === 'publish'
      ? invalidClient.publish({
          streamId: STREAM_ID,
          expectedPreviousDigest: first.payload_digest,
          envelope: second,
        })
      : method === 'readPage'
        ? invalidClient.readPage({
            streamId: STREAM_ID,
            afterSequence: 0,
            throughSequence: 2,
            limit: 2,
          })
        : invalidClient.health({ streamId: STREAM_ID });
  await assert.rejects(invocation, expectCode('anchor_store_response_invalid'));
}

const oversized = clientFor(socketHarness({ respond: () => ['x'.repeat(576 * 1024), 'y'] }));
await assert.rejects(
  oversized.readHead({ streamId: STREAM_ID }),
  expectCode('anchor_store_response_too_large'),
);
for (const [harnessOptions, code] of [
  [{ error: true }, 'anchor_store_unavailable'],
  [{ timeout: true }, 'anchor_store_timeout'],
  [{ throwOnConnect: true }, 'anchor_store_unavailable'],
]) {
  const failingClient = clientFor(socketHarness(harnessOptions));
  await assert.rejects(failingClient.readHead({ streamId: STREAM_ID }), expectCode(code));
}

const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  client.readHead({ streamId: STREAM_ID, signal: aborted.signal }),
  expectCode('anchor_store_aborted'),
);
await assert.rejects(
  client.readHead({ streamId: STREAM_ID, signal: {} }),
  expectCode('anchor_store_request_invalid'),
);

const probeAbortHarness = socketHarness();
const probeAbortController = new AbortController();
let probeStatCalls = 0;
const probeAbortClient = clientFor(probeAbortHarness, {
  stat: async (path) => {
    probeStatCalls += 1;
    if (probeStatCalls === 1) probeAbortController.abort();
    return safeStat(path);
  },
});
await assert.rejects(
  probeAbortClient.readHead({ streamId: STREAM_ID, signal: probeAbortController.signal }),
  expectCode('anchor_store_aborted'),
);
assert.equal(probeAbortHarness.state.payload, undefined);

const connectAbortController = new AbortController();
const connectAbortHarness = socketHarness({
  onConnect: () => connectAbortController.abort(),
});
await assert.rejects(
  clientFor(connectAbortHarness).readHead({
    streamId: STREAM_ID,
    signal: connectAbortController.signal,
  }),
  expectCode('anchor_store_aborted'),
);
assert.equal(connectAbortHarness.state.payload, undefined);

const abortHarness = socketHarness({ timeout: true });
const duringAbort = new AbortController();
const pending = clientFor(abortHarness).readHead({
  streamId: STREAM_ID,
  signal: duringAbort.signal,
});
queueMicrotask(() => duringAbort.abort());
await assert.rejects(pending, expectCode('anchor_store_aborted'));

assert.deepEqual(LOCAL_AUDIT_ANCHOR_STORE_CONTRACT, {
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: 1,
  purpose: 'secret-broker.audit-anchor-store',
  maximum_request_bytes: 24 * 1024,
  maximum_response_bytes: 576 * 1024,
  maximum_envelope_bytes: 16 * 1024,
  maximum_wire_page_size: 32,
  maximum_timeout_ms: 60_000,
  provider_credentials_available_to_client: false,
  retention_mutation_available_to_client: false,
  deletion_available_to_client: false,
});

console.log(
  'local audit anchor store: fixed socket, role-safe protocol and bounded responses passed',
);
