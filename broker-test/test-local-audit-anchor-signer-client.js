import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  LOCAL_AUDIT_ANCHOR_SIGNER_CONTRACT,
  LocalAuditAnchorSignerError,
  createLocalAuditAnchorSignerClient,
} from '../broker/lib/local-audit-anchor-signer-client.js';
import {
  ANCHOR_PURPOSE,
  createAuditAnchorRequest,
  createAuditAnchorSigningInput,
} from '../broker/lib/audit-anchor.js';

const SOCKET_DIRECTORY = '/run/secret-broker-audit-anchor';
const SOCKET_PATH = `${SOCKET_DIRECTORY}/signer.sock`;
const algorithm = 'ed25519';
const keyId = 'audit-anchor-key-2026-01';
const signature = Buffer.alloc(64, 7).toString('base64url');
const anchor = createAuditAnchorRequest(
  { files: 2, count: 7, lastHash: 'a'.repeat(64) },
  { streamId: 'broker-production', sequence: 1, now: () => 1_900_000_000_000 },
);
const expectCode = (code) =>
  (error) => error instanceof LocalAuditAnchorSignerError && error.code === code;
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

function response(overrides = {}) {
  return JSON.stringify({
    version: 2,
    purpose: ANCHOR_PURPOSE,
    algorithm,
    key_id: keyId,
    payload_digest: anchor.payload_digest,
    signature,
    ...overrides,
  });
}

function socketHarness({ body = response(), error = false, timeout = false, throwOnConnect = false } = {}) {
  const state = {};
  const connect = (options, connected) => {
    if (throwOnConnect) throw new Error('connect detail must not escape');
    state.options = options;
    const socket = new EventEmitter();
    socket.setTimeout = (value, handler) => {
      state.timeoutMs = value;
      state.timeoutHandler = handler;
    };
    socket.destroy = () => { state.destroyed = true; };
    socket.end = (payload) => {
      state.payload = payload;
      if (error) queueMicrotask(() => socket.emit('error', new Error('socket detail')));
      else if (timeout) queueMicrotask(() => state.timeoutHandler());
      else {
        queueMicrotask(() => {
          for (const chunk of Array.isArray(body) ? body : [body]) socket.emit('data', chunk);
          socket.emit('end');
        });
      }
    };
    queueMicrotask(connected);
    return socket;
  };
  return { connect, state };
}

const harness = socketHarness();
const client = createLocalAuditAnchorSignerClient({
  algorithm,
  keyId,
  connect: harness.connect,
  stat: safeStat,
  timeoutMs: 500,
  processUid: 1000,
  processGroups: [3000],
});
assert.equal(await client.probe(), true);
assert.deepEqual(await client.signAnchor(anchor), { algorithm, key_id: keyId, value: signature });
assert.equal(harness.state.options.path, SOCKET_PATH);
assert.equal(harness.state.timeoutMs, 500);
assert.equal(harness.state.destroyed, true);
const wireRequest = JSON.parse(harness.state.payload.trim());
assert.deepEqual(wireRequest, {
  version: 2,
  purpose: ANCHOR_PURPOSE,
  algorithm,
  key_id: keyId,
  stream_id: anchor.payload.stream_id,
  sequence: anchor.payload.sequence,
  previous_anchor_digest: anchor.payload.previous_anchor_digest,
  payload_digest: anchor.payload_digest,
  signing_input: createAuditAnchorSigningInput(anchor, { algorithm, keyId }).toString('base64url'),
});
assert.doesNotMatch(harness.state.payload, /private_key|authorization|credential|audit_event/i);

for (const options of [
  { algorithm: 'unknown', keyId },
  { algorithm, keyId: '../key' },
  { algorithm, keyId, connect: null },
  { algorithm, keyId, stat: null },
  { algorithm, keyId, timeoutMs: 99 },
  { algorithm, keyId, timeoutMs: 10_001 },
  { algorithm, keyId, processUid: -1 },
  { algorithm, keyId, processGroups: [1.5] },
]) {
  assert.throws(() => createLocalAuditAnchorSignerClient(options), TypeError);
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
  const boundaryClient = createLocalAuditAnchorSignerClient({
    algorithm,
    keyId,
    stat: async (path) => (path === SOCKET_DIRECTORY ? directoryMetadata : safeStat(path)),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('anchor_signer_boundary_invalid'));
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
  const boundaryClient = createLocalAuditAnchorSignerClient({
    algorithm,
    keyId,
    stat: async (path) => (path === SOCKET_DIRECTORY ? safeStat(path) : socketMetadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('anchor_signer_boundary_invalid'));
}

await assert.rejects(
  createLocalAuditAnchorSignerClient({
    algorithm,
    keyId,
    stat: async () => { throw new Error('stat detail must not escape'); },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('anchor_signer_unavailable'),
);
await assert.rejects(
  createLocalAuditAnchorSignerClient({
    algorithm, keyId, stat: safeStat, processUid: null, processGroups: [3000],
  }).probe(),
  expectCode('anchor_signer_boundary_invalid'),
);

await assert.rejects(client.signAnchor(null), expectCode('anchor_signer_request_invalid'));
await assert.rejects(
  client.signAnchor(anchor, { signal: {} }),
  expectCode('anchor_signer_request_invalid'),
);
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  client.signAnchor(anchor, { signal: aborted.signal }),
  expectCode('anchor_signer_aborted'),
);

for (const body of [
  '{invalid-json',
  JSON.stringify(null),
  response({ version: 1 }),
  response({ purpose: 'another-purpose' }),
  response({ algorithm: 'ecdsa-p256-sha256' }),
  response({ key_id: 'another-key' }),
  response({ payload_digest: 'b'.repeat(64) }),
  response({ signature: '*' }),
  JSON.stringify({ ...JSON.parse(response()), extra: true }),
]) {
  const invalidClient = createLocalAuditAnchorSignerClient({
    algorithm,
    keyId,
    connect: socketHarness({ body }).connect,
    stat: safeStat,
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(
    invalidClient.signAnchor(anchor),
    expectCode('anchor_signer_response_invalid'),
  );
}

const oversized = createLocalAuditAnchorSignerClient({
  algorithm,
  keyId,
  connect: socketHarness({ body: ['x'.repeat(8192), 'y'] }).connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
await assert.rejects(
  oversized.signAnchor(anchor),
  expectCode('anchor_signer_response_too_large'),
);
for (const [harnessOptions, code] of [
  [{ error: true }, 'anchor_signer_unavailable'],
  [{ timeout: true }, 'anchor_signer_timeout'],
  [{ throwOnConnect: true }, 'anchor_signer_unavailable'],
]) {
  const failingClient = createLocalAuditAnchorSignerClient({
    algorithm,
    keyId,
    connect: socketHarness(harnessOptions).connect,
    stat: safeStat,
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(failingClient.signAnchor(anchor), expectCode(code));
}

const abortHarness = socketHarness({ timeout: true });
const abortClient = createLocalAuditAnchorSignerClient({
  algorithm,
  keyId,
  connect: abortHarness.connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
const duringAbort = new AbortController();
const pending = abortClient.signAnchor(anchor, { signal: duringAbort.signal });
queueMicrotask(() => duringAbort.abort());
await assert.rejects(pending, expectCode('anchor_signer_aborted'));

assert.deepEqual(LOCAL_AUDIT_ANCHOR_SIGNER_CONTRACT, {
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET_PATH,
  protocol_version: 2,
  maximum_request_bytes: 8192,
  maximum_response_bytes: 8192,
  maximum_timeout_ms: 10_000,
  private_key_available_to_broker: false,
  audit_content_available_to_signer: false,
});

console.log('local audit anchor signer: fixed socket, metadata binding and safe failures passed');
