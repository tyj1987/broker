import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

import {
  createLocalTencentSigningClient,
  LOCAL_TENCENT_SIGNING_CONTRACT,
  LocalTencentSigningError,
} from '../broker/lib/local-tencent-signing-client.js';

const DIRECTORY = '/run/secret-broker-signer';
const SOCKET = `${DIRECTORY}/tencent.sock`;
const payload = JSON.stringify({ Limit: 20, Offset: 0 });
const input = {
  operation_id: 'cvm.instances.list',
  account_ref: 'tencent-primary',
  environment: 'production',
  resource_ref: 'primary-cvm-inventory',
  region: 'ap-singapore',
  execution_id: '12345678-1234-4123-8123-123456789abc',
  request_binding: 'a'.repeat(43),
  method: 'POST',
  path: '/',
  payload,
  payload_sha256: createHash('sha256').update(payload).digest('hex'),
  signal: new AbortController().signal,
};
const headers = { Authorization: 'redacted-in-test', 'x-tc-token': 'temporary-token' };
const response = JSON.stringify({
  version: 1,
  provider: 'tencent',
  operation_id: input.operation_id,
  account_ref: input.account_ref,
  environment: input.environment,
  resource_ref: input.resource_ref,
  region: input.region,
  execution_id: input.execution_id,
  request_binding: input.request_binding,
  payload_sha256: input.payload_sha256,
  headers,
});
const safeStat = async (path) =>
  path === DIRECTORY
    ? { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040750, uid: 2000, gid: 3000 }
    : { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2000, gid: 3000 };
const expectCode = (code) => (error) =>
  error instanceof LocalTencentSigningError && error.code === code;

function socketHarness({
  output = response,
  error = false,
  timeout = false,
  throwOnConnect = false,
} = {}) {
  const state = {};
  const connect = (options, connected) => {
    if (throwOnConnect) throw new Error('canary-connect');
    state.options = options;
    const socket = new EventEmitter();
    socket.setTimeout = (value, handler) => {
      state.timeoutMs = value;
      state.timeoutHandler = handler;
    };
    socket.destroy = () => {
      state.destroyed = true;
    };
    socket.end = (value) => {
      state.payload = value;
      queueMicrotask(() => {
        if (error) socket.emit('error', new Error('canary-socket'));
        else if (timeout) state.timeoutHandler();
        else {
          for (const chunk of Array.isArray(output) ? output : [output]) socket.emit('data', chunk);
          socket.emit('end');
        }
      });
    };
    queueMicrotask(connected);
    return socket;
  };
  return { state, connect };
}

const harness = socketHarness();
const client = createLocalTencentSigningClient({
  connect: harness.connect,
  stat: safeStat,
  timeoutMs: 500,
  processUid: 1000,
  processGroups: [3000],
});
assert.equal(await client.probe(), true);
assert.deepEqual(await client.sign(input), {
  account_ref: input.account_ref,
  environment: input.environment,
  resource_ref: input.resource_ref,
  region: input.region,
  execution_id: input.execution_id,
  request_binding: input.request_binding,
  payload_sha256: input.payload_sha256,
  headers,
});
assert.equal(harness.state.options.path, SOCKET);
assert.equal(harness.state.timeoutMs, 500);
assert.equal(harness.state.destroyed, true);
const encoded = JSON.parse(harness.state.payload.trim());
assert.equal(encoded.provider, 'tencent');
assert.equal(encoded.payload, payload);
assert.equal(encoded.execution_id, input.execution_id);
assert.equal(encoded.request_binding, input.request_binding);
assert.doesNotMatch(harness.state.payload, /SecretKey|X-TC-Token|Authorization/);

assert.throws(() => createLocalTencentSigningClient({ connect: null }), TypeError);
assert.throws(() => createLocalTencentSigningClient({ stat: null }), TypeError);
assert.throws(() => createLocalTencentSigningClient({ timeoutMs: 99 }), TypeError);
assert.throws(() => createLocalTencentSigningClient({ timeoutMs: 10_001 }), TypeError);
assert.throws(() => createLocalTencentSigningClient({ processUid: -1 }), TypeError);
assert.throws(() => createLocalTencentSigningClient({ processGroups: [1.5] }), TypeError);
for (const changed of [
  null,
  [],
  { ...input, unexpected: true },
  { ...input, operation_id: 'cvm.instances.delete' },
  { ...input, account_ref: '../account' },
  { ...input, environment: 'Production' },
  { ...input, resource_ref: '../inventory' },
  { ...input, region: 'https://attacker.example' },
  { ...input, execution_id: 'bad' },
  { ...input, request_binding: 'bad' },
  { ...input, method: 'GET' },
  { ...input, path: 'https://attacker.example' },
  { ...input, payload: '{bad' },
  { ...input, payload: JSON.stringify({ Limit: 20, Offset: 0, Extra: true }) },
  { ...input, payload: JSON.stringify({ Offset: 0, Limit: 20 }) },
  { ...input, payload: JSON.stringify({ Limit: 0, Offset: 0 }) },
  { ...input, payload: JSON.stringify({ Limit: 20, Offset: 10_001 }) },
  { ...input, payload_sha256: 'bad' },
  { ...input, signal: {} },
]) {
  await assert.rejects(client.sign(changed), expectCode('tencent_signing_request_invalid'));
}
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  client.sign({ ...input, signal: aborted.signal }),
  expectCode('tencent_signing_aborted'),
);

for (const [directoryMetadata, socketMetadata] of [
  [null, await safeStat(SOCKET)],
  [{ isDirectory: () => false, mode: 0o040750, uid: 2000, gid: 3000 }, await safeStat(SOCKET)],
  [
    { isDirectory: () => true, isSymbolicLink: () => true, mode: 0o040750, uid: 2000, gid: 3000 },
    await safeStat(SOCKET),
  ],
  [
    { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040770, uid: 2000, gid: 3000 },
    await safeStat(SOCKET),
  ],
  [await safeStat(DIRECTORY), { isSocket: () => false, mode: 0o100660, uid: 2000, gid: 3000 }],
  [
    await safeStat(DIRECTORY),
    { isSocket: () => true, isSymbolicLink: () => true, mode: 0o140660, uid: 2000, gid: 3000 },
  ],
  [
    await safeStat(DIRECTORY),
    { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140666, uid: 2000, gid: 3000 },
  ],
  [
    await safeStat(DIRECTORY),
    { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 1000, gid: 3000 },
  ],
]) {
  const boundaryClient = createLocalTencentSigningClient({
    stat: async (path) => (path === DIRECTORY ? directoryMetadata : socketMetadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('tencent_signer_boundary_invalid'));
}
await assert.rejects(
  createLocalTencentSigningClient({
    stat: async () => {
      throw new Error('canary');
    },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('tencent_signer_unavailable'),
);

for (const output of [
  '{bad-json',
  'null',
  JSON.stringify({ ...JSON.parse(response), version: 2 }),
  JSON.stringify({ ...JSON.parse(response), execution_id: 'other' }),
  JSON.stringify({ ...JSON.parse(response), payload_sha256: 'b'.repeat(64) }),
  JSON.stringify({ ...JSON.parse(response), headers: null }),
  JSON.stringify({ ...JSON.parse(response), extra: 'canary-secret' }),
]) {
  await assert.rejects(
    createLocalTencentSigningClient({
      connect: socketHarness({ output }).connect,
      stat: safeStat,
      processUid: 1000,
      processGroups: [3000],
    }).sign(input),
    expectCode('tencent_signing_response_invalid'),
  );
}
await assert.rejects(
  createLocalTencentSigningClient({
    connect: socketHarness({ output: ['x'.repeat(16 * 1024), 'x'] }).connect,
    stat: safeStat,
    processUid: 1000,
    processGroups: [3000],
  }).sign(input),
  expectCode('tencent_signing_response_too_large'),
);
for (const [options, code] of [
  [{ error: true }, 'tencent_signer_unavailable'],
  [{ timeout: true }, 'tencent_signer_timeout'],
  [{ throwOnConnect: true }, 'tencent_signer_unavailable'],
]) {
  await assert.rejects(
    createLocalTencentSigningClient({
      connect: socketHarness(options).connect,
      stat: safeStat,
      processUid: 1000,
      processGroups: [3000],
    }).sign(input),
    expectCode(code),
  );
}

assert.deepEqual(LOCAL_TENCENT_SIGNING_CONTRACT, {
  socket_directory: DIRECTORY,
  socket_path: SOCKET,
  protocol_version: 1,
  supported_operations: ['cvm.instances.list'],
  maximum_request_bytes: 16384,
  maximum_response_bytes: 16384,
  maximum_timeout_ms: 10000,
  secret_key_available_to_broker: false,
  credential_available_to_agent: false,
});

console.log('local tencent signer: fixed socket, execution binding and safe failures passed');
