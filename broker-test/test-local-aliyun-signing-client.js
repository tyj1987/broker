import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  createLocalAliyunSigningClient,
  LOCAL_ALIYUN_SIGNING_CONTRACT,
  LocalAliyunSigningError,
} from '../broker/lib/local-aliyun-signing-client.js';

const DIRECTORY = '/run/secret-broker-signer';
const SOCKET = `${DIRECTORY}/aliyun.sock`;
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const input = {
  operation_id: 'ecs.instances.list',
  account_ref: 'aliyun-primary',
  environment: 'production',
  resource_ref: 'primary-ecs-inventory',
  region_id: 'cn-hangzhou',
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  method: 'POST',
  path: '/',
  query: { MaxResults: 20, RegionId: 'cn-hangzhou' },
  signal: new AbortController().signal,
};
const CREDENTIAL_BINDING = 'b'.repeat(43);
const headers = {
  Authorization: `ACS3-HMAC-SHA256 Credential=STS.TEST,SignedHeaders=x,Signature=${'a'.repeat(64)}`,
  host: 'ecs.cn-hangzhou.aliyuncs.com',
  'x-acs-action': 'DescribeInstances',
  'x-acs-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'x-acs-date': '2026-09-11T01:02:03Z',
  'x-acs-security-token': 'temporary-security-token',
  'x-acs-signature-nonce': 'nonce-12345678',
  'x-acs-version': '2014-05-26',
};
const response = JSON.stringify({
  version: 3,
  provider: 'aliyun',
  operation_id: input.operation_id,
  account_ref: input.account_ref,
  environment: input.environment,
  resource_ref: input.resource_ref,
  region_id: input.region_id,
  execution_id: input.execution_id,
  request_binding: input.request_binding,
  credential_binding: CREDENTIAL_BINDING,
  headers,
});
const safeStat = async (path) =>
  path === DIRECTORY
    ? { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040750, uid: 2000, gid: 3000 }
    : { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2000, gid: 3000 };
const expectCode = (code) => (error) =>
  error instanceof LocalAliyunSigningError && error.code === code;

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
    socket.end = (payload) => {
      state.payload = payload;
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
const client = createLocalAliyunSigningClient({
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
  region_id: input.region_id,
  execution_id: input.execution_id,
  request_binding: input.request_binding,
  credential_binding: CREDENTIAL_BINDING,
  headers,
});
assert.equal(harness.state.options.path, SOCKET);
assert.equal(harness.state.timeoutMs, 500);
assert.equal(harness.state.destroyed, true);
const encoded = JSON.parse(harness.state.payload.trim());
assert.deepEqual(encoded, {
  version: 3,
  provider: 'aliyun',
  operation_id: input.operation_id,
  account_ref: input.account_ref,
  environment: input.environment,
  resource_ref: input.resource_ref,
  region_id: input.region_id,
  execution_id: input.execution_id,
  request_binding: input.request_binding,
  method: 'POST',
  path: '/',
  query: input.query,
});
assert.doesNotMatch(harness.state.payload, /AccessKeySecret|SecurityToken|Authorization/);

const authorityInput = {
  ...input,
  operation_id: 'sts.caller-identity.read',
  query: {},
};
const authorityHeaders = {
  ...headers,
  host: 'sts.aliyuncs.com',
  'x-acs-action': 'GetCallerIdentity',
  'x-acs-version': '2015-04-01',
};
const authorityHarness = socketHarness({
  output: JSON.stringify({
    version: 3,
    provider: 'aliyun',
    operation_id: authorityInput.operation_id,
    account_ref: authorityInput.account_ref,
    environment: authorityInput.environment,
    resource_ref: authorityInput.resource_ref,
    region_id: authorityInput.region_id,
    execution_id: authorityInput.execution_id,
    request_binding: authorityInput.request_binding,
    credential_binding: CREDENTIAL_BINDING,
    headers: authorityHeaders,
  }),
});
const authorityClient = createLocalAliyunSigningClient({
  connect: authorityHarness.connect,
  stat: safeStat,
  timeoutMs: 500,
  processUid: 1000,
  processGroups: [3000],
});
assert.equal((await authorityClient.sign(authorityInput)).headers.host, 'sts.aliyuncs.com');
assert.deepEqual(JSON.parse(authorityHarness.state.payload).query, {});

assert.throws(() => createLocalAliyunSigningClient({ connect: null }), TypeError);
assert.throws(() => createLocalAliyunSigningClient({ stat: null }), TypeError);
assert.throws(() => createLocalAliyunSigningClient({ timeoutMs: 99 }), TypeError);
assert.throws(() => createLocalAliyunSigningClient({ timeoutMs: 10_001 }), TypeError);
assert.throws(() => createLocalAliyunSigningClient({ processUid: -1 }), TypeError);
assert.throws(() => createLocalAliyunSigningClient({ processGroups: [1.5] }), TypeError);
for (const changed of [
  null,
  [],
  { ...input, unexpected: true },
  { ...input, operation_id: 'ecs.instances.delete' },
  { ...input, account_ref: '../account' },
  { ...input, environment: 'Production' },
  { ...input, resource_ref: '../inventory' },
  { ...input, region_id: 'https://attacker.example' },
  { ...input, execution_id: 'wrong' },
  { ...input, request_binding: 'wrong' },
  { ...input, method: 'GET' },
  { ...input, path: 'https://attacker.example' },
  { ...input, query: null },
  { ...input, query: { ...input.query, Evil: 'value' } },
  { ...input, query: { ...input.query, RegionId: 'cn-shanghai' } },
  { ...input, query: { ...input.query, MaxResults: 101 } },
  { ...input, query: { ...input.query, NextToken: '../token' } },
  { ...input, signal: {} },
]) {
  await assert.rejects(client.sign(changed), expectCode('aliyun_signing_request_invalid'));
}
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  client.sign({ ...input, signal: aborted.signal }),
  expectCode('aliyun_signing_aborted'),
);

for (const [directoryMetadata, socketMetadata] of [
  [null, await safeStat(SOCKET)],
  [
    { isDirectory: () => false, isSymbolicLink: () => false, mode: 0o040750, uid: 2000, gid: 3000 },
    await safeStat(SOCKET),
  ],
  [
    { isDirectory: () => true, isSymbolicLink: () => true, mode: 0o040750, uid: 2000, gid: 3000 },
    await safeStat(SOCKET),
  ],
  [
    { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o040770, uid: 2000, gid: 3000 },
    await safeStat(SOCKET),
  ],
  [
    await safeStat(DIRECTORY),
    { isSocket: () => false, isSymbolicLink: () => false, mode: 0o100660, uid: 2000, gid: 3000 },
  ],
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
  const boundaryClient = createLocalAliyunSigningClient({
    stat: async (path) => (path === DIRECTORY ? directoryMetadata : socketMetadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('aliyun_signer_boundary_invalid'));
}
await assert.rejects(
  createLocalAliyunSigningClient({
    stat: async () => {
      throw new Error('canary');
    },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('aliyun_signer_unavailable'),
);

for (const output of [
  '{bad-json',
  'null',
  JSON.stringify({ ...JSON.parse(response), version: 1 }),
  JSON.stringify({ ...JSON.parse(response), account_ref: 'other' }),
  JSON.stringify({ ...JSON.parse(response), execution_id: '87654321-1234-4123-8123-123456789abc' }),
  JSON.stringify({ ...JSON.parse(response), request_binding: 'c'.repeat(43) }),
  JSON.stringify({ ...JSON.parse(response), headers: null }),
  JSON.stringify({ ...JSON.parse(response), credential_binding: 'short' }),
  JSON.stringify({ ...JSON.parse(response), extra: 'canary-secret' }),
]) {
  await assert.rejects(
    createLocalAliyunSigningClient({
      connect: socketHarness({ output }).connect,
      stat: safeStat,
      processUid: 1000,
      processGroups: [3000],
    }).sign(input),
    expectCode('aliyun_signing_response_invalid'),
  );
}
await assert.rejects(
  createLocalAliyunSigningClient({
    connect: socketHarness({ output: ['x'.repeat(16 * 1024), 'x'] }).connect,
    stat: safeStat,
    processUid: 1000,
    processGroups: [3000],
  }).sign(input),
  expectCode('aliyun_signing_response_too_large'),
);
for (const [options, code] of [
  [{ error: true }, 'aliyun_signer_unavailable'],
  [{ timeout: true }, 'aliyun_signer_timeout'],
  [{ throwOnConnect: true }, 'aliyun_signer_unavailable'],
]) {
  await assert.rejects(
    createLocalAliyunSigningClient({
      connect: socketHarness(options).connect,
      stat: safeStat,
      processUid: 1000,
      processGroups: [3000],
    }).sign(input),
    expectCode(code),
  );
}
const duringAbortHarness = socketHarness({ timeout: true });
const duringAbortClient = createLocalAliyunSigningClient({
  connect: duringAbortHarness.connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
const duringAbort = new AbortController();
const pending = duringAbortClient.sign({ ...input, signal: duringAbort.signal });
queueMicrotask(() => duringAbort.abort());
await assert.rejects(pending, expectCode('aliyun_signing_aborted'));

assert.deepEqual(LOCAL_ALIYUN_SIGNING_CONTRACT, {
  socket_directory: DIRECTORY,
  socket_path: SOCKET,
  protocol_version: 3,
  supported_operations: ['ecs.instances.list', 'sts.caller-identity.read'],
  maximum_request_bytes: 8192,
  maximum_response_bytes: 16384,
  maximum_timeout_ms: 10000,
  access_key_secret_available_to_broker: false,
  credential_available_to_agent: false,
});

console.log('local aliyun signer: fixed socket, bounded typed protocol and safe failures passed');
