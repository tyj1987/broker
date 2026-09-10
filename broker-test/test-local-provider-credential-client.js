import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  createLocalProviderCredentialClient,
  LOCAL_PROVIDER_CREDENTIAL_CONTRACT,
  LocalProviderCredentialError,
} from '../broker/lib/local-provider-credential-client.js';

const NOW = 2_000_000_000_000;
const SOCKET_DIRECTORY = '/run/secret-broker-credentials';
const SOCKET = `${SOCKET_DIRECTORY}/cloudflare.sock`;
const requestInput = {
  operation_id: 'zones.list',
  account_ref: 'cloudflare-primary',
  environment: 'production',
  resource_ref: 'a'.repeat(32),
  signal: new AbortController().signal,
};
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
const expectCode = (code) => (error) =>
  error instanceof LocalProviderCredentialError && error.code === code;

function socketHarness({ response, error, timeout, throwOnConnect } = {}) {
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
      if (error) queueMicrotask(() => socket.emit('error', new Error('canary-socket')));
      else if (timeout) queueMicrotask(() => state.timeoutHandler());
      else
        queueMicrotask(() => {
          if (Array.isArray(response)) {
            for (const chunk of response) socket.emit('data', chunk);
          } else if (response !== undefined) socket.emit('data', response);
          socket.emit('end');
        });
    };
    queueMicrotask(connected);
    return socket;
  };
  return { state, connect };
}

const responseDocument = (overrides = {}) => ({
  version: 1,
  provider: 'cloudflare',
  operation_id: requestInput.operation_id,
  account_ref: requestInput.account_ref,
  environment: requestInput.environment,
  resource_ref: requestInput.resource_ref,
  token: 'unit-provider-token',
  expires_at: new Date(NOW + 60_000).toISOString(),
  ...overrides,
});
const harness = socketHarness({ response: JSON.stringify(responseDocument()) });
const client = createLocalProviderCredentialClient({
  provider: 'cloudflare',
  connect: harness.connect,
  stat: safeStat,
  now: () => NOW,
  processUid: 1000,
  processGroups: [3000],
  timeoutMs: 500,
});
assert.equal(await client.probe(), true);
assert.deepEqual(await client.lease(requestInput), {
  token: 'unit-provider-token',
  expires_at: new Date(NOW + 60_000).toISOString(),
});
assert.equal(harness.state.options.path, SOCKET);
assert.equal(harness.state.timeoutMs, 500);
assert.equal(harness.state.destroyed, true);
assert.deepEqual(JSON.parse(harness.state.payload), {
  version: 1,
  provider: 'cloudflare',
  operation_id: requestInput.operation_id,
  account_ref: requestInput.account_ref,
  environment: requestInput.environment,
  resource_ref: requestInput.resource_ref,
});
assert.doesNotMatch(harness.state.payload, /token|secret|authorization/i);

const dockerHarness = socketHarness({
  response: JSON.stringify({
    version: 1,
    provider: 'docker',
    operation_id: 'repository.tags.list',
    account_ref: 'docker-primary',
    environment: 'production',
    resource_ref: 'tyj1987/broker',
    token: 'unit-docker-token',
    expires_at: new Date(NOW + 60_000).toISOString(),
  }),
});
const dockerClient = createLocalProviderCredentialClient({
  provider: 'docker',
  connect: dockerHarness.connect,
  stat: safeStat,
  now: () => NOW,
  processUid: 1000,
  processGroups: [3000],
});
await dockerClient.lease({
  operation_id: 'repository.tags.list',
  account_ref: 'docker-primary',
  environment: 'production',
  resource_ref: 'tyj1987/broker',
});
assert.equal(dockerHarness.state.options.path, `${SOCKET_DIRECTORY}/docker.sock`);

for (const options of [
  {},
  { provider: 'unknown' },
  { provider: 'cloudflare', connect: null },
  { provider: 'cloudflare', stat: null },
  { provider: 'cloudflare', now: null },
  { provider: 'cloudflare', timeoutMs: 99 },
  { provider: 'cloudflare', timeoutMs: 10_001 },
  { provider: 'cloudflare', processUid: -1 },
  { provider: 'cloudflare', processGroups: [1.5] },
])
  assert.throws(() => createLocalProviderCredentialClient(options), TypeError);

for (const input of [
  null,
  [],
  { ...requestInput, extra: true },
  { ...requestInput, operation_id: '../zones' },
  { ...requestInput, account_ref: '../account' },
  { ...requestInput, environment: 'Production' },
  { ...requestInput, resource_ref: '../resource' },
  { ...requestInput, signal: {} },
])
  await assert.rejects(client.lease(input), expectCode('credential_request_invalid'));

const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  client.lease({ ...requestInput, signal: aborted.signal }),
  expectCode('credential_request_aborted'),
);

for (const response of [
  '{bad-json',
  JSON.stringify(null),
  JSON.stringify(responseDocument({ version: 2 })),
  JSON.stringify(responseDocument({ provider: 'docker' })),
  JSON.stringify(responseDocument({ account_ref: 'other' })),
  JSON.stringify(responseDocument({ resource_ref: 'b'.repeat(32) })),
  JSON.stringify(responseDocument({ token: 'short' })),
  JSON.stringify(responseDocument({ token: 'unsafe\r\ntoken' })),
  JSON.stringify(responseDocument({ expires_at: new Date(NOW).toISOString() })),
  JSON.stringify(responseDocument({ expires_at: new Date(NOW + 300_001).toISOString() })),
  JSON.stringify({ ...responseDocument(), unexpected: true }),
]) {
  const invalidClient = createLocalProviderCredentialClient({
    provider: 'cloudflare',
    connect: socketHarness({ response }).connect,
    stat: safeStat,
    now: () => NOW,
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(
    invalidClient.lease(requestInput),
    expectCode('credential_response_invalid'),
  );
}

for (const [metadata, code] of [
  [null, 'credential_provider_boundary_invalid'],
  [
    { isSocket: () => false, isSymbolicLink: () => false, mode: 0o100660, uid: 2000, gid: 3000 },
    'credential_provider_boundary_invalid',
  ],
  [
    { isSocket: () => true, isSymbolicLink: () => true, mode: 0o140660, uid: 2000, gid: 3000 },
    'credential_provider_boundary_invalid',
  ],
  [
    { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140666, uid: 2000, gid: 3000 },
    'credential_provider_boundary_invalid',
  ],
  [
    { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 1000, gid: 3000 },
    'credential_provider_boundary_invalid',
  ],
]) {
  const boundaryClient = createLocalProviderCredentialClient({
    provider: 'cloudflare',
    stat: async (path) => (path === SOCKET_DIRECTORY ? safeStat(path) : metadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode(code));
}
await assert.rejects(
  createLocalProviderCredentialClient({
    provider: 'cloudflare',
    stat: async () => {
      throw new Error('canary-stat');
    },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('credential_provider_unavailable'),
);

for (const [failure, code] of [
  [{ error: true }, 'credential_provider_unavailable'],
  [{ timeout: true }, 'credential_provider_timeout'],
  [{ throwOnConnect: true }, 'credential_provider_unavailable'],
  [{ response: ['x'.repeat(8192), 'y'] }, 'credential_response_too_large'],
]) {
  const failedClient = createLocalProviderCredentialClient({
    provider: 'cloudflare',
    connect: socketHarness(failure).connect,
    stat: safeStat,
    now: () => NOW,
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(failedClient.lease(requestInput), expectCode(code));
}

const abortHarness = socketHarness({ timeout: true });
const abortClient = createLocalProviderCredentialClient({
  provider: 'cloudflare',
  connect: abortHarness.connect,
  stat: safeStat,
  now: () => NOW,
  processUid: 1000,
  processGroups: [3000],
});
const duringAbort = new AbortController();
const pending = abortClient.lease({ ...requestInput, signal: duringAbort.signal });
queueMicrotask(() => duringAbort.abort());
await assert.rejects(pending, expectCode('credential_request_aborted'));

assert.deepEqual(LOCAL_PROVIDER_CREDENTIAL_CONTRACT, {
  socket_directory: SOCKET_DIRECTORY,
  socket_paths: { cloudflare: SOCKET, docker: `${SOCKET_DIRECTORY}/docker.sock` },
  protocol_version: 1,
  maximum_request_bytes: 4096,
  maximum_response_bytes: 8192,
  maximum_lease_ttl_seconds: 300,
  secret_available_to_agent: false,
});

console.log(
  'local provider credential client: fixed socket, exact lease binding and safe failures passed',
);
