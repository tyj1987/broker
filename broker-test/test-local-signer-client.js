import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  createLocalSignerClient,
  LOCAL_SIGNER_CONTRACT,
  LocalSignerError,
} from '../broker/lib/local-signer-client.js';

const SOCKET = '/run/secret-broker-signer/github.sock';
const SOCKET_DIRECTORY = '/run/secret-broker-signer';
const signature = Buffer.alloc(256, 7);
const validInput = {
  algorithm: 'RS256',
  signing_input: `${'a'.repeat(20)}.${'b'.repeat(20)}`,
  account_ref: 'github-primary',
  environment: 'production',
  client_id: 'Iv1.runtime-test',
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
const expectCode = (code) => (error) => error instanceof LocalSignerError && error.code === code;

function socketHarness({ response, error, timeout = false, throwOnConnect = false } = {}) {
  const state = {};
  const connect = (options, connected) => {
    if (throwOnConnect) throw new Error('canary-connect-error');
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
      if (error) queueMicrotask(() => socket.emit('error', new Error('canary-socket-error')));
      else if (timeout) queueMicrotask(() => state.timeoutHandler());
      else {
        queueMicrotask(() => {
          if (Array.isArray(response)) {
            for (const chunk of response) socket.emit('data', chunk);
          } else if (response !== undefined) socket.emit('data', response);
          socket.emit('end');
        });
      }
    };
    queueMicrotask(connected);
    return socket;
  };
  return { state, connect };
}

const successHarness = socketHarness({
  response: JSON.stringify({ version: 1, signature: signature.toString('base64url') }),
});
const client = createLocalSignerClient({
  connect: successHarness.connect,
  stat: safeStat,
  timeoutMs: 500,
  processUid: 1000,
  processGroups: [3000],
});
assert.equal(await client.probe(), true);
const signed = await client.sign(validInput);
assert.deepEqual(signed, signature);
assert.equal(successHarness.state.options.path, SOCKET);
assert.equal(successHarness.state.timeoutMs, 500);
assert.equal(successHarness.state.destroyed, true);
const request = JSON.parse(successHarness.state.payload.trim());
assert.deepEqual(request, {
  version: 1,
  algorithm: 'RS256',
  signing_input: validInput.signing_input,
  account_ref: 'github-primary',
  environment: 'production',
  client_id: 'Iv1.runtime-test',
});
assert.doesNotMatch(successHarness.state.payload, /private|secret|token|authorization/i);

assert.throws(() => createLocalSignerClient({ socketPath: '/tmp/signer.sock' }), TypeError);
assert.throws(() => createLocalSignerClient({ connect: null }), TypeError);
assert.throws(() => createLocalSignerClient({ stat: null }), TypeError);
assert.throws(() => createLocalSignerClient({ processUid: -1 }), TypeError);
assert.throws(() => createLocalSignerClient({ processGroups: [1.5] }), TypeError);
for (const timeoutMs of [99, 10_001, 1.5]) {
  assert.throws(() => createLocalSignerClient({ timeoutMs }), TypeError);
}

for (const [metadata, code] of [
  [null, 'signer_boundary_invalid'],
  [{ isSocket: () => false, isSymbolicLink: () => false, mode: 0o100660, uid: 2000, gid: 3000 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => true, mode: 0o140660, uid: 2000, gid: 3000 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => false, mode: 0o140666, uid: 2000, gid: 3000 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 1000, gid: 3000 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2001, gid: 3000 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660, uid: 2000, gid: 3001 }, 'signer_boundary_invalid'],
  [{ isSocket: () => true, isSymbolicLink: () => false, mode: 0o140640, uid: 2000, gid: 3000 }, 'signer_boundary_invalid'],
]) {
  const boundaryClient = createLocalSignerClient({
    stat: async (path) => (path === SOCKET_DIRECTORY ? safeStat(path) : metadata),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode(code));
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
  const boundaryClient = createLocalSignerClient({
    stat: async (path) => (path === SOCKET_DIRECTORY ? directoryMetadata : safeStat(path)),
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(boundaryClient.probe(), expectCode('signer_boundary_invalid'));
}
await assert.rejects(
  createLocalSignerClient({
    stat: async () => { throw new Error('canary-stat'); },
    processUid: 1000,
    processGroups: [3000],
  }).probe(),
  expectCode('signer_unavailable'),
);
await assert.rejects(
  createLocalSignerClient({ stat: safeStat, processUid: null, processGroups: [3000] }).probe(),
  expectCode('signer_boundary_invalid'),
);

for (const input of [
  null,
  [],
  { ...validInput, unexpected: true },
  { ...validInput, algorithm: 'none' },
  { ...validInput, signing_input: 'not-a-jwt' },
  { ...validInput, signing_input: `${'a'.repeat(4096)}.b` },
  { ...validInput, account_ref: '../account' },
  { ...validInput, environment: 'Production' },
  { ...validInput, client_id: 'x' },
  { ...validInput, signal: {} },
]) {
  await assert.rejects(client.sign(input), expectCode('signer_request_invalid'));
}
const preAborted = new AbortController();
preAborted.abort();
await assert.rejects(client.sign({ ...validInput, signal: preAborted.signal }), expectCode('signer_aborted'));

for (const response of [
  '{bad-json',
  JSON.stringify(null),
  JSON.stringify({ version: 2, signature: signature.toString('base64url') }),
  JSON.stringify({ version: 1, signature: signature.toString('base64url'), extra: true }),
  JSON.stringify({ version: 1, signature: '*' }),
  JSON.stringify({ version: 1, signature: Buffer.alloc(255).toString('base64url') }),
  JSON.stringify({ version: 1, signature: Buffer.alloc(1025).toString('base64url') }),
]) {
  const invalidClient = createLocalSignerClient({
    connect: socketHarness({ response }).connect,
    stat: safeStat,
    processUid: 1000,
    processGroups: [3000],
  });
  await assert.rejects(invalidClient.sign(validInput), expectCode('signer_response_invalid'));
}

const oversized = createLocalSignerClient({
  connect: socketHarness({ response: ['x'.repeat(4096), 'y'] }).connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
await assert.rejects(oversized.sign(validInput), expectCode('signer_response_too_large'));
const errored = createLocalSignerClient({
  connect: socketHarness({ error: true }).connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
await assert.rejects(errored.sign(validInput), expectCode('signer_unavailable'));
const throwing = createLocalSignerClient({
  connect: socketHarness({ throwOnConnect: true }).connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
await assert.rejects(throwing.sign(validInput), expectCode('signer_unavailable'));
const timedOut = createLocalSignerClient({
  connect: socketHarness({ timeout: true }).connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
await assert.rejects(timedOut.sign(validInput), expectCode('signer_timeout'));

const abortHarness = socketHarness({ timeout: true });
const abortClient = createLocalSignerClient({
  connect: abortHarness.connect,
  stat: safeStat,
  processUid: 1000,
  processGroups: [3000],
});
const duringAbort = new AbortController();
const pending = abortClient.sign({ ...validInput, signal: duringAbort.signal });
queueMicrotask(() => duringAbort.abort());
await assert.rejects(pending, expectCode('signer_aborted'));

assert.deepEqual(LOCAL_SIGNER_CONTRACT, {
  socket_directory: SOCKET_DIRECTORY,
  socket_path: SOCKET,
  algorithm: 'RS256',
  protocol_version: 1,
  maximum_request_bytes: 8192,
  maximum_response_bytes: 4096,
  maximum_timeout_ms: 10_000,
  private_key_available_to_broker: false,
});

console.log('local signer client: fixed socket, ownership boundary, bounded protocol and safe failures passed');
