import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { runProviderSignerAuthorityGeneration } from '../broker/bin/provider-signer-authority-generation.js';
import {
  PROVIDER_SIGNER_AUTHORITY_GENERATION_CONTRACT,
  ProviderSignerGenerationError,
  readProviderSignerAuthorityGenerations,
} from '../broker/lib/provider-signer-authority-generation.js';

const generations = { github: '1'.repeat(64), aliyun: '2'.repeat(64) };
const requests = [];
const connect = ({ path }, connected) => {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  socket.end = (payload) => {
    const request = JSON.parse(payload);
    requests.push({ path, request });
    const provider = path.includes('github') ? 'github' : 'aliyun';
    queueMicrotask(() => {
      socket.emit(
        'data',
        `${JSON.stringify({
          version: 1,
          operation: 'authority_generation.read',
          challenge: request.challenge,
          authority_generation_sha256: generations[provider],
        })}\n`,
      );
      socket.emit('end');
    });
  };
  queueMicrotask(connected);
  return socket;
};

const result = await readProviderSignerAuthorityGenerations({
  connect,
  randomBytes: () => Buffer.alloc(32, 7),
});
assert.deepEqual(result, generations);
assert.deepEqual(
  requests.map(({ path }) => path),
  ['/run/secret-broker-github-signer/signer.sock', '/run/secret-broker-aliyun-signer/signer.sock'],
);
assert.equal(
  requests.every(({ request }) => Object.keys(request).length === 3),
  true,
);
assert.equal(
  requests.every(({ request }) => request.challenge.length === 43),
  true,
);

const output = [];
assert.deepEqual(
  await runProviderSignerAuthorityGeneration({
    readGenerations: async () => generations,
    writeOutput: (value) => output.push(value),
  }),
  generations,
);
assert.deepEqual(output, [JSON.stringify(generations)]);

const expectUnavailable = async (response) => {
  const invalidConnect = (_options, connected) => {
    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.end = (payload) => {
      const request = JSON.parse(payload);
      queueMicrotask(() => {
        socket.emit('data', response(request));
        socket.emit('end');
      });
    };
    queueMicrotask(connected);
    return socket;
  };
  await assert.rejects(
    readProviderSignerAuthorityGenerations({
      connect: invalidConnect,
      randomBytes: () => Buffer.alloc(32, 3),
    }),
    (error) =>
      error instanceof ProviderSignerGenerationError &&
      error.code === 'provider_signer_generation_unavailable',
  );
};

await expectUnavailable(
  (request) =>
    `${JSON.stringify({
      version: 1,
      operation: 'authority_generation.read',
      challenge: `${request.challenge.slice(0, -1)}x`,
      authority_generation_sha256: '3'.repeat(64),
    })}\n`,
);
await expectUnavailable(
  (request) =>
    `${JSON.stringify({
      version: 1,
      operation: 'authority_generation.read',
      challenge: request.challenge,
      authority_generation_sha256: 'INVALID',
    })}\n`,
);
await expectUnavailable(() => `${'x'.repeat(513)}\n`);
await expectUnavailable(() => 'not-json\n');
await expectUnavailable(() => '{}\n');
await expectUnavailable(
  (request) =>
    `${JSON.stringify({
      version: 2,
      operation: 'authority_generation.read',
      challenge: request.challenge,
      authority_generation_sha256: '3'.repeat(64),
    })}\n`,
);
await expectUnavailable(
  (request) =>
    `${JSON.stringify({
      version: 1,
      operation: 'unexpected',
      challenge: request.challenge,
      authority_generation_sha256: '3'.repeat(64),
    })}\n`,
);
await expectUnavailable(() => '[]\n');
await expectUnavailable(() => '\r\n');
await expectUnavailable(
  (request) =>
    `{"version":1,"operation":"authority_generation.read","challenge":"${request.challenge}","authority_generation_sha256":["${'3'.repeat(64)}"]}\n`,
);
await expectUnavailable(
  (request) =>
    `{"version":1,"operation":"authority_generation.read","challenge":"${request.challenge}","authority_generation_sha256":"invalid","authority_generation_sha256":"${'3'.repeat(64)}"}\n`,
);

await assert.rejects(
  readProviderSignerAuthorityGenerations({
    connect: () => {
      throw new Error('connect failed');
    },
    randomBytes: () => Buffer.alloc(32, 8),
  }),
  /provider_signer_generation_unavailable/,
);
await assert.rejects(
  readProviderSignerAuthorityGenerations({
    connect: (_options, connected) => {
      const socket = new EventEmitter();
      socket.destroy = () => {};
      socket.end = () => queueMicrotask(() => socket.emit('error', new Error('socket failed')));
      queueMicrotask(connected);
      return socket;
    },
    randomBytes: () => Buffer.alloc(32, 9),
  }),
  /provider_signer_generation_unavailable/,
);

let timeoutCallback;
let destroyed = false;
const timeoutPromise = readProviderSignerAuthorityGenerations({
  connect: () => {
    const socket = new EventEmitter();
    socket.destroy = () => {
      destroyed = true;
    };
    socket.end = () => {};
    return socket;
  },
  randomBytes: () => Buffer.alloc(32, 4),
  setTimer: (callback) => {
    timeoutCallback = callback;
    return 1;
  },
  clearTimer: () => {},
});
timeoutCallback();
await assert.rejects(timeoutPromise, /provider_signer_generation_unavailable/);
assert.equal(destroyed, true);

for (const options of [
  { connect: null },
  { randomBytes: null },
  { timeoutMs: 99 },
  { timeoutMs: 10_001 },
  { timeoutMs: 100.5 },
  { setTimer: null },
  { clearTimer: null },
]) {
  await assert.rejects(readProviderSignerAuthorityGenerations(options), TypeError);
}
await assert.rejects(
  readProviderSignerAuthorityGenerations({ randomBytes: () => Buffer.alloc(31) }),
  /provider_signer_generation_unavailable/,
);
await assert.rejects(
  readProviderSignerAuthorityGenerations({
    randomBytes: () => {
      throw new Error('entropy unavailable');
    },
  }),
  /provider_signer_generation_unavailable/,
);
assert.equal(PROVIDER_SIGNER_AUTHORITY_GENERATION_CONTRACT.secret_material_returned, false);

console.log('provider signer authority generation: fresh bounded dual-signer probes passed');
