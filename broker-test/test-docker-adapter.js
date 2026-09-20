import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import {
  createDockerRepositoryTagsListAdapter,
  DOCKER_REPOSITORY_TAGS_LIST_CONTRACT,
} from '../broker/adapters/docker-repository-tags-list.js';
import { createDockerRepositoryTagsListExecutor } from '../broker/adapters/docker-repository-tags-list-executor.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-09T08:00:00Z');
const REPOSITORY = 'library/alpine';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const parameters = { resource_ref: REPOSITORY, namespace: 'library', repository: 'alpine' };
const context = {
  accountRef: 'docker-pull-account',
  environment: 'production',
  execution: {
    tool: 'docker.repository.tags.list@1.0.0',
    target: REPOSITORY,
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const validLease = () => ({
  token: 'unit-docker-token',
  repository: REPOSITORY,
  expires_at: new Date(NOW + 60_000).toISOString(),
});
const validBody = () => ({ name: REPOSITORY, tags: ['3.20', 'latest'] });
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let tokenInput;
let requestInput;
const adapter = createDockerRepositoryTagsListAdapter({
  now: () => NOW,
  tokenProvider: async (input) => {
    tokenInput = input;
    return validLease();
  },
  request: async (input) => {
    requestInput = input;
    return { status: 200, body: JSON.stringify(validBody()) };
  },
});
assert.deepEqual(await adapter(parameters, context), validBody());
assert.deepEqual(tokenInput, {
  account_ref: 'docker-pull-account',
  environment: 'production',
  repository: REPOSITORY,
  scope: 'repository:library/alpine:pull',
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal: context.signal,
});
assert.equal(requestInput.origin, 'https://registry-1.docker.io');
assert.equal(requestInput.method, 'GET');
assert.equal(requestInput.path, '/v2/library/alpine/tags/list?n=100');
assert.equal(requestInput.headers.Authorization, 'Bearer unit-docker-token');
assert.equal(requestInput.redirect, 'manual');
assert.equal(requestInput.max_response_bytes, 1024 * 1024);

assert.throws(() => createDockerRepositoryTagsListAdapter(), TypeError);
assert.throws(() => createDockerRepositoryTagsListAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createDockerRepositoryTagsListAdapter({
      request: async () => {},
      tokenProvider: async () => validLease(),
      now: 1,
    }),
  TypeError,
);
for (const changed of [
  { namespace: 'Library' },
  { repository: '../alpine' },
  { namespace: 1 },
  { resource_ref: 'other/alpine' },
]) {
  await assert.rejects(
    adapter({ ...parameters, ...changed }, context),
    (error) =>
      error instanceof V2Error &&
      ['docker_invalid_repository', 'docker_repository_binding_mismatch'].includes(error.code),
  );
}
for (const execution of [
  { ...context.execution, tool: 'docker.repository.push@1.0.0' },
  { ...context.execution, target: 'library/ubuntu' },
  { ...context.execution, environment: 'staging' },
  { ...context.execution, execution_id: 'wrong' },
  { ...context.execution, request_binding: 'wrong' },
]) {
  await assert.rejects(
    adapter(parameters, { ...context, execution }),
    expectCode('docker_execution_binding_mismatch'),
  );
}
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('docker_account_unavailable'),
);

const withLease = (lease) =>
  createDockerRepositoryTagsListAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
for (const [lease, code] of [
  [null, 'docker_credential_unavailable'],
  [{ ...validLease(), token: '' }, 'docker_credential_unavailable'],
  [{ ...validLease(), repository: 'library/ubuntu' }, 'docker_credential_unavailable'],
  [
    { ...validLease(), expires_at: new Date(NOW).toISOString() },
    'docker_credential_expiry_invalid',
  ],
  [
    { ...validLease(), expires_at: new Date(NOW + 300_001).toISOString() },
    'docker_credential_expiry_invalid',
  ],
]) {
  await assert.rejects(withLease(lease)(parameters, context), expectCode(code));
}
await assert.rejects(
  createDockerRepositoryTagsListAdapter({
    now: () => NOW,
    tokenProvider: async () => {
      throw new Error('canary-docker-secret');
    },
    request: async () => ({ status: 200, body: validBody() }),
  })(parameters, context),
  (error) =>
    expectCode('docker_credential_unavailable')(error) && !error.message.includes('canary'),
);

const withResponse = (response) =>
  createDockerRepositoryTagsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => response,
  });
for (const [status, code] of [
  [301, 'docker_redirect_denied'],
  [401, 'docker_credential_rejected'],
  [403, 'docker_forbidden'],
  [404, 'docker_not_found'],
  [429, 'docker_rate_limited'],
  [500, 'docker_upstream_error'],
]) {
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
}
await assert.rejects(
  withResponse({ status: 200, body: 'not-json' })(parameters, context),
  expectCode('docker_invalid_response'),
);
await assert.rejects(
  withResponse({ status: 200, body: 'x'.repeat(1024 * 1024 + 1) })(parameters, context),
  expectCode('docker_response_too_large'),
);
for (const body of [
  null,
  { ...validBody(), name: 'library/ubuntu' },
  { ...validBody(), tags: ['latest', 'latest'] },
  { ...validBody(), tags: ['bad/tag'] },
  { ...validBody(), tags: Array.from({ length: 101 }, (_, index) => `tag-${index}`) },
]) {
  await assert.rejects(
    withResponse({ status: 200, body })(parameters, context),
    (error) =>
      error instanceof V2Error &&
      ['docker_invalid_response', 'docker_scope_mismatch'].includes(error.code),
  );
}
assert.deepEqual(
  await withResponse({ status: 200, body: { name: REPOSITORY, tags: null } })(parameters, context),
  { name: REPOSITORY, tags: [] },
);
await assert.rejects(
  createDockerRepositoryTagsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('network detail');
    },
  })(parameters, context),
  (error) => expectCode('docker_unavailable')(error) && !error.message.includes('detail'),
);
await assert.rejects(
  createDockerRepositoryTagsListAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

const transportCalls = [];
const executor = createDockerRepositoryTagsListExecutor({
  now: () => NOW,
  tokenProvider: async () => validLease(),
  resolveHost: async () => [{ address: '54.85.107.53', family: 4 }],
  requestImpl: (options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.destroy = () => {};
    request.end = () => {
      transportCalls.push(options);
      const response = Readable.from([JSON.stringify(validBody())]);
      response.statusCode = 200;
      response.headers = { 'content-type': 'application/json' };
      queueMicrotask(() => callback(response));
    };
    return request;
  },
});
assert.deepEqual(await executor(parameters, context), validBody());
assert.equal(transportCalls[0].hostname, 'registry-1.docker.io');
assert.equal(transportCalls[0].rejectUnauthorized, true);

assert.deepEqual(DOCKER_REPOSITORY_TAGS_LIST_CONTRACT, {
  tool: 'docker.repository.tags.list@1.0.0',
  origin: 'https://registry-1.docker.io',
  method: 'GET',
  path_template: '/v2/{namespace}/{repository}/tags/list?n=100',
  scope_template: 'repository:{namespace}/{repository}:pull',
  maximum_response_bytes: 1024 * 1024,
  maximum_tags: 100,
  maximum_token_ttl_seconds: 300,
});

console.log('docker tags adapter: repository binding, scoped lease and pinned transport passed');
