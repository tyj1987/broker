import assert from 'node:assert/strict';
import {
  createGitHubRepositoryReadAdapter,
  GITHUB_REPOSITORY_READ_CONTRACT,
} from '../broker/adapters/github-repository-read.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const parameters = { resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' };
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  execution: {
    tool: 'github.repository.read@1.0.0',
    target: 'tyj1987/broker',
    environment: 'production',
    execution_id: EXECUTION_ID,
    request_binding: REQUEST_BINDING,
  },
  signal: new AbortController().signal,
};
const validLease = () => ({
  token: 'unit-token',
  repository: 'tyj1987/broker',
  expires_at: new Date(NOW + 60_000).toISOString(),
  permissions: { metadata: 'read' },
});
const validBody = () => ({
  id: 123,
  full_name: 'tyj1987/broker',
  visibility: 'public',
  archived: false,
  private: false,
  ignored: 'not returned',
});

let requestInput;
let tokenInput;
const adapter = createGitHubRepositoryReadAdapter({
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
const result = await adapter(parameters, context);
assert.deepEqual(result, {
  id: 123,
  full_name: 'tyj1987/broker',
  visibility: 'public',
  archived: false,
});
assert.deepEqual(
  {
    account: tokenInput.account_ref,
    environment: tokenInput.environment,
    repository: tokenInput.repository,
    origin: requestInput.origin,
    method: requestInput.method,
    path: requestInput.path,
    accept: requestInput.headers.Accept,
    version: requestInput.headers['X-GitHub-Api-Version'],
    redirect: requestInput.redirect,
    maxBytes: requestInput.max_response_bytes,
  },
  {
    account: 'github-primary',
    environment: 'production',
    repository: 'tyj1987/broker',
    origin: 'https://api.github.com',
    method: 'GET',
    path: '/repos/tyj1987/broker',
    accept: 'application/vnd.github+json',
    version: '2026-03-10',
    redirect: 'manual',
    maxBytes: 1024 * 1024,
  },
);
assert.equal(requestInput.headers.Authorization, 'Bearer unit-token');
assert.equal(
  JSON.stringify(result).includes('unit-token'),
  false,
  'credential cannot enter the business result',
);
assert.equal(tokenInput.signal, context.signal);
assert.equal(tokenInput.execution_id, EXECUTION_ID);
assert.equal(tokenInput.request_binding, REQUEST_BINDING);
const defaultClockResult = await createGitHubRepositoryReadAdapter({
  tokenProvider: async () => ({
    ...validLease(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  }),
  request: async () => ({ status: 200, body: validBody() }),
})(parameters, context);
assert.equal(defaultClockResult.id, 123);

assert.throws(() => createGitHubRepositoryReadAdapter(), TypeError);
assert.throws(() => createGitHubRepositoryReadAdapter({ request: async () => {} }), TypeError);
await assert.rejects(
  adapter({ ...parameters, owner: '../admin' }, context),
  expectCode('github_invalid_repository'),
);
await assert.rejects(
  adapter({ ...parameters, resource_ref: 'other/repo' }, context),
  expectCode('github_target_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, execution: { ...context.execution, target: 'other/repo' } }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, {
    ...context,
    execution: { ...context.execution, tool: 'github.issue.write@1.0.0' },
  }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, execution: { ...context.execution, environment: 'staging' } }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, execution: { ...context.execution, execution_id: 'wrong' } }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, {
    ...context,
    execution: { ...context.execution, request_binding: 'wrong' },
  }),
  expectCode('github_execution_binding_mismatch'),
);
await assert.rejects(
  adapter(parameters, { ...context, accountRef: '' }),
  expectCode('github_account_unavailable'),
);

const withLease = (lease) =>
  createGitHubRepositoryReadAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => ({ status: 200, body: validBody() }),
  });
await assert.rejects(
  withLease(null)(parameters, context),
  expectCode('github_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), token: '' })(parameters, context),
  expectCode('github_credential_unavailable'),
);
await assert.rejects(
  withLease({ ...validLease(), repository: 'other/repo' })(parameters, context),
  expectCode('github_credential_scope_mismatch'),
);
await assert.rejects(
  withLease({ ...validLease(), permissions: { contents: 'read' } })(parameters, context),
  expectCode('github_credential_scope_mismatch'),
);
await assert.rejects(
  withLease({ ...validLease(), expires_at: new Date(NOW).toISOString() })(parameters, context),
  expectCode('github_credential_expired'),
);
await assert.rejects(
  withLease({ ...validLease(), expires_at: new Date(NOW + 3_700_000).toISOString() })(
    parameters,
    context,
  ),
  expectCode('github_credential_expired'),
);
await assert.rejects(
  createGitHubRepositoryReadAdapter({
    now: () => NOW,
    tokenProvider: async () => {
      throw new Error('unit-token must not escape');
    },
    request: async () => ({ status: 200, body: validBody() }),
  })(parameters, context),
  (error) =>
    expectCode('github_credential_unavailable')(error) && !error.message.includes('unit-token'),
);

const withResponse = (response) =>
  createGitHubRepositoryReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => response,
  });
const buffered = await withResponse({
  status: 200,
  body: Buffer.from(JSON.stringify(validBody())),
})(parameters, context);
assert.equal(buffered.full_name, 'tyj1987/broker');
for (const [status, code] of [
  [301, 'github_redirect_denied'],
  [401, 'github_credential_rejected'],
  [403, 'github_forbidden'],
  [404, 'github_not_found'],
  [429, 'github_upstream_error'],
])
  await assert.rejects(withResponse({ status, body: '{}' })(parameters, context), expectCode(code));
await assert.rejects(
  withResponse({ status: 200, body: 'not-json' })(parameters, context),
  expectCode('github_invalid_response'),
);
await assert.rejects(
  withResponse({ status: 200, body: 'x'.repeat(1024 * 1024 + 1) })(parameters, context),
  expectCode('github_response_too_large'),
);
await assert.rejects(
  withResponse({ status: 200, body: { ...validBody(), full_name: 'other/repo' } })(
    parameters,
    context,
  ),
  expectCode('github_invalid_response'),
);
await assert.rejects(
  createGitHubRepositoryReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new Error('network detail');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('network detail'),
);
await assert.rejects(
  createGitHubRepositoryReadAdapter({
    now: () => NOW,
    tokenProvider: async () => validLease(),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_REPOSITORY_READ_CONTRACT, {
  tool: 'github.repository.read@1.0.0',
  origin: 'https://api.github.com',
  method: 'GET',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  credential_maximum_ttl_seconds: 3600,
  required_permission: 'metadata:read',
});

console.log(
  'github repository adapter: pinned request, scoped lease, projection and safe failures passed',
);
