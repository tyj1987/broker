import assert from 'node:assert/strict';

import {
  createGitHubPullRequestCreateAdapter,
  GITHUB_PULL_REQUEST_CREATE_CONTRACT,
} from '../broker/adapters/github-pull-request-create.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const parameters = {
  resource_ref: 'tyj1987/broker',
  owner: 'tyj1987',
  repo: 'broker',
  title: 'Add bounded capability',
  body: 'Summary\n\n- Safe change',
  head: 'codex/bounded-capability',
  base: 'master',
};
const context = {
  accountRef: 'github-primary',
  environment: 'production',
  signal: new AbortController().signal,
  execution: {
    tool: 'github.pull-request.create@1.0.0',
    target: 'tyj1987/broker',
    environment: 'production',
  },
};
const lease = {
  token: 'installation-write-token',
  repository: 'tyj1987/broker',
  expires_at: new Date(NOW + 60 * 60_000).toISOString(),
  permissions: { pull_requests: 'write' },
};
const responseBody = (overrides = {}) => ({
  number: 42,
  state: 'open',
  draft: true,
  head: { ref: parameters.head },
  base: { ref: parameters.base },
  ...overrides,
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let requestInput;
let tokenInput;
const adapter = createGitHubPullRequestCreateAdapter({
  now: () => NOW,
  tokenProvider: async (input) => {
    tokenInput = input;
    return lease;
  },
  request: async (input) => {
    requestInput = input;
    return { status: 201, body: JSON.stringify(responseBody()) };
  },
});

assert.deepEqual(await adapter(parameters, context), {
  number: 42,
  state: 'open',
  draft: true,
  head: parameters.head,
  base: parameters.base,
  url: 'https://github.com/tyj1987/broker/pull/42',
});
assert.deepEqual(tokenInput, {
  account_ref: 'github-primary',
  environment: 'production',
  owner: 'tyj1987',
  repo: 'broker',
  repository: 'tyj1987/broker',
  signal: context.signal,
});
assert.deepEqual(
  {
    origin: requestInput.origin,
    method: requestInput.method,
    path: requestInput.path,
    accept: requestInput.headers.Accept,
    version: requestInput.headers['X-GitHub-Api-Version'],
    contentType: requestInput.headers['Content-Type'],
    redirect: requestInput.redirect,
    maximum: requestInput.max_response_bytes,
  },
  {
    origin: 'https://api.github.com',
    method: 'POST',
    path: '/repos/tyj1987/broker/pulls',
    accept: 'application/vnd.github+json',
    version: '2026-03-10',
    contentType: 'application/json',
    redirect: 'manual',
    maximum: 1024 * 1024,
  },
);
assert.deepEqual(JSON.parse(requestInput.body), {
  title: parameters.title,
  head: parameters.head,
  base: parameters.base,
  draft: true,
  body: parameters.body,
});
assert.equal(requestInput.headers.Authorization, 'Bearer installation-write-token');

const explicit = createGitHubPullRequestCreateAdapter({
  now: () => NOW,
  tokenProvider: async () => lease,
  request: async (input) => ({
    status: 201,
    body: responseBody({ draft: false, head: { ref: 'feature' } }),
    request: input,
  }),
});
assert.equal(
  (await explicit({ ...parameters, body: undefined, draft: false, head: 'feature' }, context))
    .draft,
  false,
);

assert.throws(() => createGitHubPullRequestCreateAdapter(), TypeError);
assert.throws(() => createGitHubPullRequestCreateAdapter({ request: async () => {} }), TypeError);
assert.throws(
  () =>
    createGitHubPullRequestCreateAdapter({
      request: async () => {},
      tokenProvider: async () => lease,
      now: null,
    }),
  TypeError,
);

const noRequest = createGitHubPullRequestCreateAdapter({
  now: () => NOW,
  tokenProvider: async () => lease,
  request: async () => {
    throw new Error('must not run');
  },
});
for (const invalid of [
  { ...parameters, owner: '../owner' },
  { ...parameters, repo: '..' },
  { ...parameters, resource_ref: 'other/repo' },
  { ...parameters, title: '' },
  { ...parameters, title: 'bad\nline' },
  { ...parameters, body: '' },
  { ...parameters, body: `bad\u0000body` },
  { ...parameters, head: '../feature' },
  { ...parameters, head: 'feature..branch' },
  { ...parameters, head: 'feature.lock' },
  { ...parameters, head: 'master' },
  { ...parameters, draft: 'true' },
]) {
  await assert.rejects(noRequest(invalid, context), (error) => error instanceof V2Error);
}
for (const execution of [
  { ...context.execution, tool: 'github.repository.read@1.0.0' },
  { ...context.execution, target: 'other/repo' },
  { ...context.execution, environment: 'staging' },
]) {
  await assert.rejects(
    noRequest(parameters, { ...context, execution }),
    expectCode('github_execution_binding_mismatch'),
  );
}
await assert.rejects(
  noRequest(parameters, { ...context, accountRef: '' }),
  expectCode('github_account_unavailable'),
);

for (const invalidLease of [
  null,
  { ...lease, token: '' },
  { ...lease, repository: 'other/repo' },
  { ...lease, permissions: { pull_requests: 'read' } },
  { ...lease, permissions: { pull_requests: 'write', contents: 'read' } },
  { ...lease, expires_at: new Date(NOW).toISOString() },
  { ...lease, expires_at: new Date(NOW + 3_700_000).toISOString() },
]) {
  const invalidAdapter = createGitHubPullRequestCreateAdapter({
    now: () => NOW,
    tokenProvider: async () => invalidLease,
    request: async () => ({ status: 201, body: responseBody() }),
  });
  await assert.rejects(
    invalidAdapter(parameters, context),
    expectCode('github_credential_scope_mismatch'),
  );
}
await assert.rejects(
  createGitHubPullRequestCreateAdapter({
    now: () => NOW,
    tokenProvider: async () => {
      throw new Error('canary-secret');
    },
    request: async () => ({ status: 201, body: responseBody() }),
  })(parameters, context),
  (error) =>
    expectCode('github_credential_unavailable')(error) && !error.message.includes('canary'),
);

for (const [response, code] of [
  [{ status: 302, body: '{}' }, 'github_redirect_denied'],
  [{ status: 401, body: '{}' }, 'github_credential_rejected'],
  [{ status: 403, body: '{}' }, 'github_forbidden'],
  [{ status: 404, body: '{}' }, 'github_not_found'],
  [{ status: 422, body: '{}' }, 'github_pull_request_rejected'],
  [{ status: 500, body: '{}' }, 'github_upstream_error'],
  [{ status: 201, body: 'not-json' }, 'github_invalid_response'],
  [{ status: 201, body: 'x'.repeat(1024 * 1024 + 1) }, 'github_response_too_large'],
  [{ status: 201, body: responseBody({ number: 0 }) }, 'github_invalid_response'],
  [{ status: 201, body: responseBody({ state: 'closed' }) }, 'github_invalid_response'],
  [{ status: 201, body: responseBody({ draft: false }) }, 'github_invalid_response'],
  [{ status: 201, body: responseBody({ head: { ref: 'other' } }) }, 'github_invalid_response'],
  [{ status: 201, body: responseBody({ base: { ref: 'other' } }) }, 'github_invalid_response'],
]) {
  const responseAdapter = createGitHubPullRequestCreateAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => response,
  });
  await assert.rejects(responseAdapter(parameters, context), expectCode(code));
}
await assert.rejects(
  createGitHubPullRequestCreateAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => {
      throw new Error('network canary secret');
    },
  })(parameters, context),
  (error) => expectCode('github_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  createGitHubPullRequestCreateAdapter({
    now: () => NOW,
    tokenProvider: async () => lease,
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(parameters, context),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_PULL_REQUEST_CREATE_CONTRACT, {
  tool: 'github.pull-request.create@1.0.0',
  origin: 'https://api.github.com',
  method: 'POST',
  path_template: '/repos/{owner}/{repo}/pulls',
  api_version: '2026-03-10',
  maximum_response_bytes: 1024 * 1024,
  maximum_body_characters: 10_000,
  required_permission: 'pull_requests:write',
  default_draft: true,
  arbitrary_url: false,
  credential_export: false,
});

console.log('github pull request adapter: approval-gated typed write boundary passed');
