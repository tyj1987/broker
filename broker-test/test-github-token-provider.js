import assert from 'node:assert/strict';
import {
  createGitHubAppInstallationTokenProvider,
  GITHUB_APP_TOKEN_CONTRACT,
} from '../broker/adapters/github-app-token-provider.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const input = {
  account_ref: 'github-primary',
  environment: 'production',
  repository: 'tyj1987/broker',
  owner: 'tyj1987',
  repo: 'broker',
  signal: new AbortController().signal,
};
const binding = {
  account_ref: 'github-primary',
  environment: 'production',
  client_id: 'Iv1.test-client',
  installation_id: 12345,
  repositories: ['tyj1987/broker'],
};
const responseBody = () => ({
  token: 'installation-token',
  expires_at: new Date(NOW + 60 * 60_000).toISOString(),
  permissions: { metadata: 'read' },
  repositories: [{ full_name: 'tyj1987/broker' }],
});
const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;

let signingCall;
let requestCall;
let resolverCall;
const provider = createGitHubAppInstallationTokenProvider({
  now: () => NOW,
  accountResolver: async (value) => {
    resolverCall = value;
    return binding;
  },
  signer: async (value) => {
    signingCall = value;
    return Buffer.alloc(256, 7);
  },
  request: async (value) => {
    requestCall = value;
    return { status: 201, body: JSON.stringify(responseBody()) };
  },
});
const lease = await provider(input);
assert.deepEqual(lease, {
  token: 'installation-token',
  repository: 'tyj1987/broker',
  expires_at: responseBody().expires_at,
  permissions: { metadata: 'read' },
});
assert.deepEqual(resolverCall, {
  account_ref: 'github-primary',
  environment: 'production',
  repository: 'tyj1987/broker',
  signal: input.signal,
});
assert.equal(signingCall.algorithm, 'RS256');
assert.equal(signingCall.account_ref, input.account_ref);
assert.equal(signingCall.environment, input.environment);
assert.equal(signingCall.client_id, binding.client_id);
assert.equal(signingCall.signal, input.signal);
const [header, claims] = signingCall.signing_input
  .split('.')
  .map((part) => JSON.parse(Buffer.from(part, 'base64url')));
assert.deepEqual(header, { alg: 'RS256', typ: 'JWT' });
assert.deepEqual(claims, {
  iat: Math.floor(NOW / 1000) - 60,
  exp: Math.floor(NOW / 1000) + 540,
  iss: binding.client_id,
});
assert.deepEqual(
  {
    origin: requestCall.origin,
    method: requestCall.method,
    path: requestCall.path,
    accept: requestCall.headers.Accept,
    version: requestCall.headers['X-GitHub-Api-Version'],
    redirect: requestCall.redirect,
    maxBytes: requestCall.max_response_bytes,
  },
  {
    origin: 'https://api.github.com',
    method: 'POST',
    path: '/app/installations/12345/access_tokens',
    accept: 'application/vnd.github+json',
    version: '2026-03-10',
    redirect: 'manual',
    maxBytes: 256 * 1024,
  },
);
assert.deepEqual(JSON.parse(requestCall.body), {
  repositories: ['broker'],
  permissions: { metadata: 'read' },
});
assert.match(
  requestCall.headers.Authorization,
  /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
);
assert.equal(requestCall.headers.Authorization.includes('installation-token'), false);

assert.throws(() => createGitHubAppInstallationTokenProvider(), TypeError);
assert.throws(
  () => createGitHubAppInstallationTokenProvider({ request: async () => {} }),
  TypeError,
);
assert.throws(
  () =>
    createGitHubAppInstallationTokenProvider({ request: async () => {}, signer: async () => {} }),
  TypeError,
);
assert.throws(() => createGitHubAppInstallationTokenProvider({
  request: async () => {}, signer: async () => {}, accountResolver: async () => {},
  permissions: { contents: 'write' },
}), /read-only/);
assert.throws(() => createGitHubAppInstallationTokenProvider({
  request: async () => {}, signer: async () => {}, accountResolver: async () => {}, permissions: {},
}), /non-empty/);
assert.throws(() => createGitHubAppInstallationTokenProvider({
  request: async () => {}, signer: async () => {}, accountResolver: async () => {}, permissions: null,
}), /non-empty/);
const makeProvider = ({
  resolved = binding,
  signed = Buffer.alloc(256),
  response = { status: 201, body: responseBody() },
} = {}) =>
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => resolved,
    signer: async () => signed,
    request: async () => response,
  });
for (const invalid of [
  { ...input, account_ref: '../account' },
  { ...input, environment: 'Production' },
  { ...input, repository: 'bad' },
  { ...input, repo: 'other' },
])
  await assert.rejects(makeProvider()(invalid), expectCode('github_token_request_invalid'));
for (const invalidBinding of [
  null,
  { ...binding, account_ref: 'other' },
  { ...binding, environment: 'staging' },
  { ...binding, client_id: '' },
  { ...binding, installation_id: 0 },
  { ...binding, repositories: ['other/repo'] },
])
  await assert.rejects(
    makeProvider({ resolved: invalidBinding })(input),
    expectCode('github_app_binding_unavailable'),
  );
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => {
      throw new Error('resolver detail');
    },
    signer: async () => Buffer.alloc(256),
    request: async () => ({ status: 201, body: responseBody() }),
  })(input),
  (error) =>
    expectCode('github_app_binding_unavailable')(error) &&
    !error.message.includes('resolver detail'),
);
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => {
      throw new V2Error('resolver_secret', 'canary-resolver-secret', 500);
    },
    signer: async () => Buffer.alloc(256),
    request: async () => ({ status: 201, body: responseBody() }),
  })(input),
  (error) =>
    expectCode('github_app_binding_unavailable')(error) && !error.message.includes('canary'),
);
await assert.rejects(
  makeProvider({ signed: Buffer.alloc(128) })(input),
  expectCode('github_app_signing_failed'),
);
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => {
      throw new Error('signer detail');
    },
    request: async () => ({ status: 201, body: responseBody() }),
  })(input),
  (error) =>
    expectCode('github_app_signing_failed')(error) && !error.message.includes('signer detail'),
);
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => {
      throw new V2Error('signer_secret', 'canary-signer-secret', 500);
    },
    request: async () => ({ status: 201, body: responseBody() }),
  })(input),
  (error) => expectCode('github_app_signing_failed')(error) && !error.message.includes('canary'),
);

for (const [response, code] of [
  [{ status: 302, body: '{}' }, 'github_token_redirect_denied'],
  [{ status: 401, body: '{}' }, 'github_token_request_failed'],
  [{ status: 201, body: 'not-json' }, 'github_token_invalid_response'],
  [{ status: 201, body: 'x'.repeat(256 * 1024 + 1) }, 'github_token_response_too_large'],
  [{ status: 201, body: { ...responseBody(), token: '' } }, 'github_token_scope_mismatch'],
  [
    { status: 201, body: { ...responseBody(), expires_at: new Date(NOW).toISOString() } },
    'github_token_scope_mismatch',
  ],
  [
    {
      status: 201,
      body: { ...responseBody(), expires_at: new Date(NOW + 3_700_000).toISOString() },
    },
    'github_token_scope_mismatch',
  ],
  [
    { status: 201, body: { ...responseBody(), permissions: { metadata: 'read', issues: 'read' } } },
    'github_token_scope_mismatch',
  ],
  [
    { status: 201, body: { ...responseBody(), repositories: [{ full_name: 'other/repo' }] } },
    'github_token_scope_mismatch',
  ],
  [{ status: 201, body: { ...responseBody(), repositories: [] } }, 'github_token_scope_mismatch'],
])
  await assert.rejects(makeProvider({ response })(input), expectCode(code));
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => Buffer.alloc(256),
    request: async () => {
      throw new Error('network token detail');
    },
  })(input),
  (error) =>
    expectCode('github_token_unavailable')(error) &&
    !error.message.includes('network token detail'),
);
await assert.rejects(
  createGitHubAppInstallationTokenProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => Buffer.alloc(256),
    request: async () => {
      throw new V2Error('transport_policy_denied', 'safe', 403);
    },
  })(input),
  expectCode('transport_policy_denied'),
);

assert.deepEqual(GITHUB_APP_TOKEN_CONTRACT, {
  origin: 'https://api.github.com',
  method: 'POST',
  api_version: '2026-03-10',
  jwt_algorithm: 'RS256',
  jwt_maximum_ttl_seconds: 600,
  credential_maximum_ttl_seconds: 3600,
  maximum_response_bytes: 256 * 1024,
  permissions: { metadata: 'read' },
});

console.log(
  'github app token provider: signer boundary, repository scope and safe failures passed',
);
