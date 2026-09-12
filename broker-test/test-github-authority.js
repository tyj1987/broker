import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  GITHUB_INSTALLATION_AUTHORITY_CONTRACT,
  createGitHubInstallationAuthorityProvider,
} from '../broker/adapters/github-installation-authority.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = Date.parse('2026-09-13T00:00:00Z');
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const input = {
  account_ref: 'github-isolated',
  environment: 'staging',
  tool: 'github.repository.read@1.0.0',
  target: 'tyj1987/broker',
  resource_ref: 'tyj1987/broker',
  execution_environment: 'staging',
  repository: 'tyj1987/broker',
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
};
const binding = {
  account_ref: input.account_ref,
  environment: input.environment,
  client_id: 'Iv1.authority-test',
  installation_id: 12345,
  repositories: [input.repository],
};
const response = {
  id: 12345,
  account: { id: 98765, login: 'tyj1987', token: 'must-not-project' },
  target_type: 'Organization',
  permissions: { administration: 'write' },
};
const sha = (value) => createHash('sha256').update(String(value)).digest('hex');
const calls = [];
const provider = createGitHubInstallationAuthorityProvider({
  now: () => NOW,
  accountResolver: async (request) => {
    calls.push({ resolver: request });
    return binding;
  },
  signer: async (request) => {
    calls.push({ signer: request });
    return Buffer.alloc(256, 7);
  },
  request: async (request) => {
    calls.push({ request });
    return { status: 200, body: response };
  },
});
const evidence = await provider(input);
assert.deepEqual(evidence.authority, {
  installation_id_sha256: sha(response.id),
  account_id_sha256: sha(response.account.id),
  account_login_sha256: sha(response.account.login),
  target_type: 'Organization',
});
assert.equal(JSON.stringify(evidence.authority).includes('tyj1987'), false);
assert.equal(JSON.stringify(evidence.authority).includes('98765'), false);
assert.equal(evidence.binding.installation_id, 12345);
assert.equal(calls[2].request.origin, 'https://api.github.com');
assert.equal(calls[2].request.method, 'GET');
assert.equal(calls[2].request.path, '/app/installations/12345');
assert.equal(calls[2].request.redirect, 'manual');
assert.match(calls[2].request.headers.Authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
assert.equal(calls[1].signer.execution_id, EXECUTION_ID);
assert.equal(calls[1].signer.request_binding, REQUEST_BINDING);

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const withResponse = (value) =>
  createGitHubInstallationAuthorityProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => Buffer.alloc(256),
    request: async () => value,
  });
for (const [value, code] of [
  [{ status: 302, body: {} }, 'github_authority_redirect_denied'],
  [{ status: 401, body: {} }, 'github_authority_credential_rejected'],
  [{ status: 404, body: {} }, 'github_authority_not_found'],
  [{ status: 500, body: { token: 'canary' } }, 'github_authority_upstream_error'],
  [{ status: 200, body: { ...response, id: 54321 } }, 'github_authority_invalid_response'],
  [{ status: 200, body: Buffer.alloc(256 * 1024 + 1) }, 'github_authority_response_too_large'],
  [{ status: 200, body: Buffer.from('{') }, 'github_authority_invalid_response'],
])
  await assert.rejects(withResponse(value)(input), expectCode(code));
await assert.rejects(
  provider({ ...input, repository: '../escape' }),
  expectCode('github_authority_request_invalid'),
);
await assert.rejects(
  provider({ ...input, resource_ref: 'other/repo' }),
  expectCode('github_authority_request_invalid'),
);
await assert.rejects(
  provider({ ...input, tool: 'github.issues.list@1.0.0' }),
  expectCode('github_authority_request_invalid'),
);
await assert.rejects(
  createGitHubInstallationAuthorityProvider({
    now: () => NOW,
    accountResolver: async () => ({ ...binding, installation_id: 54321 }),
    signer: async () => Buffer.alloc(256),
    request: async () => ({ status: 200, body: response }),
  })(input),
  expectCode('github_authority_invalid_response'),
);
for (const changed of [
  null,
  { ...binding, account_ref: 'other' },
  { ...binding, environment: 'production' },
  { ...binding, client_id: '../bad' },
  { ...binding, installation_id: 0 },
  { ...binding, repositories: ['other/repo'] },
]) {
  const resolver =
    changed === null
      ? async () => {
          throw new Error('private');
        }
      : async () => changed;
  await assert.rejects(
    createGitHubInstallationAuthorityProvider({
      now: () => NOW,
      accountResolver: resolver,
      signer: async () => Buffer.alloc(256),
      request: async () => ({ status: 200, body: response }),
    })(input),
    expectCode('github_authority_binding_unavailable'),
  );
}
for (const signer of [
  async () => {
    throw new Error('private');
  },
  async () => Buffer.alloc(1),
]) {
  await assert.rejects(
    createGitHubInstallationAuthorityProvider({
      now: () => NOW,
      accountResolver: async () => binding,
      signer,
      request: async () => ({ status: 200, body: response }),
    })(input),
    expectCode('github_authority_signing_failed'),
  );
}
await assert.rejects(
  createGitHubInstallationAuthorityProvider({
    accountResolver: async () => binding,
    signer: async () => Buffer.alloc(256),
    request: async () => {
      throw new Error('private');
    },
  })(input),
  expectCode('github_authority_unavailable'),
);
const transportError = new V2Error('transport_policy_denied', 'safe', 502);
await assert.rejects(
  createGitHubInstallationAuthorityProvider({
    now: () => NOW,
    accountResolver: async () => binding,
    signer: async () => Buffer.alloc(256),
    request: async () => {
      throw transportError;
    },
  })(input),
  (error) => error === transportError,
);
assert.throws(() => createGitHubInstallationAuthorityProvider(), TypeError);
assert.throws(
  () => createGitHubInstallationAuthorityProvider({ request: async () => {} }),
  TypeError,
);
assert.throws(
  () =>
    createGitHubInstallationAuthorityProvider({ request: async () => {}, signer: async () => {} }),
  TypeError,
);
assert.throws(
  () =>
    createGitHubInstallationAuthorityProvider({
      request: async () => {},
      signer: async () => {},
      accountResolver: async () => {},
      now: null,
    }),
  TypeError,
);
assert.equal(GITHUB_INSTALLATION_AUTHORITY_CONTRACT.output_contains_identifiers, false);

console.log(
  'github authority: fixed JWT probe, hashed projection and fail-closed responses passed',
);
