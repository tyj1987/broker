import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  commitGitHubRuntimeExecutors,
  GITHUB_RUNTIME_CONTRACT,
  GitHubRuntimeConfigError,
  prepareGitHubRuntimeExecutors,
} from '../broker/adapters/github-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['github-primary'],
};
const validConfig = () => ({
  operation_policies: {
    github: {
      'repo.read': { ...basePolicy },
      'issues.list': { ...basePolicy },
      'workflow_runs.list': { ...basePolicy },
      'pull_request.create': { ...basePolicy },
    },
  },
  provider_accounts: {
    github: {
      'github-primary': {
        client_id: 'Iv1.runtime-test',
        installation_id: 12345,
        environments: ['production'],
        repositories: ['tyj1987/broker'],
      },
    },
  },
});
const expectRuntimeError = (error) => error instanceof GitHubRuntimeConfigError;

let signerFactoryCalls = 0;
let signerProbeCalls = 0;
const signerInputs = [];
const createSignerClient = () => {
  signerFactoryCalls += 1;
  return {
    probe: async () => {
      signerProbeCalls += 1;
      return true;
    },
    sign: async (input) => {
      signerInputs.push(input);
      return Buffer.alloc(256, 4);
    },
  };
};
const requests = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = (body) => {
    requests.push({ options, body: body?.toString() });
    const tokenRequest = options.path.includes('/access_tokens');
    const pullRequestCreate = options.method === 'POST' && options.path.endsWith('/pulls');
    const permission = options.path.includes('/issues') ? 'issues' : 'metadata';
    const responseBody = tokenRequest
      ? {
          token: 'runtime-installation-token',
          expires_at: new Date(NOW + 60 * 60_000).toISOString(),
          permissions: JSON.parse(body).permissions,
          repositories: [{ full_name: 'tyj1987/broker' }],
        }
      : pullRequestCreate
        ? {
            number: 73,
            state: 'open',
            draft: true,
            head: { ref: 'codex/runtime-test' },
            base: { ref: 'master' },
          }
        : permission === 'issues'
          ? []
          : { id: 123, full_name: 'tyj1987/broker', visibility: 'public', archived: false };
    const response = Readable.from([JSON.stringify(responseBody)]);
    response.statusCode = tokenRequest || pullRequestCreate ? 201 : 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

const empty = await prepareGitHubRuntimeExecutors({
  config: {},
  createSignerClient: () => {
    throw new Error('must not initialize an unused signer');
  },
});
assert.equal(empty.size, 0);
const unverified = await prepareGitHubRuntimeExecutors({
  config: {
    operation_policies: { github: { 'repo.read': { ...basePolicy, contract_verified: false } } },
  },
  createSignerClient: () => {
    throw new Error('must not initialize an unverified signer');
  },
});
assert.equal(unverified.size, 0);

const executors = await prepareGitHubRuntimeExecutors({
  config: validConfig(),
  createSignerClient,
  resolveHost: async () => [{ address: '93.184.216.34', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual(
  [...executors.keys()],
  [
    'github.repository.read@1.0.0',
    'github.issues.list@1.0.0',
    'github.workflow-runs.list@1.0.0',
    'github.pull-request.create@1.0.0',
  ],
);
assert.equal(signerFactoryCalls, 1);
assert.equal(signerProbeCalls, 1);

const repository = await executors.get('github.repository.read@1.0.0')(
  { resource_ref: 'tyj1987/broker', owner: 'tyj1987', repo: 'broker' },
  {
    accountRef: 'github-primary',
    environment: 'production',
    execution: {
      tool: 'github.repository.read@1.0.0',
      target: 'tyj1987/broker',
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.deepEqual(repository, {
  id: 123,
  full_name: 'tyj1987/broker',
  visibility: 'public',
  archived: false,
});
assert.equal(signerInputs.length, 1);
assert.equal(signerInputs[0].account_ref, 'github-primary');
assert.equal(signerInputs[0].environment, 'production');
assert.equal(signerInputs[0].algorithm, 'RS256');
assert.equal(signerInputs[0].execution_id, EXECUTION_ID);
assert.equal(signerInputs[0].request_binding, REQUEST_BINDING);
assert.equal(JSON.parse(requests[0].body).permissions.metadata, 'read');
assert.equal(requests[1].options.headers.authorization, 'Bearer runtime-installation-token');

const pullRequest = await executors.get('github.pull-request.create@1.0.0')(
  {
    resource_ref: 'tyj1987/broker',
    owner: 'tyj1987',
    repo: 'broker',
    title: 'Runtime contract test',
    head: 'codex/runtime-test',
    base: 'master',
  },
  {
    accountRef: 'github-primary',
    environment: 'production',
    execution: {
      tool: 'github.pull-request.create@1.0.0',
      target: 'tyj1987/broker',
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.deepEqual(pullRequest, {
  number: 73,
  state: 'open',
  draft: true,
  head: 'codex/runtime-test',
  base: 'master',
  url: 'https://github.com/tyj1987/broker/pull/73',
});
assert.deepEqual(JSON.parse(requests[2].body).permissions, { pull_requests: 'write' });
assert.equal(requests[3].options.path, '/repos/tyj1987/broker/pulls');
assert.equal(requests[3].options.headers.authorization, 'Bearer runtime-installation-token');

await assert.rejects(
  executors.get('github.repository.read@1.0.0')(
    { resource_ref: 'other/repo', owner: 'other', repo: 'repo' },
    {
      accountRef: 'github-primary',
      environment: 'production',
      execution: {
        tool: 'github.repository.read@1.0.0',
        target: 'other/repo',
        environment: 'production',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ),
  (error) => error instanceof V2Error && error.code === 'github_credential_unavailable',
);

for (const mutate of [
  (config) => {
    config.operation_policies.github['repo.read'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.github['unknown.read'] = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.github['repo.read'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.github = [];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].private_key = 'forbidden';
  },
  (config) => {
    config.provider_accounts.github['github-primary'].client_id = 'x';
  },
  (config) => {
    config.provider_accounts.github['github-primary'].installation_id = 0;
  },
  (config) => {
    config.provider_accounts.github['github-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].environments = ['Production'];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].repositories = [];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].repositories = ['../repo'];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].repositories = [
      'tyj1987/broker',
      'TYJ1987/BROKER',
    ];
  },
  (config) => {
    config.provider_accounts.github['github-primary'].environments = ['production', 'production'];
  },
  (config) => {
    config.operation_policies.github['repo.read'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareGitHubRuntimeExecutors({ config, createSignerClient }),
    expectRuntimeError,
  );
}

const tooManyAccounts = validConfig();
tooManyAccounts.provider_accounts.github = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    {
      client_id: 'Iv1.runtime-test',
      installation_id: index + 1,
      environments: ['production'],
      repositories: ['tyj1987/broker'],
    },
  ]),
);
await assert.rejects(
  prepareGitHubRuntimeExecutors({ config: tooManyAccounts, createSignerClient }),
  expectRuntimeError,
);
const tooManyRepositories = validConfig();
tooManyRepositories.provider_accounts.github['github-primary'].repositories = Array.from(
  { length: 101 },
  (_, index) => `tyj1987/repo-${index}`,
);
await assert.rejects(
  prepareGitHubRuntimeExecutors({ config: tooManyRepositories, createSignerClient }),
  expectRuntimeError,
);

await assert.rejects(
  prepareGitHubRuntimeExecutors({
    config: validConfig(),
    createSignerClient: () => null,
  }),
  expectRuntimeError,
);
await assert.rejects(
  prepareGitHubRuntimeExecutors({
    config: validConfig(),
    createSignerClient: () => ({
      probe: async () => {
        throw new Error('canary-probe');
      },
      sign: async () => Buffer.alloc(256),
    }),
  }),
  (error) => expectRuntimeError(error) && !error.message.includes('canary'),
);

const target = new Map([
  ['broker.tools.inspect@1.0.0', async () => ({})],
  ['github.old@1.0.0', async () => ({})],
]);
assert.equal(commitGitHubRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('github.old@1.0.0'), false);
assert.equal(target.has('github.repository.read@1.0.0'), true);
assert.throws(() => commitGitHubRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitGitHubRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(GITHUB_RUNTIME_CONTRACT, {
  supported_operations: [
    'repo.read',
    'branches.list',
    'commits.list',
    'issues.list',
    'pull_request.create',
    'workflow_runs.list',
  ],
  account_binding_fields: ['client_id', 'installation_id', 'environments', 'repositories'],
  maximum_accounts: 64,
  maximum_repositories_per_account: 100,
  private_key_configuration_supported: false,
  requires_contract_verified_policy: true,
});

const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareGitHubRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitGitHubRuntimeExecutors\(taskExecutors, prepared\.githubExecutors\)/,
);

console.log(
  'github runtime: verified policies, account binding, signer probe and atomic executor commit passed',
);
