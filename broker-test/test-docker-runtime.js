import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import {
  DOCKER_RUNTIME_CONTRACT,
  DockerRuntimeConfigError,
  commitDockerRuntimeExecutors,
  prepareDockerRuntimeExecutors,
} from '../broker/adapters/docker-runtime.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const NOW = 2_000_000_000_000;
const REPOSITORY = 'tyj1987/broker';
const EXECUTION_ID = '12345678-1234-4123-8123-123456789abc';
const REQUEST_BINDING = 'a'.repeat(43);
const basePolicy = {
  enabled: true,
  contract_verified: true,
  execution_mode: 'adapter',
  accounts: ['docker-primary'],
};
const validConfig = () => ({
  operation_policies: { docker: { 'repository.tags.list': { ...basePolicy } } },
  provider_accounts: {
    docker: {
      'docker-primary': {
        environments: ['production'],
        repositories: [REPOSITORY],
      },
    },
  },
});
const expectRuntimeError = (error) => error instanceof DockerRuntimeConfigError;
let factoryCalls = 0;
let probeCalls = 0;
const leaseInputs = [];
const createCredentialClient = (options) => {
  factoryCalls += 1;
  assert.deepEqual(options, { provider: 'docker' });
  return {
    probe: async () => {
      probeCalls += 1;
      return true;
    },
    lease: async (input) => {
      leaseInputs.push(input);
      return {
        token: 'runtime-docker-token',
        expires_at: new Date(NOW + 60_000).toISOString(),
      };
    },
  };
};
const requests = [];
const requestImpl = (options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = () => {
    requests.push(options);
    const response = Readable.from([JSON.stringify({ name: REPOSITORY, tags: ['latest'] })]);
    response.statusCode = 200;
    response.headers = { 'content-type': 'application/json' };
    queueMicrotask(() => callback(response));
  };
  return request;
};

assert.equal(
  (
    await prepareDockerRuntimeExecutors({
      config: {},
      createCredentialClient: () => {
        throw new Error('unused');
      },
    })
  ).size,
  0,
);
assert.equal(
  (
    await prepareDockerRuntimeExecutors({
      config: {
        operation_policies: {
          docker: { 'repository.tags.list': { ...basePolicy, contract_verified: false } },
        },
      },
      createCredentialClient: () => {
        throw new Error('unused');
      },
    })
  ).size,
  0,
);

const executors = await prepareDockerRuntimeExecutors({
  config: validConfig(),
  createCredentialClient,
  resolveHost: async () => [{ address: '54.85.107.53', family: 4 }],
  requestImpl,
  now: () => NOW,
});
assert.deepEqual([...executors.keys()], ['docker.repository.tags.list@1.0.0']);
assert.equal(factoryCalls, 1);
assert.equal(probeCalls, 1);
const signal = new AbortController().signal;
const result = await executors.get('docker.repository.tags.list@1.0.0')(
  { resource_ref: REPOSITORY, namespace: 'tyj1987', repository: 'broker' },
  {
    accountRef: 'docker-primary',
    environment: 'production',
    signal,
    execution: {
      tool: 'docker.repository.tags.list@1.0.0',
      target: REPOSITORY,
      environment: 'production',
      execution_id: EXECUTION_ID,
      request_binding: REQUEST_BINDING,
    },
  },
);
assert.deepEqual(result, { name: REPOSITORY, tags: ['latest'] });
assert.deepEqual(leaseInputs[0], {
  operation_id: 'repository.tags.list',
  account_ref: 'docker-primary',
  environment: 'production',
  resource_ref: REPOSITORY,
  execution_id: EXECUTION_ID,
  request_binding: REQUEST_BINDING,
  signal,
});
assert.equal(requests[0].headers.authorization, 'Bearer runtime-docker-token');
assert.equal(JSON.stringify(result).includes('runtime-docker-token'), false);

await assert.rejects(
  executors.get('docker.repository.tags.list@1.0.0')(
    { resource_ref: 'other/repo', namespace: 'other', repository: 'repo' },
    {
      accountRef: 'docker-primary',
      environment: 'production',
      execution: {
        tool: 'docker.repository.tags.list@1.0.0',
        target: 'other/repo',
        environment: 'production',
        execution_id: EXECUTION_ID,
        request_binding: REQUEST_BINDING,
      },
    },
  ),
  (error) => error instanceof V2Error && error.code === 'docker_credential_unavailable',
);

for (const mutate of [
  (config) => {
    config.operation_policies.docker['repository.tags.list'].execution_mode = 'browser';
  },
  (config) => {
    config.operation_policies.docker.unknown = { ...basePolicy };
  },
  (config) => {
    config.operation_policies.docker['repository.tags.list'].accounts = [];
  },
  (config) => {
    delete config.provider_accounts;
  },
  (config) => {
    config.provider_accounts.docker = [];
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].token = 'forbidden';
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].environments = [];
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].environments = ['Production'];
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].repositories = [];
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].repositories = ['../repo'];
  },
  (config) => {
    config.provider_accounts.docker['docker-primary'].repositories = [REPOSITORY, REPOSITORY];
  },
  (config) => {
    config.operation_policies.docker['repository.tags.list'].accounts = ['missing'];
  },
]) {
  const config = validConfig();
  mutate(config);
  await assert.rejects(
    prepareDockerRuntimeExecutors({ config, createCredentialClient }),
    expectRuntimeError,
  );
}

const tooManyAccounts = validConfig();
tooManyAccounts.provider_accounts.docker = Object.fromEntries(
  Array.from({ length: 65 }, (_, index) => [
    `account-${index}`,
    {
      environments: ['production'],
      repositories: [`tyj1987/repo-${index}`],
    },
  ]),
);
await assert.rejects(
  prepareDockerRuntimeExecutors({ config: tooManyAccounts, createCredentialClient }),
  expectRuntimeError,
);
const tooManyRepositories = validConfig();
tooManyRepositories.provider_accounts.docker['docker-primary'].repositories = Array.from(
  { length: 101 },
  (_, index) => `tyj1987/repo-${index}`,
);
await assert.rejects(
  prepareDockerRuntimeExecutors({ config: tooManyRepositories, createCredentialClient }),
  expectRuntimeError,
);
await assert.rejects(
  prepareDockerRuntimeExecutors({ config: validConfig(), createCredentialClient: () => null }),
  expectRuntimeError,
);
await assert.rejects(
  prepareDockerRuntimeExecutors({
    config: validConfig(),
    createCredentialClient: () => ({
      probe: async () => {
        throw new Error('canary-probe');
      },
      lease: async () => ({}),
    }),
  }),
  (error) => expectRuntimeError(error) && !error.message.includes('canary'),
);

const target = new Map([
  ['broker.tools.inspect@1.0.0', async () => ({})],
  ['docker.old@1.0.0', async () => ({})],
]);
assert.equal(commitDockerRuntimeExecutors(target, executors), target);
assert.equal(target.has('broker.tools.inspect@1.0.0'), true);
assert.equal(target.has('docker.old@1.0.0'), false);
assert.equal(target.has('docker.repository.tags.list@1.0.0'), true);
assert.throws(() => commitDockerRuntimeExecutors({}, executors), TypeError);
assert.throws(() => commitDockerRuntimeExecutors(target, {}), TypeError);

assert.deepEqual(DOCKER_RUNTIME_CONTRACT, {
  supported_operations: ['repository.tags.list'],
  account_binding_fields: ['environments', 'repositories'],
  maximum_accounts: 64,
  maximum_repositories_per_account: 100,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
const serverSource = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
assert.match(serverSource, /await prepareDockerRuntimeExecutors\(\{ config: cfg \}\)/);
assert.match(
  serverSource,
  /commitDockerRuntimeExecutors\(taskExecutors, prepared\.dockerExecutors\)/,
);

console.log(
  'docker runtime: verified policy, repository binding, credential probe and atomic commit passed',
);
