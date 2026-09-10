import { createDockerRepositoryTagsListExecutor } from './docker-repository-tags-list-executor.js';
import { createLocalProviderCredentialClient } from '../lib/local-provider-credential-client.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const COMPONENT_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['environments', 'repositories']);
const EXECUTORS = new Map([
  [
    'repository.tags.list',
    ['docker.repository.tags.list@1.0.0', createDockerRepositoryTagsListExecutor],
  ],
]);

export class DockerRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DockerRuntimeConfigError';
  }
}

function invalid(message) {
  throw new DockerRuntimeConfigError(message);
}

function validRepository(value) {
  if (typeof value !== 'string' || value.length >= 256) return false;
  const parts = value.split('/');
  return parts.length === 2 && parts.every((part) => COMPONENT_RE.test(part));
}

function activeOperations(config) {
  const policies = config?.operation_policies?.docker;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('Docker operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified Docker operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified Docker operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.docker;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified Docker operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('Docker provider account bindings are invalid');
  }
  const normalized = new Map();
  for (const [accountRef, binding] of entries) {
    if (
      !ACCOUNT_REF_RE.test(accountRef) ||
      !binding ||
      typeof binding !== 'object' ||
      Array.isArray(binding) ||
      Object.keys(binding).some((key) => !BINDING_FIELDS.has(key)) ||
      !Array.isArray(binding.environments) ||
      binding.environments.length < 1 ||
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment)) ||
      !Array.isArray(binding.repositories) ||
      binding.repositories.length < 1 ||
      binding.repositories.length > 100 ||
      binding.repositories.some((repository) => !validRepository(repository))
    ) {
      invalid('Docker provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    const repositories = [...new Set(binding.repositories)];
    if (
      environments.length !== binding.environments.length ||
      repositories.length !== binding.repositories.length
    ) {
      invalid('Docker provider account binding contains duplicates');
    }
    normalized.set(
      accountRef,
      Object.freeze({
        environments: Object.freeze(environments),
        repositories: Object.freeze(repositories),
      }),
    );
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !normalized.has(accountRef))) {
      invalid('A verified Docker operation references an unknown provider account');
    }
  }
  return normalized;
}

function createTokenProvider(accounts, credentialClient) {
  return async function tokenProvider({
    account_ref: accountRef,
    environment,
    repository,
    scope,
    execution_id: executionId,
    request_binding: requestBinding,
    signal,
  }) {
    const binding = accounts.get(accountRef);
    if (
      !binding ||
      !binding.environments.includes(environment) ||
      !binding.repositories.includes(repository) ||
      scope !== `repository:${repository}:pull`
    ) {
      throw new DockerRuntimeConfigError('Docker provider account binding is unavailable');
    }
    const lease = await credentialClient.lease({
      operation_id: 'repository.tags.list',
      account_ref: accountRef,
      environment,
      resource_ref: repository,
      execution_id: executionId,
      request_binding: requestBinding,
      signal,
    });
    return { token: lease.token, repository, expires_at: lease.expires_at };
  };
}

export async function prepareDockerRuntimeExecutors({
  config,
  createCredentialClient = createLocalProviderCredentialClient,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.docker !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified Docker operations require provider account bindings');

  let credentialClient;
  try {
    credentialClient = createCredentialClient({ provider: 'docker' });
    if (
      !credentialClient ||
      typeof credentialClient.probe !== 'function' ||
      typeof credentialClient.lease !== 'function'
    ) {
      invalid('Docker credential client is invalid');
    }
    await credentialClient.probe();
  } catch (error) {
    if (error instanceof DockerRuntimeConfigError) throw error;
    invalid('Verified Docker operations require an available isolated credential service');
  }

  const tokenProvider = createTokenProvider(accounts, credentialClient);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({ tokenProvider, resolveHost, requestImpl, timeoutMs, now }));
  }
  return executors;
}

export function commitDockerRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('Docker runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('docker.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const DOCKER_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  maximum_repositories_per_account: 100,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
