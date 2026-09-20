import { createLocalProviderCredentialClient } from '../lib/local-provider-credential-client.js';
import { createDeepSeekModelsListExecutor } from './deepseek-models-list-executor.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['environments']);
const EXECUTORS = new Map([
  ['models.list', ['deepseek.models.list@1.0.0', createDeepSeekModelsListExecutor]],
]);

export class DeepSeekRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeepSeekRuntimeConfigError';
  }
}

function invalid(message) {
  throw new DeepSeekRuntimeConfigError(message);
}

function activeOperations(config) {
  const policies = config?.operation_policies?.deepseek;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('DeepSeek operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified DeepSeek operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified DeepSeek operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.deepseek;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified DeepSeek operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('DeepSeek provider account bindings are invalid');
  }
  const accounts = new Map();
  for (const [accountRef, binding] of entries) {
    if (
      !ACCOUNT_REF_RE.test(accountRef) ||
      !binding ||
      typeof binding !== 'object' ||
      Array.isArray(binding) ||
      Object.keys(binding).some((key) => !BINDING_FIELDS.has(key)) ||
      !Array.isArray(binding.environments) ||
      binding.environments.length < 1 ||
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment))
    ) {
      invalid('DeepSeek provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    if (environments.length !== binding.environments.length) {
      invalid('DeepSeek provider account binding contains duplicates');
    }
    accounts.set(accountRef, Object.freeze({ environments: Object.freeze(environments) }));
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !accounts.has(accountRef))) {
      invalid('A verified DeepSeek operation references an unknown provider account');
    }
  }
  return accounts;
}

function createTokenProvider(accounts, credentialClient) {
  return async function tokenProvider({
    account_ref: accountRef,
    environment,
    resource_ref,
    execution_id: executionId,
    request_binding: requestBinding,
    signal,
  }) {
    const binding = accounts.get(accountRef);
    if (
      !binding ||
      !binding.environments.includes(environment) ||
      resource_ref !== 'model-catalog'
    ) {
      throw new DeepSeekRuntimeConfigError('DeepSeek provider account binding is unavailable');
    }
    const lease = await credentialClient.lease({
      operation_id: 'models.list',
      account_ref: accountRef,
      environment,
      resource_ref,
      execution_id: executionId,
      request_binding: requestBinding,
      signal,
    });
    return { ...lease, account_ref: accountRef, environment, resource_ref };
  };
}

export async function prepareDeepSeekRuntimeExecutors({
  config,
  createCredentialClient = createLocalProviderCredentialClient,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.deepseek !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified DeepSeek operations require provider account bindings');

  let credentialClient;
  try {
    credentialClient = createCredentialClient({ provider: 'deepseek' });
    if (
      !credentialClient ||
      typeof credentialClient.probe !== 'function' ||
      typeof credentialClient.lease !== 'function'
    ) {
      invalid('DeepSeek credential client is invalid');
    }
    await credentialClient.probe();
  } catch (error) {
    if (error instanceof DeepSeekRuntimeConfigError) throw error;
    invalid('Verified DeepSeek operations require an available isolated credential service');
  }

  const tokenProvider = createTokenProvider(accounts, credentialClient);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({ tokenProvider, resolveHost, requestImpl, timeoutMs, now }));
  }
  return executors;
}

export function commitDeepSeekRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('DeepSeek runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('deepseek.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const DEEPSEEK_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
