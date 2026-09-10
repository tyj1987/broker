import { createLocalProviderCredentialClient } from '../lib/local-provider-credential-client.js';
import { createOpenAIModelsListExecutor } from './openai-models-list-executor.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['project_id', 'environments']);
const EXECUTORS = new Map([
  ['models.list', ['openai.models.list@1.0.0', createOpenAIModelsListExecutor]],
]);

export class OpenAIRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OpenAIRuntimeConfigError';
  }
}

function invalid(message) {
  throw new OpenAIRuntimeConfigError(message);
}

function activeOperations(config) {
  const policies = config?.operation_policies?.openai;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('OpenAI operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified OpenAI operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified OpenAI operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.openai;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified OpenAI operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('OpenAI provider account bindings are invalid');
  }
  const accounts = new Map();
  for (const [accountRef, binding] of entries) {
    if (
      !ACCOUNT_REF_RE.test(accountRef) ||
      !binding ||
      typeof binding !== 'object' ||
      Array.isArray(binding) ||
      Object.keys(binding).some((key) => !BINDING_FIELDS.has(key)) ||
      !PROJECT_ID_RE.test(binding.project_id || '') ||
      !Array.isArray(binding.environments) ||
      binding.environments.length < 1 ||
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment))
    ) {
      invalid('OpenAI provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    if (environments.length !== binding.environments.length) {
      invalid('OpenAI provider account binding contains duplicates');
    }
    accounts.set(
      accountRef,
      Object.freeze({
        project_id: binding.project_id,
        environments: Object.freeze(environments),
      }),
    );
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !accounts.has(accountRef))) {
      invalid('A verified OpenAI operation references an unknown provider account');
    }
  }
  return accounts;
}

function createTokenProvider(accounts, credentialClient) {
  return async function tokenProvider({
    account_ref: accountRef,
    environment,
    resource_ref: projectId,
    execution_id: executionId,
    request_binding: requestBinding,
    signal,
  }) {
    const binding = accounts.get(accountRef);
    if (
      !binding ||
      binding.project_id !== projectId ||
      !binding.environments.includes(environment)
    ) {
      throw new OpenAIRuntimeConfigError('OpenAI provider account binding is unavailable');
    }
    const lease = await credentialClient.lease({
      operation_id: 'models.list',
      account_ref: accountRef,
      environment,
      resource_ref: projectId,
      execution_id: executionId,
      request_binding: requestBinding,
      signal,
    });
    return { ...lease, account_ref: accountRef, environment, resource_ref: projectId };
  };
}

export async function prepareOpenAIRuntimeExecutors({
  config,
  createCredentialClient = createLocalProviderCredentialClient,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.openai !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified OpenAI operations require provider account bindings');

  let credentialClient;
  try {
    credentialClient = createCredentialClient({ provider: 'openai' });
    if (
      !credentialClient ||
      typeof credentialClient.probe !== 'function' ||
      typeof credentialClient.lease !== 'function'
    ) {
      invalid('OpenAI credential client is invalid');
    }
    await credentialClient.probe();
  } catch (error) {
    if (error instanceof OpenAIRuntimeConfigError) throw error;
    invalid('Verified OpenAI operations require an available isolated credential service');
  }

  const tokenProvider = createTokenProvider(accounts, credentialClient);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({ tokenProvider, resolveHost, requestImpl, timeoutMs, now }));
  }
  return executors;
}

export function commitOpenAIRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('OpenAI runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('openai.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const OPENAI_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
  preferred_identity: 'workload_identity_federation',
});
