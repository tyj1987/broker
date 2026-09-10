import { createCloudflareZonesListExecutor } from './cloudflare-zones-list-executor.js';
import { createLocalProviderCredentialClient } from '../lib/local-provider-credential-client.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ACCOUNT_ID_RE = /^[a-f0-9]{32}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['account_id', 'environments']);
const EXECUTORS = new Map([
  ['zones.list', ['cloudflare.zones.list@1.0.0', createCloudflareZonesListExecutor]],
]);

export class CloudflareRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CloudflareRuntimeConfigError';
  }
}

function invalid(message) {
  throw new CloudflareRuntimeConfigError(message);
}

function activeOperations(config) {
  const policies = config?.operation_policies?.cloudflare;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('Cloudflare operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified Cloudflare operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified Cloudflare operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.cloudflare;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified Cloudflare operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('Cloudflare provider account bindings are invalid');
  }
  const normalized = new Map();
  for (const [accountRef, binding] of entries) {
    if (
      !ACCOUNT_REF_RE.test(accountRef) ||
      !binding ||
      typeof binding !== 'object' ||
      Array.isArray(binding) ||
      Object.keys(binding).some((key) => !BINDING_FIELDS.has(key)) ||
      !ACCOUNT_ID_RE.test(binding.account_id || '') ||
      !Array.isArray(binding.environments) ||
      binding.environments.length < 1 ||
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment))
    ) {
      invalid('Cloudflare provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    if (environments.length !== binding.environments.length) {
      invalid('Cloudflare provider account binding contains duplicates');
    }
    normalized.set(
      accountRef,
      Object.freeze({
        account_id: binding.account_id,
        environments: Object.freeze(environments),
      }),
    );
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !normalized.has(accountRef))) {
      invalid('A verified Cloudflare operation references an unknown provider account');
    }
  }
  return normalized;
}

function createTokenProvider(accounts, credentialClient) {
  return async function tokenProvider({
    account_ref: accountRef,
    environment,
    account_id: accountId,
    execution_id: executionId,
    request_binding: requestBinding,
    signal,
  }) {
    const binding = accounts.get(accountRef);
    if (
      !binding ||
      binding.account_id !== accountId ||
      !binding.environments.includes(environment)
    ) {
      throw new CloudflareRuntimeConfigError('Cloudflare provider account binding is unavailable');
    }
    const lease = await credentialClient.lease({
      operation_id: 'zones.list',
      account_ref: accountRef,
      environment,
      resource_ref: accountId,
      execution_id: executionId,
      request_binding: requestBinding,
      signal,
    });
    return { token: lease.token, account_id: binding.account_id };
  };
}

export async function prepareCloudflareRuntimeExecutors({
  config,
  createCredentialClient = createLocalProviderCredentialClient,
  resolveHost,
  requestImpl,
  timeoutMs,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.cloudflare !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified Cloudflare operations require provider account bindings');

  let credentialClient;
  try {
    credentialClient = createCredentialClient({ provider: 'cloudflare' });
    if (
      !credentialClient ||
      typeof credentialClient.probe !== 'function' ||
      typeof credentialClient.lease !== 'function'
    ) {
      invalid('Cloudflare credential client is invalid');
    }
    await credentialClient.probe();
  } catch (error) {
    if (error instanceof CloudflareRuntimeConfigError) throw error;
    invalid('Verified Cloudflare operations require an available isolated credential service');
  }

  const tokenProvider = createTokenProvider(accounts, credentialClient);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({ tokenProvider, resolveHost, requestImpl, timeoutMs }));
  }
  return executors;
}

export function commitCloudflareRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('Cloudflare runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('cloudflare.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const CLOUDFLARE_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  plaintext_token_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_credential_service: true,
});
