import { createLocalTencentSigningClient } from '../lib/local-tencent-signing-client.js';
import { createTencentCvmInstancesListExecutor } from './tencent-cvm-instances-list-executor.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RESOURCE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REGION_RE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['environments', 'regions', 'resources']);
const EXECUTORS = new Map([
  [
    'cvm.instances.list',
    ['tencent.cvm.instances.list@1.0.0', createTencentCvmInstancesListExecutor],
  ],
]);

export class TencentRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TencentRuntimeConfigError';
  }
}

function invalid(message) {
  throw new TencentRuntimeConfigError(message);
}

function activeOperations(config) {
  const policies = config?.operation_policies?.tencent;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('Tencent Cloud operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified Tencent Cloud operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified Tencent Cloud operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.tencent;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified Tencent Cloud operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('Tencent Cloud provider account bindings are invalid');
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
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment)) ||
      !Array.isArray(binding.regions) ||
      binding.regions.length < 1 ||
      binding.regions.length > 32 ||
      binding.regions.some((region) => !REGION_RE.test(region || '')) ||
      !Array.isArray(binding.resources) ||
      binding.resources.length < 1 ||
      binding.resources.length > 64 ||
      binding.resources.some((resource) => !RESOURCE_RE.test(resource || ''))
    ) {
      invalid('Tencent Cloud provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    const regions = [...new Set(binding.regions)];
    const resources = [...new Set(binding.resources)];
    if (
      environments.length !== binding.environments.length ||
      regions.length !== binding.regions.length ||
      resources.length !== binding.resources.length
    ) {
      invalid('Tencent Cloud provider account binding contains duplicates');
    }
    accounts.set(
      accountRef,
      Object.freeze({
        environments: Object.freeze(environments),
        regions: Object.freeze(regions),
        resources: Object.freeze(resources),
      }),
    );
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !accounts.has(accountRef))) {
      invalid('A verified Tencent Cloud operation references an unknown provider account');
    }
  }
  return accounts;
}

function createSignRequest(accounts, signerClient) {
  return async function signRequest(input) {
    const binding = accounts.get(input.account_ref);
    if (
      !binding ||
      !binding.environments.includes(input.environment) ||
      !binding.regions.includes(input.region) ||
      !binding.resources.includes(input.resource_ref)
    ) {
      throw new TencentRuntimeConfigError('Tencent Cloud provider account binding is unavailable');
    }
    return signerClient.sign(input);
  };
}

export async function prepareTencentRuntimeExecutors({
  config,
  createSignerClient = createLocalTencentSigningClient,
  resolveHost,
  requestImpl,
  timeoutMs,
  now,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.tencent !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified Tencent Cloud operations require provider account bindings');

  let signerClient;
  try {
    signerClient = createSignerClient();
    if (
      !signerClient ||
      typeof signerClient.probe !== 'function' ||
      typeof signerClient.sign !== 'function'
    ) {
      invalid('Tencent Cloud signer client is invalid');
    }
    await signerClient.probe();
  } catch (error) {
    if (error instanceof TencentRuntimeConfigError) throw error;
    invalid('Verified Tencent Cloud operations require an available isolated signer');
  }

  const signRequest = createSignRequest(accounts, signerClient);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({ signRequest, resolveHost, requestImpl, timeoutMs, now }));
  }
  return executors;
}

export function commitTencentRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('Tencent Cloud runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('tencent.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const TENCENT_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  maximum_regions_per_account: 32,
  maximum_resources_per_account: 64,
  plaintext_secret_key_configuration_supported: false,
  requires_contract_verified_policy: true,
  requires_isolated_signer: true,
});
