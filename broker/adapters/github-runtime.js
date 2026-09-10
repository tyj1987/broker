import { createGitHubBranchesListExecutor } from './github-branches-list-executor.js';
import { createGitHubCommitsListExecutor } from './github-commits-list-executor.js';
import { createGitHubIssuesListExecutor } from './github-issues-list-executor.js';
import { createGitHubRepositoryReadExecutor } from './github-repository-read-executor.js';
import { createGitHubWorkflowRunsListExecutor } from './github-workflow-runs-list-executor.js';
import { createLocalSignerClient } from '../lib/local-signer-client.js';

const ACCOUNT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{3,128}$/;
const REPOSITORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const BINDING_FIELDS = new Set(['client_id', 'installation_id', 'environments', 'repositories']);
const EXECUTORS = new Map([
  ['repo.read', ['github.repository.read@1.0.0', createGitHubRepositoryReadExecutor]],
  ['branches.list', ['github.branches.list@1.0.0', createGitHubBranchesListExecutor]],
  ['commits.list', ['github.commits.list@1.0.0', createGitHubCommitsListExecutor]],
  ['issues.list', ['github.issues.list@1.0.0', createGitHubIssuesListExecutor]],
  ['workflow_runs.list', ['github.workflow-runs.list@1.0.0', createGitHubWorkflowRunsListExecutor]],
]);

export class GitHubRuntimeConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GitHubRuntimeConfigError';
  }
}

function invalid(message) {
  throw new GitHubRuntimeConfigError(message);
}

function activeOperations(config) {
  const policies = config?.operation_policies?.github;
  if (policies === undefined) return [];
  if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
    invalid('GitHub operation policies are invalid');
  }
  const active = [];
  for (const [operationId, policy] of Object.entries(policies)) {
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) continue;
    if (policy.enabled !== true || policy.contract_verified !== true) continue;
    if (policy.execution_mode !== 'adapter' || !EXECUTORS.has(operationId)) {
      invalid('A verified GitHub operation does not have a supported adapter runtime');
    }
    if (
      !Array.isArray(policy.accounts) ||
      policy.accounts.length < 1 ||
      policy.accounts.some((account) => !ACCOUNT_REF_RE.test(account || ''))
    ) {
      invalid('A verified GitHub operation has invalid account bindings');
    }
    active.push({ operationId, accounts: [...new Set(policy.accounts)] });
  }
  return active;
}

function normalizeAccounts(config, active) {
  const source = config?.provider_accounts?.github;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    invalid('Verified GitHub operations require provider account bindings');
  }
  const entries = Object.entries(source);
  if (entries.length < 1 || entries.length > 64) {
    invalid('GitHub provider account bindings are invalid');
  }
  const normalized = new Map();
  for (const [accountRef, binding] of entries) {
    if (
      !ACCOUNT_REF_RE.test(accountRef) ||
      !binding ||
      typeof binding !== 'object' ||
      Array.isArray(binding) ||
      Object.keys(binding).some((key) => !BINDING_FIELDS.has(key)) ||
      !CLIENT_ID_RE.test(binding.client_id || '') ||
      !Number.isSafeInteger(binding.installation_id) ||
      binding.installation_id < 1 ||
      !Array.isArray(binding.environments) ||
      binding.environments.length < 1 ||
      binding.environments.some((environment) => !ENVIRONMENTS.has(environment)) ||
      !Array.isArray(binding.repositories) ||
      binding.repositories.length < 1 ||
      binding.repositories.length > 100 ||
      binding.repositories.some((repository) => !REPOSITORY_RE.test(repository || ''))
    ) {
      invalid('GitHub provider account binding is invalid');
    }
    const environments = [...new Set(binding.environments)];
    const repositories = [...new Map(
      binding.repositories.map((repository) => [repository.toLowerCase(), repository]),
    ).values()];
    if (
      environments.length !== binding.environments.length ||
      repositories.length !== binding.repositories.length
    ) {
      invalid('GitHub provider account binding contains duplicates');
    }
    normalized.set(accountRef, Object.freeze({
      client_id: binding.client_id,
      installation_id: binding.installation_id,
      environments: Object.freeze(environments),
      repositories: Object.freeze(repositories),
    }));
  }
  for (const operation of active) {
    if (operation.accounts.some((accountRef) => !normalized.has(accountRef))) {
      invalid('A verified GitHub operation references an unknown provider account');
    }
  }
  return normalized;
}

function createAccountResolver(accounts) {
  return async function resolveAccount({ account_ref, environment, repository }) {
    const binding = accounts.get(account_ref);
    if (
      !binding ||
      !binding.environments.includes(environment) ||
      !binding.repositories.some((candidate) => candidate.toLowerCase() === repository.toLowerCase())
    ) {
      throw new GitHubRuntimeConfigError('GitHub provider account binding is unavailable');
    }
    return {
      account_ref,
      environment,
      client_id: binding.client_id,
      installation_id: binding.installation_id,
      repositories: [...binding.repositories],
    };
  };
}

export async function prepareGitHubRuntimeExecutors({
  config,
  createSignerClient = createLocalSignerClient,
  resolveHost,
  requestImpl,
  now,
  timeoutMs,
} = {}) {
  const active = activeOperations(config);
  const hasAccountConfiguration = config?.provider_accounts?.github !== undefined;
  const accounts = hasAccountConfiguration ? normalizeAccounts(config, active) : null;
  if (active.length === 0) return new Map();
  if (!accounts) invalid('Verified GitHub operations require provider account bindings');
  let signerClient;
  try {
    signerClient = createSignerClient();
    if (
      !signerClient ||
      typeof signerClient.probe !== 'function' ||
      typeof signerClient.sign !== 'function'
    ) {
      invalid('GitHub signer client is invalid');
    }
    await signerClient.probe();
  } catch (error) {
    if (error instanceof GitHubRuntimeConfigError) throw error;
    invalid('Verified GitHub operations require an available isolated signer');
  }

  const accountResolver = createAccountResolver(accounts);
  const executors = new Map();
  for (const { operationId } of active) {
    const [tool, factory] = EXECUTORS.get(operationId);
    executors.set(tool, factory({
      signer: signerClient.sign,
      accountResolver,
      resolveHost,
      requestImpl,
      now,
      timeoutMs,
    }));
  }
  return executors;
}

export function commitGitHubRuntimeExecutors(target, prepared) {
  if (!(target instanceof Map) || !(prepared instanceof Map)) {
    throw new TypeError('GitHub runtime executor commit requires maps');
  }
  for (const key of target.keys()) {
    if (key.startsWith('github.')) target.delete(key);
  }
  for (const [key, executor] of prepared) target.set(key, executor);
  return target;
}

export const GITHUB_RUNTIME_CONTRACT = Object.freeze({
  supported_operations: Object.freeze([...EXECUTORS.keys()]),
  account_binding_fields: Object.freeze([...BINDING_FIELDS]),
  maximum_accounts: 64,
  maximum_repositories_per_account: 100,
  private_key_configuration_supported: false,
  requires_contract_verified_policy: true,
});
