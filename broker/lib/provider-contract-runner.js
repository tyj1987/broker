import { redactDeep } from './redact.js';

const SAFE_ID_RE = /^[a-z0-9][a-z0-9._:-]{2,127}$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9._:-]{16,96}$/;
const GITHUB_SEGMENT_RE = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$/;
const ALIYUN_REGION_RE = /^[a-z][a-z0-9-]{1,62}[a-z0-9]$/;
const TASK_ID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const ALIYUN_INSTANCE_KEYS = new Set([
  'instance_id',
  'instance_name',
  'status',
  'region_id',
  'zone_id',
  'instance_type',
]);
const ROOT_KEYS = new Set([
  'version',
  'provider',
  'tool_name',
  'tool_version',
  'account_ref',
  'wrong_account_ref',
  'environment',
  'parameters',
  'wrong_resource_ref',
  'idempotency_prefix',
]);
const PROVIDERS = Object.freeze({
  github: Object.freeze({
    toolName: 'github.repository.read',
    operationId: 'repo.read',
    parameterKeys: new Set(['resource_ref', 'owner', 'repo']),
  }),
  aliyun: Object.freeze({
    toolName: 'aliyun.ecs.instances.list',
    operationId: 'ecs.instances.list',
    parameterKeys: new Set(['resource_ref', 'region_id', 'max_results']),
  }),
});

export class ProviderContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProviderContractError';
    this.code = code;
  }
}

function fail(code) {
  throw new ProviderContractError(code);
}

function exactObject(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function validResourceRef(provider, value) {
  if (provider === 'github') {
    const parts = typeof value === 'string' ? value.split('/') : [];
    return parts.length === 2 && parts.every((part) => GITHUB_SEGMENT_RE.test(part));
  }
  return SAFE_ID_RE.test(value || '');
}

function validateParameters(provider, parameters) {
  const definition = PROVIDERS[provider];
  if (!exactObject(parameters, definition.parameterKeys)) fail('contract_plan_invalid');
  if (!validResourceRef(provider, parameters.resource_ref)) fail('contract_plan_invalid');
  if (provider === 'github') {
    if (
      !GITHUB_SEGMENT_RE.test(parameters.owner || '') ||
      !GITHUB_SEGMENT_RE.test(parameters.repo || '') ||
      parameters.resource_ref.toLowerCase() !==
        `${parameters.owner}/${parameters.repo}`.toLowerCase()
    ) {
      fail('contract_plan_invalid');
    }
    return;
  }
  if (
    !ALIYUN_REGION_RE.test(parameters.region_id || '') ||
    !Number.isSafeInteger(parameters.max_results) ||
    parameters.max_results < 1 ||
    parameters.max_results > 20
  ) {
    fail('contract_plan_invalid');
  }
}

export function validateProviderContractPlan(input) {
  if (
    !exactObject(input, ROOT_KEYS) ||
    input.version !== 1 ||
    !Object.hasOwn(PROVIDERS, input.provider) ||
    input.tool_name !== PROVIDERS[input.provider]?.toolName ||
    input.tool_version !== '1.0.0' ||
    !SAFE_ID_RE.test(input.account_ref || '') ||
    !SAFE_ID_RE.test(input.wrong_account_ref || '') ||
    input.account_ref === input.wrong_account_ref ||
    !['staging', 'production'].includes(input.environment) ||
    !validResourceRef(input.provider, input.wrong_resource_ref) ||
    input.wrong_resource_ref === input.parameters?.resource_ref ||
    !IDEMPOTENCY_RE.test(input.idempotency_prefix || '')
  ) {
    fail('contract_plan_invalid');
  }
  validateParameters(input.provider, input.parameters);
  return structuredClone(input);
}

function validTaskBinding(task, plan, state) {
  return (
    task &&
    typeof task === 'object' &&
    TASK_ID_RE.test(task.id || '') &&
    task.tool === plan.tool_name &&
    task.tool_version === plan.tool_version &&
    task.account_ref === plan.account_ref &&
    task.environment === plan.environment &&
    task.state === state
  );
}

function validateGitHubResult(result, plan) {
  if (
    !exactObject(result, new Set(['id', 'full_name', 'visibility', 'archived'])) ||
    !Number.isSafeInteger(result.id) ||
    result.id < 1 ||
    typeof result.full_name !== 'string' ||
    result.full_name.toLowerCase() !==
      `${plan.parameters.owner}/${plan.parameters.repo}`.toLowerCase() ||
    !['public', 'private', 'internal'].includes(result.visibility) ||
    typeof result.archived !== 'boolean'
  ) {
    fail('contract_result_invalid');
  }
}

function validateAliyunResult(result, plan) {
  if (
    !result ||
    typeof result !== 'object' ||
    Array.isArray(result) ||
    !Array.isArray(result.instances) ||
    !Number.isSafeInteger(result.total_count) ||
    result.total_count < result.instances.length ||
    result.instances.length > plan.parameters.max_results ||
    Object.keys(result).some((key) => !['instances', 'total_count', 'next_token'].includes(key)) ||
    result.instances.some(
      (instance) =>
        !exactObject(instance, ALIYUN_INSTANCE_KEYS) ||
        Object.values(instance).some(
          (value) => typeof value !== 'string' || value.length < 1 || value.length > 256,
        ) ||
        instance.region_id !== plan.parameters.region_id,
    )
  ) {
    fail('contract_result_invalid');
  }
}

function validateSafeResult(result, plan) {
  let redactedJSON;
  let originalJSON;
  try {
    redactedJSON = JSON.stringify(redactDeep(structuredClone(result)));
    originalJSON = JSON.stringify(result);
  } catch {
    fail('contract_result_invalid');
  }
  if (redactedJSON !== originalJSON) fail('contract_result_sensitive');
  if (plan.provider === 'github') validateGitHubResult(result, plan);
  else validateAliyunResult(result, plan);
}

async function createTask(callBroker, plan, accountRef, parameters, suffix) {
  return callBroker('/api/v2/tasks', {
    method: 'POST',
    body: {
      tool: plan.tool_name,
      tool_version: plan.tool_version,
      account_ref: accountRef,
      environment: plan.environment,
      parameters,
      idempotency_key: `${plan.idempotency_prefix}:${suffix}`,
    },
  });
}

async function cancelUnexpectedTask(callBroker, task) {
  if (!TASK_ID_RE.test(task?.id || '')) return;
  try {
    await callBroker(`/api/v2/tasks/${task.id}/cancel`, { method: 'POST', body: {} });
  } catch {
    // The boundary failure is retained even when cleanup is unavailable.
  }
}

async function requireDenied(callBroker, plan, accountRef, parameters, suffix) {
  try {
    const task = await createTask(callBroker, plan, accountRef, parameters, suffix);
    await cancelUnexpectedTask(callBroker, task);
    fail('contract_negative_boundary_failed');
  } catch (error) {
    if (error instanceof ProviderContractError) throw error;
    if (error?.code !== 'forbidden') fail('contract_negative_result_invalid');
  }
}

function parametersForResource(plan, resourceRef) {
  const parameters = { ...structuredClone(plan.parameters), resource_ref: resourceRef };
  if (plan.provider === 'github') {
    [parameters.owner, parameters.repo] = resourceRef.split('/');
  }
  return parameters;
}

function validateDiscovery(response, plan) {
  const definition = PROVIDERS[plan.provider];
  if (!response || response.registry_version !== 1 || !Array.isArray(response.tools)) {
    fail('contract_discovery_invalid');
  }
  const matches = response.tools.filter(
    (tool) => tool?.name === plan.tool_name && tool?.version === plan.tool_version,
  );
  if (
    matches.length !== 1 ||
    matches[0].provider !== plan.provider ||
    matches[0].operation_id !== definition.operationId ||
    matches[0].agent_execution !== true ||
    !matches[0].environments?.includes(plan.environment)
  ) {
    fail('contract_tool_unavailable');
  }
}

export function createProviderContractRunner({ callBroker } = {}) {
  if (typeof callBroker !== 'function') {
    throw new TypeError('Provider contract runner requires a Broker client');
  }
  return async function runProviderContract(input) {
    const plan = validateProviderContractPlan(input);
    let discovery;
    try {
      discovery = await callBroker('/api/v2/tools', { method: 'GET' });
    } catch {
      fail('contract_broker_unavailable');
    }
    validateDiscovery(discovery, plan);

    let created;
    try {
      created = await createTask(
        callBroker,
        plan,
        plan.account_ref,
        structuredClone(plan.parameters),
        'positive',
      );
    } catch {
      fail('contract_positive_create_failed');
    }
    if (!validTaskBinding(created, plan, 'READY')) fail('contract_positive_task_invalid');

    let completed;
    try {
      completed = await callBroker(`/api/v2/tasks/${created.id}/run`, {
        method: 'POST',
        body: {},
      });
    } catch {
      fail('contract_positive_run_failed');
    }
    if (!validTaskBinding(completed, plan, 'SUCCEEDED')) fail('contract_positive_task_invalid');
    validateSafeResult(completed.result, plan);

    await requireDenied(
      callBroker,
      plan,
      plan.wrong_account_ref,
      structuredClone(plan.parameters),
      'wrong-account',
    );
    await requireDenied(
      callBroker,
      plan,
      plan.account_ref,
      parametersForResource(plan, plan.wrong_resource_ref),
      'wrong-resource',
    );

    return Object.freeze({
      version: 1,
      provider: plan.provider,
      operation_id: PROVIDERS[plan.provider].operationId,
      environment: plan.environment,
      status: 'passed',
      checks: Object.freeze([
        'tool_discovery',
        'bounded_read',
        'safe_output',
        'wrong_account_denied',
        'wrong_resource_denied',
      ]),
    });
  };
}
