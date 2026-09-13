import assert from 'node:assert/strict';

import {
  ProviderContractError,
  createProviderContractRunner,
  validateProviderContractPlan,
} from '../broker/lib/provider-contract-runner.js';

const taskId = '00000000-0000-4000-8000-000000000101';
const githubAuthority = Object.freeze({
  installation_id_sha256: '1'.repeat(64),
  account_id_sha256: '2'.repeat(64),
  account_login_sha256: '3'.repeat(64),
  target_type: 'Organization',
});
const aliyunAuthority = Object.freeze({
  identity_type: 'AssumedRoleUser',
  account_id_sha256: '4'.repeat(64),
  principal_id_sha256: '5'.repeat(64),
  arn_sha256: '6'.repeat(64),
});

function githubPlan() {
  return {
    version: 2,
    provider: 'github',
    tool_name: 'github.repository.read',
    tool_version: '1.0.0',
    account_ref: 'github-isolated',
    wrong_account_ref: 'github-other',
    environment: 'staging',
    parameters: {
      resource_ref: 'contract-owner/private-contract-repo',
      owner: 'contract-owner',
      repo: 'private-contract-repo',
    },
    wrong_resource_ref: 'contract-owner/other-private-repo',
    idempotency_prefix: 'dq004-github-contract-20260912',
    expected_authority: { ...githubAuthority },
  };
}

function aliyunPlan() {
  return {
    version: 2,
    provider: 'aliyun',
    tool_name: 'aliyun.ecs.instances.list',
    tool_version: '1.0.0',
    account_ref: 'aliyun-isolated',
    wrong_account_ref: 'aliyun-other',
    environment: 'staging',
    parameters: {
      resource_ref: 'ecs-inventory-isolated',
      region_id: 'cn-hangzhou',
      max_results: 5,
    },
    wrong_resource_ref: 'ecs-inventory-other',
    idempotency_prefix: 'dq004-aliyun-contract-20260912',
    expected_authority: { ...aliyunAuthority },
  };
}

function toolFor(plan) {
  return {
    name: plan.tool_name,
    version: plan.tool_version,
    provider: plan.provider,
    operation_id: plan.provider === 'github' ? 'repo.read' : 'ecs.instances.list',
    agent_execution: true,
    environments: ['staging', 'production'],
  };
}

function resultFor(plan) {
  if (plan.provider === 'github') {
    return {
      id: 123,
      full_name: `${plan.parameters.owner}/${plan.parameters.repo}`,
      visibility: 'private',
      archived: false,
      authority: { ...githubAuthority },
    };
  }
  return {
    instances: [
      {
        instance_id: 'i-contract',
        instance_name: 'contract-instance',
        status: 'Stopped',
        region_id: plan.parameters.region_id,
        zone_id: 'cn-hangzhou-h',
        instance_type: 'ecs.t6-c1m1.large',
      },
    ],
    total_count: 1,
    authority: { ...aliyunAuthority },
  };
}

function successfulBroker(plan, { result = resultFor(plan) } = {}) {
  const calls = [];
  const callBroker = async (path, options) => {
    calls.push(structuredClone({ path, options }));
    if (path === '/api/v2/tools') {
      return { registry_version: 1, tools: [toolFor(plan)] };
    }
    if (path === `/api/v2/tasks/${taskId}/run`) {
      return {
        id: taskId,
        tool: plan.tool_name,
        tool_version: plan.tool_version,
        account_ref: plan.account_ref,
        environment: plan.environment,
        state: 'SUCCEEDED',
        result: structuredClone(result),
      };
    }
    if (path === `/api/v2/tasks/${taskId}/cancel`) return { state: 'CANCELLED' };
    if (path === '/api/v2/tasks') {
      if (
        options.body.account_ref === plan.wrong_account_ref ||
        options.body.parameters.resource_ref === plan.wrong_resource_ref
      ) {
        const error = new Error('safe denial');
        error.code = 'forbidden';
        throw error;
      }
      return {
        id: taskId,
        tool: plan.tool_name,
        tool_version: plan.tool_version,
        account_ref: plan.account_ref,
        environment: plan.environment,
        state: 'READY',
      };
    }
    throw new Error('unexpected path');
  };
  return { calls, callBroker };
}

for (const plan of [githubPlan(), aliyunPlan()]) {
  assert.deepEqual(validateProviderContractPlan(plan), plan);
  const broker = successfulBroker(plan);
  const receipt = await createProviderContractRunner({ callBroker: broker.callBroker })(plan);
  assert.deepEqual(receipt, {
    version: 2,
    provider: plan.provider,
    operation_id: plan.provider === 'github' ? 'repo.read' : 'ecs.instances.list',
    environment: 'staging',
    status: 'passed',
    checks: [
      'tool_discovery',
      'authority_identity',
      'authority_match',
      'bounded_read',
      'safe_output',
      'wrong_account_denied',
      'wrong_resource_denied',
    ],
  });
  assert.equal(broker.calls.filter((call) => call.path.endsWith('/run')).length, 1);
  assert.equal(broker.calls.filter((call) => call.path === '/api/v2/tasks').length, 3);
  const wrongResourceCall = broker.calls.find((call) =>
    call.options?.body?.idempotency_key?.endsWith(':wrong-resource'),
  );
  assert.equal(wrongResourceCall.options.body.parameters.resource_ref, plan.wrong_resource_ref);
  if (plan.provider === 'github') {
    assert.equal(
      `${wrongResourceCall.options.body.parameters.owner}/${wrongResourceCall.options.body.parameters.repo}`,
      plan.wrong_resource_ref,
    );
  }
  assert.equal(JSON.stringify(receipt).includes(plan.account_ref), false);
  assert.equal(JSON.stringify(receipt).includes(plan.parameters.resource_ref), false);
}

{
  const plan = githubPlan();
  plan.expected_authority = Object.fromEntries(Object.entries(plan.expected_authority).reverse());
  const broker = successfulBroker(plan);
  assert.equal(
    (await createProviderContractRunner({ callBroker: broker.callBroker })(plan)).status,
    'passed',
  );
}

const expectPlanInvalid = (mutate) => {
  const candidate = githubPlan();
  mutate(candidate);
  assert.throws(
    () => validateProviderContractPlan(candidate),
    (error) => error instanceof ProviderContractError && error.code === 'contract_plan_invalid',
  );
};

for (const mutate of [
  (value) => {
    value.secret = 'forbidden';
  },
  (value) => {
    value.provider = 'docker';
  },
  (value) => {
    value.tool_name = 'github.issues.list';
  },
  (value) => {
    value.tool_version = 'latest';
  },
  (value) => {
    value.account_ref = value.wrong_account_ref;
  },
  (value) => {
    value.environment = 'development';
  },
  (value) => {
    value.parameters.extra = true;
  },
  (value) => {
    value.parameters.resource_ref = 'other/repo';
  },
  (value) => {
    value.parameters.owner = '../owner';
  },
  (value) => {
    value.wrong_resource_ref = value.parameters.resource_ref;
  },
  (value) => {
    value.idempotency_prefix = 'short';
  },
  (value) => {
    value.expected_authority.account_id_sha256 = 'not-a-digest';
  },
])
  expectPlanInvalid(mutate);

for (const mutate of [
  (value) => {
    value.parameters.region_id = 'INVALID';
  },
  (value) => {
    value.parameters.max_results = 0;
  },
  (value) => {
    value.parameters.max_results = 21;
  },
  (value) => {
    delete value.parameters.max_results;
  },
]) {
  const candidate = aliyunPlan();
  mutate(candidate);
  assert.throws(() => validateProviderContractPlan(candidate), /contract_plan_invalid/);
}

assert.throws(() => createProviderContractRunner(), TypeError);

const expectRunCode = async (plan, callBroker, code) => {
  await assert.rejects(
    createProviderContractRunner({ callBroker })(plan),
    (error) => error instanceof ProviderContractError && error.code === code,
  );
};

await expectRunCode(
  githubPlan(),
  async () => {
    throw new Error('private transport detail');
  },
  'contract_broker_unavailable',
);

for (const [response, code] of [
  [{}, 'contract_discovery_invalid'],
  [{ registry_version: 1, tools: [] }, 'contract_tool_unavailable'],
  [
    {
      registry_version: 1,
      tools: [{ ...toolFor(githubPlan()), agent_execution: false }],
    },
    'contract_tool_unavailable',
  ],
]) {
  await expectRunCode(githubPlan(), async () => response, code);
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  await expectRunCode(
    plan,
    async (path, options) => {
      if (path === '/api/v2/tasks' && options.body.idempotency_key.endsWith(':positive')) {
        throw new Error('private detail');
      }
      return broker.callBroker(path, options);
    },
    'contract_positive_create_failed',
  );
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  await expectRunCode(
    plan,
    async (path, options) => {
      const result = await broker.callBroker(path, options);
      if (path === '/api/v2/tasks') return { ...result, state: 'PENDING_APPROVAL' };
      return result;
    },
    'contract_positive_task_invalid',
  );
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  await expectRunCode(
    plan,
    async (path, options) => {
      if (path.endsWith('/run')) throw new Error('private detail');
      return broker.callBroker(path, options);
    },
    'contract_positive_run_failed',
  );
}

for (const [result, code] of [
  [
    {
      id: 1,
      full_name: 'wrong/repo',
      visibility: 'private',
      archived: false,
      authority: { ...githubAuthority },
    },
    'contract_result_invalid',
  ],
  [
    {
      id: 1,
      full_name: 'contract-owner/private-contract-repo',
      visibility: 'private',
      archived: false,
      access_token: 'credential-canary',
      authority: { ...githubAuthority },
    },
    'contract_result_sensitive',
  ],
]) {
  const plan = githubPlan();
  const broker = successfulBroker(plan, { result });
  await expectRunCode(plan, broker.callBroker, code);
}

{
  const plan = githubPlan();
  const result = resultFor(plan);
  result.authority.account_id_sha256 = '7'.repeat(64);
  const broker = successfulBroker(plan, { result });
  await expectRunCode(plan, broker.callBroker, 'contract_authority_mismatch');
}

{
  const plan = githubPlan();
  const cyclic = resultFor(plan);
  cyclic.self = cyclic;
  const broker = successfulBroker(plan, { result: cyclic });
  await expectRunCode(plan, broker.callBroker, 'contract_result_invalid');
}

{
  const plan = aliyunPlan();
  const result = resultFor(plan);
  result.instances[0].region_id = 'cn-shanghai';
  const broker = successfulBroker(plan, { result });
  await expectRunCode(plan, broker.callBroker, 'contract_result_invalid');
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  let cancelled = false;
  await expectRunCode(
    plan,
    async (path, options) => {
      if (path.endsWith('/cancel')) {
        cancelled = true;
        return { state: 'CANCELLED' };
      }
      if (path === '/api/v2/tasks' && !options.body.idempotency_key.endsWith(':positive')) {
        return {
          id: taskId,
          tool: plan.tool_name,
          tool_version: plan.tool_version,
          account_ref: plan.account_ref,
          environment: plan.environment,
          state: 'READY',
        };
      }
      return broker.callBroker(path, options);
    },
    'contract_negative_boundary_failed',
  );
  assert.equal(cancelled, true);
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  await expectRunCode(
    plan,
    async (path, options) => {
      if (path.endsWith('/cancel')) throw new Error('cleanup unavailable');
      if (path === '/api/v2/tasks' && !options.body.idempotency_key.endsWith(':positive')) {
        return {
          id: taskId,
          tool: plan.tool_name,
          tool_version: plan.tool_version,
          account_ref: plan.account_ref,
          environment: plan.environment,
          state: 'READY',
        };
      }
      return broker.callBroker(path, options);
    },
    'contract_negative_boundary_failed',
  );
}

{
  const plan = githubPlan();
  const broker = successfulBroker(plan);
  await expectRunCode(
    plan,
    async (path, options) => {
      if (path === '/api/v2/tasks' && !options.body.idempotency_key.endsWith(':positive')) {
        const error = new Error('upstream detail');
        error.code = 'provider_unavailable';
        throw error;
      }
      return broker.callBroker(path, options);
    },
    'contract_negative_result_invalid',
  );
}

console.log('provider contract runner: bounded read and negative account/resource checks passed');
