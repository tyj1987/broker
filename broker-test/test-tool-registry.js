import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { ToolRegistry, loadToolRegistry } from '../broker/lib/tool-registry.js';

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const github = registry.find('github', 'repo.read');
assert.equal(github.name, 'github.repository.read');
assert.equal(github.risk_level, 'LOW');
const deviceEnroll = registry.find('broker', 'device.enroll');
assert.equal(deviceEnroll.input_schema.properties.capabilities.maxItems, 32);
assert.equal(deviceEnroll.input_schema.properties.capabilities.items.type, 'string');
github.name = 'tampered';
assert.equal(registry.find('github', 'repo.read').name, 'github.repository.read', 'callers receive defensive copies');

const admin = { name: 'admin-a', context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } } };
assert.ok(registry.listFor(admin).some((tool) => tool.risk_level === 'CRITICAL'));
const agent = { name: 'agent-a', context: { via: 'api_key', client: { role: 'admin' } } };
assert.deepEqual(registry.listFor(agent), [], 'an API-key identity without key constraints fails closed');
const githubAgent = {
  name: 'agent-github',
  context: {
    via: 'api_key',
    client: { role: 'admin' },
    apiKey: {
      scopes: ['operations:github:repo.read'],
      allowed_services: ['github'],
      allowed_operations: ['github:repo.read'],
      allowed_accounts: ['repository-main'],
      allowed_resources: ['repository-main'],
      allowed_environments: ['production'],
    },
  },
};
assert.deepEqual(
  registry.listFor(githubAgent).map((tool) => tool.name),
  ['github.repository.read'],
  'tool discovery cannot exceed API-key operation constraints',
);
for (const field of [
  'scopes',
  'allowed_services',
  'allowed_operations',
  'allowed_accounts',
  'allowed_resources',
  'allowed_environments',
]) {
  const restricted = structuredClone(githubAgent);
  restricted.context.apiKey[field] = [];
  assert.deepEqual(registry.listFor(restricted), [], `${field} is enforced during discovery`);
}
const workloadAgent = {
  name: 'workload-a',
  context: { via: 'workload_identity', client: { role: 'admin' } },
};
assert.ok(registry.listFor(workloadAgent).every((tool) => tool.agent_execution === true));

const allowed = { allow: true, reason: 'allowed' };
assert.equal(registry.evaluate({
  identity: { name: 'developer-a', context: { via: 'api_key', client: { role: 'developer' } } },
  provider: 'github', operationId: 'repo.read', environment: 'production',
}, allowed).allow, true);
assert.equal(registry.evaluate({
  identity: admin, provider: 'unknown', operationId: 'anything', environment: 'production',
}, allowed).reason, 'tool_unregistered');
assert.equal(registry.evaluate({
  identity: agent, provider: 'broker', operationId: 'device.state', environment: 'production',
}, allowed, { operationPolicy: { approval_required: true, required_approvals: 2 } }).reason, 'critical_agent_denied');
assert.equal(registry.evaluate({
  identity: { ...admin, context: { ...admin.context, authFactors: [] } },
  provider: 'broker', operationId: 'device.state', environment: 'production',
}, allowed, { operationPolicy: { approval_required: true, required_approvals: 2 } }).reason, 'critical_step_up_required');
assert.equal(registry.evaluate({
  identity: admin, provider: 'broker', operationId: 'device.state', environment: 'production',
}, allowed, { operationPolicy: { approval_required: false } }).reason, 'tool_approval_policy_mismatch');
assert.equal(registry.evaluate({
  identity: admin, provider: 'broker', operationId: 'device.state', environment: 'production',
}, allowed, { operationPolicy: { approval_required: true, required_approvals: 1 } }).reason, 'tool_approval_policy_mismatch');

assert.equal(registry.validateConfiguration({ operation_policies: {
  github: { 'repo.read': {
    enabled: true, environments: ['production'],
    parameter_schema: { properties: { resource_ref: {}, owner: {}, repo: {} } },
  } },
} }), true);
assert.throws(() => registry.validateConfiguration({ operation_policies: {
  github: { 'repo.delete': { enabled: true, environments: ['production'], parameter_schema: { properties: {} } } },
} }), /not registered/);
assert.throws(() => registry.validateConfiguration({ operation_policies: {
  github: { 'repo.read': { enabled: true, environments: ['production'], parameter_schema: { properties: { resource_ref: {} } } } },
} }), /parameters differ/);
assert.throws(() => registry.validateConfiguration({ operation_policies: {
  broker: { 'device.state': {
    enabled: true, environments: ['production'], approval_required: false,
    parameter_schema: { properties: { resource_ref: {}, device_id: {}, state: {} } },
  } },
} }), /weakens tool approval/);

const base = registry.find('github', 'repo.read');
const invalidCritical = {
  ...base, name: 'github.repository.delete', operation_id: 'repo.delete', risk_level: 'CRITICAL', agent_execution: true,
  approval_policy: { mode: 'two_person', approvals_required: 2 },
};
assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [invalidCritical] }), /critical tool/);
const invalidApproval = { ...base, name: 'github.repository.write', operation_id: 'repo.write', risk_level: 'HIGH' };
assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [invalidApproval] }), /high-risk tool/);
const openInput = { ...base, name: 'github.repository.open', operation_id: 'repo.open', input_schema: { ...base.input_schema, additionalProperties: true } };
assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [openInput] }), /deny additional properties/);

assert.equal(registry.find('unknown', 'missing'), null);
assert.equal(registry.findByName('github.repository.read', '1.0.0').operation_id, 'repo.read');
assert.equal(registry.findByName('unknown.tool', '1.0.0'), null);
assert.deepEqual(registry.listFor({ context: {} }), []);
assert.ok(registry.listFor({ context: { via: 'session', client: { role: 'developer', principal_type: 'human' } } })
  .some((tool) => tool.name === 'github.repository.read'));

assert.deepEqual(registry.evaluate({}, null), { allow: false, reason: 'policy_denied' });
assert.equal(registry.evaluate({}, { allow: false, reason: 'explicit_deny' }).reason, 'explicit_deny');
assert.equal(registry.evaluate({
  identity: { context: { via: 'session', client: { role: 'viewer' } } },
  provider: 'github', operationId: 'repo.read', environment: 'production',
}, allowed).reason, 'tool_role_denied');
assert.equal(registry.evaluate({
  identity: admin, provider: 'github', operationId: 'repo.read', environment: 'unknown',
}, allowed).reason, 'tool_environment_denied');
assert.equal(registry.evaluate({
  identity: admin, provider: 'broker', operationId: 'device.state', environment: 'production',
}, allowed, { operationPolicy: { approval_required: true, required_approvals: 2 } }).allow, true);

assert.throws(() => new ToolRegistry(null), /must be an object/);
assert.throws(() => new ToolRegistry([]), /must be an object/);
assert.throws(() => new ToolRegistry({ registry_version: 2, tools: [base] }), /version 1/);
assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [] }), /at least one/);
assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [null] }), /entry must be an object/);

function expectInvalidTool(change, pattern) {
  const candidate = structuredClone(base);
  change(candidate);
  assert.throws(() => new ToolRegistry({ registry_version: 1, tools: [candidate] }), pattern);
}

expectInvalidTool((tool) => { tool.unexpected = true; }, /unknown field/);
expectInvalidTool((tool) => { delete tool.provider; }, /missing field provider/);
expectInvalidTool((tool) => { tool.name = 'invalid'; }, /invalid identity/);
expectInvalidTool((tool) => { tool.version = '0.1.0'; }, /invalid identity/);
expectInvalidTool((tool) => { tool.description = 'short'; }, /invalid description/);
expectInvalidTool((tool) => { tool.required_role = 'owner'; }, /invalid role or risk/);
expectInvalidTool((tool) => { tool.risk_level = 'ROOT'; }, /invalid role or risk/);
expectInvalidTool((tool) => { tool.environments = []; }, /invalid environments/);
expectInvalidTool((tool) => { tool.environments = ['production', 'production']; }, /invalid environments/);
expectInvalidTool((tool) => { tool.environments = ['unknown']; }, /invalid environments/);
expectInvalidTool((tool) => { tool.input_schema = []; }, /object schema/);
expectInvalidTool((tool) => { tool.input_schema.properties = null; }, /properties is required/);
expectInvalidTool((tool) => { tool.input_schema.required = ['missing']; }, /requires undefined property/);
expectInvalidTool((tool) => { tool.input_schema.properties.owner.pattern = '.*'; }, /unsupported schema keyword pattern/);
expectInvalidTool((tool) => { tool.input_schema.properties.owner.type = 'secret'; }, /unsupported type/);
expectInvalidTool((tool) => {
  tool.input_schema.properties.owner.minLength = 5;
  tool.input_schema.properties.owner.maxLength = 4;
}, /inconsistent string bounds/);
expectInvalidTool((tool) => { tool.input_schema.required = ['owner', 'owner']; }, /unique property names/);
expectInvalidTool((tool) => {
  tool.output_schema.properties.access_token = { type: 'string' };
}, /sensitive output field/);
expectInvalidTool((tool) => {
  tool.output_schema.properties.items = {
    type: 'array',
    items: {
      type: 'object', additionalProperties: false,
      properties: { private_key: { type: 'string' } },
    },
  };
}, /sensitive output field/);
expectInvalidTool((tool) => { tool.target.resource_parameter = 'other'; }, /target must bind/);
expectInvalidTool((tool) => { tool.timeout_ms = 99; }, /invalid timeout/);
expectInvalidTool((tool) => { tool.rate_limit.requests = 0; }, /invalid rate limit/);
expectInvalidTool((tool) => { tool.rate_limit.window_seconds = 0; }, /invalid rate limit/);
expectInvalidTool((tool) => { tool.approval_policy.mode = 'optional'; }, /invalid approval policy/);
expectInvalidTool((tool) => { tool.approval_policy.approvals_required = -1; }, /invalid approval policy/);
expectInvalidTool((tool) => { tool.approval_policy.approvals_required = 1; }, /conflicts with mode/);
expectInvalidTool((tool) => {
  tool.approval_policy = { mode: 'step_up', approvals_required: 0 };
}, /step-up requires approval/);
expectInvalidTool((tool) => {
  tool.approval_policy = { mode: 'two_person', approvals_required: 1 };
}, /dual control requires two approvals/);
expectInvalidTool((tool) => { tool.audit_policy.required = false; }, /mandatory audit policy/);
expectInvalidTool((tool) => { tool.audit_policy.redact = null; }, /mandatory audit policy/);

const sameOperation = { ...base, name: 'github.repository.read_copy' };
assert.throws(
  () => new ToolRegistry({ registry_version: 1, tools: [base, sameOperation] }),
  /duplicate tool registration/,
);
const sameName = { ...base, operation_id: 'repo.read_copy' };
assert.throws(
  () => new ToolRegistry({ registry_version: 1, tools: [base, sameName] }),
  /duplicate tool registration/,
);

assert.throws(() => registry.validateConfiguration({}), /must be configured/);
assert.throws(() => registry.validateConfiguration({ operation_policies: [] }), /must be configured/);
assert.throws(() => registry.validateConfiguration({ operation_policies: { github: [] } }), /must be an object/);
assert.equal(registry.validateConfiguration({ operation_policies: { github: { disabled: { enabled: false } } } }), true);
assert.throws(() => registry.validateConfiguration({ operation_policies: {
  github: { 'repo.read': {
    enabled: true, environments: ['disaster_recovery'],
    parameter_schema: { properties: { resource_ref: {}, owner: {}, repo: {} } },
  } },
} }), /environment exceeds/);

assert.throws(() => loadToolRegistry(resolve(import.meta.dirname, 'missing-registry.json')), /could not be loaded/);

console.log('tool registry: schema, risk, role and agent-execution gates passed');
