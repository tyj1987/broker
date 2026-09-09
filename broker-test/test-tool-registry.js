import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { ToolRegistry, loadToolRegistry } from '../broker/lib/tool-registry.js';

const registry = loadToolRegistry(resolve(import.meta.dirname, '../tools/registry.json'));
const github = registry.find('github', 'repo.read');
assert.equal(github.name, 'github.repository.read');
assert.equal(github.risk_level, 'LOW');
github.name = 'tampered';
assert.equal(registry.find('github', 'repo.read').name, 'github.repository.read', 'callers receive defensive copies');

const admin = { name: 'admin-a', context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } } };
assert.ok(registry.listFor(admin).some((tool) => tool.risk_level === 'CRITICAL'));
const agent = { name: 'agent-a', context: { via: 'api_key', client: { role: 'admin' } } };
assert.ok(registry.listFor(agent).every((tool) => tool.agent_execution === true));

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

console.log('tool registry: schema, risk, role and agent-execution gates passed');
