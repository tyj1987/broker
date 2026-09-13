import assert from 'node:assert/strict';
import { evaluateOperationPolicy, validateTypedParameters } from '../broker/lib/operation-policy.js';

const policy = {
  enabled: true,
  roles: ['operator'],
  security_profiles: ['strict'],
  identity_methods: ['mtls', 'api_key'],
  environments: ['production'],
  accounts: ['primary'],
  resources: ['billing-summary'],
  secret_refs: ['cloud-token'],
  approval_required: true,
  contract_verified: true,
  ttl_seconds: 60,
  parameter_schema: {
    type: 'object',
    required: ['resource_ref', 'detail'],
    properties: {
      resource_ref: { type: 'string', format: 'identifier' },
      detail: { type: 'string', enum: ['summary'] },
    },
  },
};
const config = { operation_policies: { aliyun: { 'billing.read': policy } } };
const apiKey = {
  scopes: ['operations:aliyun:billing.read'],
  allowed_services: ['aliyun'],
  allowed_operations: ['aliyun:billing.read'],
  allowed_accounts: ['primary'],
  allowed_environments: ['production'],
  allowed_resources: ['billing-summary'],
  allowed_secrets: ['cloud-token'],
};
const context = {
  via: 'api_key',
  clientName: 'automation-1',
  client: { role: 'operator', security_profile: 'strict', allowed_services: ['aliyun'] },
  apiKey,
  approvalGrants: [{ provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', resource_ref: 'billing-summary', approved_by: 'reviewer-2', expires_at_ms: 2_000 }],
};
const base = {
  identity: { name: 'automation-1', context }, provider: 'aliyun', operationId: 'billing.read',
  accountRef: 'primary', environment: 'production', typedParameters: { resource_ref: 'billing-summary', detail: 'summary' },
};

assert.equal(evaluateOperationPolicy(config, base, 1_000).allow, true);
const dualPolicy = { ...policy, required_approvals: 2 };
const dualConfig = { operation_policies: { aliyun: { 'billing.read': dualPolicy } } };
const dualContext = {
  ...context,
  approvalGrants: [
    ...context.approvalGrants,
    { ...context.approvalGrants[0], approved_by: 'reviewer-3' },
  ],
};
assert.equal(evaluateOperationPolicy(dualConfig, {
  ...base, identity: { ...base.identity, context: dualContext },
}, 1_000).allow, true, 'all required independent approvals are required');
assert.equal(evaluateOperationPolicy(dualConfig, base, 1_000).reason, 'approval_required');
assert.equal(evaluateOperationPolicy(dualConfig, {
  ...base,
  identity: { ...base.identity, context: { ...context, approvalGrants: [
    ...context.approvalGrants,
    { ...context.approvalGrants[0] },
  ] } },
}, 1_000).reason, 'approval_required', 'duplicate approvers do not satisfy dual control');
assert.equal(evaluateOperationPolicy(config, base, 1_000).executionMode, 'adapter');
assert.equal(evaluateOperationPolicy({
  operation_policies: { aliyun: { 'billing.read': { ...policy, execution_mode: 'browser' } } },
}, base, 1_000).executionMode, 'browser');
for (const ttl of [Infinity, NaN, '60', -1]) {
  assert.equal(evaluateOperationPolicy({
    operation_policies: { aliyun: { 'billing.read': { ...policy, ttl_seconds: ttl } } },
  }, base, 1_000).reason, 'policy_ttl_invalid', `malformed policy ttl: ${String(ttl)}`);
}
for (const ttl of [Infinity, NaN, '60', -1]) {
  assert.equal(evaluateOperationPolicy({
    operation_policies: { aliyun: { 'billing.read': { ...policy, otp: { required: true, ttl_seconds: ttl } } } },
  }, base, 1_000).reason, 'otp_policy_ttl_invalid', `malformed OTP ttl: ${String(ttl)}`);
}
const denied = [
  ['role', { client: { ...context.client, role: 'admin' } }],
  ['profile', { client: { ...context.client, security_profile: 'compatibility' } }],
  ['method', { via: 'session' }],
  ['scope', { apiKey: { ...apiKey, scopes: [] } }],
  ['service', { apiKey: { ...apiKey, allowed_services: ['github'] } }],
  ['operation', { apiKey: { ...apiKey, allowed_operations: ['aliyun:other'] } }],
  ['account', { apiKey: { ...apiKey, allowed_accounts: ['secondary'] } }],
  ['environment', { apiKey: { ...apiKey, allowed_environments: ['staging'] } }],
  ['resource', { apiKey: { ...apiKey, allowed_resources: ['other'] } }],
  ['secret', { apiKey: { ...apiKey, allowed_secrets: [] } }],
  ['approval', { approvalGrants: [] }],
  ['malformed approval expiry', { approvalGrants: [{ ...context.approvalGrants[0], expires_at_ms: Infinity }] }],
];
for (const [name, change] of denied) {
  const request = { ...base, identity: { ...base.identity, context: { ...context, ...change } } };
  assert.equal(evaluateOperationPolicy(config, request, 1_000).allow, false, name);
}
assert.equal(evaluateOperationPolicy(config, base, 2_001).allow, false, 'expired approval');
assert.equal(evaluateOperationPolicy(config, {
  ...base,
  identity: {
    ...base.identity,
    context: {
      ...context,
      clientName: undefined,
      approvalGrants: [{ ...context.approvalGrants[0], approved_by: 'automation-1' }],
    },
  },
}, 1_000).reason, 'approval_required', 'approval cannot be self-approved when clientName metadata is absent');
assert.equal(evaluateOperationPolicy(config, {
  ...base, identity: { ...base.identity, context: { ...context, approvalGrants: [] } },
}, 1_000, { ignoreApproval: true }).allow, true, 'approval preflight skips only the approval grant');
assert.equal(evaluateOperationPolicy(config, {
  ...base, identity: { ...base.identity, context: { ...context, approvalGrants: [], client: { ...context.client, role: 'admin' } } },
}, 1_000, { ignoreApproval: true }).reason, 'role_denied', 'approval preflight still enforces requester role');
assert.equal(validateTypedParameters({ resource_ref: 'billing-summary', detail: 'summary', url: 'https://evil.invalid' }, policy.parameter_schema).ok, false);
assert.equal(validateTypedParameters({ resource_ref: 'billing-summary' }, policy.parameter_schema).ok, false);
assert.equal(validateTypedParameters({ resource_ref: 'billing-summary', detail: 'full' }, policy.parameter_schema).ok, false);

const parameterCases = [
  [null, null, 'parameter_schema_missing'],
  [null, { type: 'array', properties: {} }, 'parameter_schema_missing'],
  [null, { type: 'object' }, 'parameter_schema_missing'],
  [null, { type: 'object', properties: {} }, 'typed_parameters_invalid'],
  [[], { type: 'object', properties: {} }, 'typed_parameters_invalid'],
  [{ count: 1.5 }, { type: 'object', properties: { count: { type: 'integer' } } }, 'parameter_type_mismatch'],
  [{ count: Infinity }, { type: 'object', properties: { count: { type: 'number' } } }, 'parameter_type_mismatch'],
  [{ value: [] }, { type: 'object', properties: { value: { type: 'object', additional_properties: false, required: [], properties: {} } } }, 'parameter_type_mismatch'],
  [{ value: 'a' }, { type: 'object', properties: { value: { type: 'string', min_length: 2 } } }, 'parameter_too_short'],
  [{ value: 'abc' }, { type: 'object', properties: { value: { type: 'string', max_length: 2 } } }, 'parameter_too_long'],
  [{ value: 'Bad value' }, { type: 'object', properties: { value: { type: 'string', format: 'identifier' } } }, 'parameter_format_mismatch'],
  [{ value: [1, 2] }, { type: 'object', properties: { value: { type: 'array', max_items: 1, items: { type: 'integer' } } } }, 'parameter_array_too_large'],
  [{ value: ['bad'] }, { type: 'object', properties: { value: { type: 'array', items: { type: 'integer' } } } }, 'parameter_type_mismatch'],
  [{ value: 0 }, { type: 'object', properties: { value: { type: 'integer', minimum: 1 } } }, 'parameter_below_minimum'],
  [{ value: 2 }, { type: 'object', properties: { value: { type: 'integer', maximum: 1 } } }, 'parameter_above_maximum'],
  [{ value: 'ok' }, { type: 'object', properties: { value: { type: 'string', pattern: '.*' } } }, 'parameter_schema_invalid'],
];
for (const [value, schema, reason] of parameterCases) {
  assert.equal(validateTypedParameters(value, schema).reason, reason);
}
assert.equal(validateTypedParameters({ count: 2, ratio: 1.5, nested: { label: 'ok' }, values: [] }, {
  type: 'object', properties: {
    count: { type: 'integer' }, ratio: { type: 'number' },
    nested: { type: 'object', additional_properties: false, required: ['label'], properties: { label: { type: 'string' } } },
    values: { type: 'array', items: { type: 'string' } },
  },
}).ok, true);

const requestDenials = [
  [{ ...base, identity: null }, 'identity_missing'],
  [{ ...base, identity: { ...base.identity, context: { ...context, apiKey: null } } }, 'api_key_context_missing'],
  [{ ...base, operationId: 'missing' }, 'policy_missing'],
  [{ ...base, environment: 'staging' }, 'environment_denied'],
  [{ ...base, accountRef: 'secondary' }, 'account_denied'],
  [{ ...base, typedParameters: { resource_ref: 'other', detail: 'summary' } }, 'resource_denied'],
  [{ ...base, typedParameters: { resource_ref: 'billing-summary' } }, 'required_parameter_missing'],
];
for (const [request, reason] of requestDenials) {
  assert.equal(evaluateOperationPolicy(config, request, 1_000).reason, reason);
}

assert.equal(evaluateOperationPolicy({
  operation_policies: { aliyun: { 'billing.read': { ...policy, contract_verified: false } } },
}, base, 1_000).reason, 'contract_unverified');
const stagingBase = {
  ...base,
  environment: 'staging',
  identity: {
    ...base.identity,
    context: {
      ...context,
      approvalGrants: context.approvalGrants.map((grant) => ({ ...grant, environment: 'staging' })),
      apiKey: { ...apiKey, allowed_environments: ['staging'] },
    },
  },
};
assert.equal(evaluateOperationPolicy({
  operation_policies: { aliyun: { 'billing.read': { ...policy, contract_verified: false, environments: ['staging'] } } },
}, stagingBase, 1_000).allow, true, 'unverified adapters may be exercised outside production');


const conditionedPolicy = {
  ...policy,
  source_cidrs: ['203.0.113.0/24', '2001:db8::/32'],
  not_before: '2026-09-09T00:00:00Z',
  not_after: '2026-09-10T00:00:00Z',
};
const conditionTime = Date.parse('2026-09-09T12:00:00Z');
const conditionedContext = {
  ...context,
  sourceIp: '203.0.113.42',
  approvalGrants: [{ ...context.approvalGrants[0], expires_at_ms: conditionTime + 60_000 }],
};
const conditionedRequest = { ...base, identity: { ...base.identity, context: conditionedContext } };
const conditionedConfig = { operation_policies: { aliyun: { 'billing.read': conditionedPolicy } } };
assert.equal(evaluateOperationPolicy(conditionedConfig, conditionedRequest, conditionTime).allow, true);
assert.equal(evaluateOperationPolicy(conditionedConfig, {
  ...conditionedRequest,
  identity: { ...conditionedRequest.identity, context: { ...conditionedContext, sourceIp: '198.51.100.2' } },
}, conditionTime).reason, 'source_ip_denied');
assert.equal(evaluateOperationPolicy(
  conditionedConfig, conditionedRequest, Date.parse('2026-09-10T00:00:00Z'),
).reason, 'outside_time_window');

const sessionContext = {
  ...context,
  via: 'mtls',
  apiKey: null,
  client: { ...context.client, allowed_services: [], allowed_proxy: [{ service: 'aliyun' }] },
};
assert.equal(evaluateOperationPolicy(config, {
  ...base, identity: { name: 'automation-1', context: sessionContext },
}, 1_000).allow, true, 'service may be granted by typed proxy policy');

console.log('operation policy: all authorization dimensions fail closed');
