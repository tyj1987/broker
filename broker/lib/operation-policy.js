import { evaluatePolicyConditions } from './policy-conditions.js';

const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const PARAMETER_TYPES = new Set(['string', 'boolean', 'integer', 'number', 'array', 'object']);

function includes(list, value) {
  return Array.isArray(list) && list.includes(value);
}

function matchesType(value, type) {
  if (type === 'array') return Array.isArray(value);
  if (type === 'integer') return Number.isSafeInteger(value);
  if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  return typeof value === type;
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validBound(value) {
  return value === undefined || (Number.isSafeInteger(value) && value >= 0);
}

function validateParameterRule(rule, depth = 0) {
  if (!plainObject(rule) || !PARAMETER_TYPES.has(rule.type) || depth > 4) return false;
  const keys = rule.type === 'string' ? ['type', 'enum', 'format', 'min_length', 'max_length']
    : rule.type === 'array' ? ['type', 'min_items', 'max_items', 'items']
      : rule.type === 'object' ? ['type', 'required', 'properties', 'additional_properties']
        : ['type', 'enum', 'minimum', 'maximum'];
  if (Object.keys(rule).some((key) => !keys.includes(key))) return false;
  if (rule.enum !== undefined && (!Array.isArray(rule.enum) || rule.enum.length === 0
    || rule.enum.some((item) => !matchesType(item, rule.type)))) return false;
  if (rule.type === 'string') {
    if (rule.format !== undefined && rule.format !== 'identifier') return false;
    if (!validBound(rule.min_length) || !validBound(rule.max_length)) return false;
    return rule.min_length === undefined || rule.max_length === undefined || rule.min_length <= rule.max_length;
  }
  if (rule.type === 'array') {
    if (!validBound(rule.min_items) || !validBound(rule.max_items)
      || !validateParameterRule(rule.items, depth + 1)) return false;
    return rule.min_items === undefined || rule.max_items === undefined || rule.min_items <= rule.max_items;
  }
  if (rule.type === 'object') {
    if (rule.additional_properties !== false || !plainObject(rule.properties)
      || !Array.isArray(rule.required)) return false;
    if (new Set(rule.required).size !== rule.required.length
      || rule.required.some((name) => typeof name !== 'string' || !Object.hasOwn(rule.properties, name))) return false;
    return Object.values(rule.properties).every((child) => validateParameterRule(child, depth + 1));
  }
  if (rule.minimum !== undefined && (typeof rule.minimum !== 'number' || !Number.isFinite(rule.minimum))) return false;
  if (rule.maximum !== undefined && (typeof rule.maximum !== 'number' || !Number.isFinite(rule.maximum))) return false;
  return rule.minimum === undefined || rule.maximum === undefined || rule.minimum <= rule.maximum;
}

export function validateParameterSchema(schema) {
  if (!plainObject(schema) || schema.type !== 'object' || !plainObject(schema.properties)
    || !Array.isArray(schema.required || [])
    || Object.keys(schema).some((key) => !['type', 'required', 'properties'].includes(key))) {
    return { ok: false, reason: 'parameter_schema_missing' };
  }
  const required = schema.required || [];
  if (new Set(required).size !== required.length
    || required.some((name) => typeof name !== 'string' || !Object.hasOwn(schema.properties, name))
    || !Object.values(schema.properties).every((rule) => validateParameterRule(rule))) {
    return { ok: false, reason: 'parameter_schema_invalid' };
  }
  return { ok: true };
}

function validateParameterValue(item, rule) {
  if (!matchesType(item, rule.type)) return 'parameter_type_mismatch';
  if (Array.isArray(rule.enum) && !rule.enum.includes(item)) return 'parameter_enum_mismatch';
  if (typeof item === 'string') {
    if (item.length < Number(rule.min_length || 0)) return 'parameter_too_short';
    if (item.length > Number(rule.max_length || 4096)) return 'parameter_too_long';
    if (rule.format === 'identifier' && !SAFE_ID.test(item)) return 'parameter_format_mismatch';
  }
  if (typeof item === 'number') {
    if (rule.minimum !== undefined && item < rule.minimum) return 'parameter_below_minimum';
    if (rule.maximum !== undefined && item > rule.maximum) return 'parameter_above_maximum';
  }
  if (Array.isArray(item)) {
    if (item.length < Number(rule.min_items || 0)) return 'parameter_array_too_small';
    if (item.length > Number(rule.max_items || 100)) return 'parameter_array_too_large';
    for (const child of item) {
      const reason = validateParameterValue(child, rule.items);
      if (reason) return reason;
    }
  }
  if (plainObject(item)) {
    for (const name of rule.required) {
      if (!Object.hasOwn(item, name)) return 'required_parameter_missing';
    }
    for (const [name, child] of Object.entries(item)) {
      if (!Object.hasOwn(rule.properties, name)) return 'unknown_parameter';
      const reason = validateParameterValue(child, rule.properties[name]);
      if (reason) return reason;
    }
  }
  return null;
}

export function validateTypedParameters(value, schema) {
  const schemaValidation = validateParameterSchema(schema);
  if (!schemaValidation.ok) return schemaValidation;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'typed_parameters_invalid' };
  }
  const allowed = new Set(Object.keys(schema.properties));
  for (const name of schema.required || []) {
    if (!Object.hasOwn(value, name)) return { ok: false, reason: 'required_parameter_missing' };
  }
  for (const [name, item] of Object.entries(value)) {
    if (!allowed.has(name)) return { ok: false, reason: 'unknown_parameter' };
    const rule = schema.properties[name];
    const reason = validateParameterValue(item, rule);
    if (reason) return { ok: false, reason };
  }
  return { ok: true };
}

function hasApproval(ctx, provider, operationId, accountRef, requiredApprovals, now) {
  const approvers = new Set();
  for (const grant of ctx?.approvalGrants || []) {
    if (grant
    && grant.provider === provider
    && grant.operation_id === operationId
    && grant.account_ref === accountRef
    && grant.approved_by !== ctx.clientName
    && Number(grant.expires_at_ms) > now
    && typeof grant.approved_by === 'string') {
      approvers.add(grant.approved_by);
    }
  }
  return approvers.size >= requiredApprovals;
}

export function evaluateOperationPolicy(config, request, now = Date.now(), options = {}) {
  const { identity, provider, operationId, accountRef, environment, typedParameters } = request;
  const ctx = identity?.context;
  const client = ctx?.client;
  const policy = config?.operation_policies?.[provider]?.[operationId];
  const deny = (reason) => ({ allow: false, reason });

  if (!identity?.name || !client) return deny('identity_missing');
  if (!policy || policy.enabled !== true) return deny('policy_missing');
  if (!includes(policy.roles, client.role)) return deny('role_denied');
  if (!includes(policy.security_profiles, client.security_profile)) return deny('security_profile_denied');
  if (!includes(policy.identity_methods, ctx.via)) return deny('identity_method_denied');
  if (!includes(policy.environments, environment)) return deny('environment_denied');
  if (!includes(policy.accounts, accountRef)) return deny('account_denied');
  if (environment === 'production' && policy.contract_verified !== true) {
    return deny('contract_unverified');
  }

  const conditions = evaluatePolicyConditions(policy, ctx.sourceIp, now);
  if (!conditions.ok) return deny(conditions.reason);

  const serviceAllowed = includes(client.allowed_services, provider)
    || (client.allowed_proxy || []).some((entry) => entry?.service === provider);
  if (!serviceAllowed) return deny('service_denied');

  const parameters = validateTypedParameters(typedParameters, policy.parameter_schema);
  if (!parameters.ok) return deny(parameters.reason);

  const resource = typedParameters.resource_ref;
  if (Array.isArray(policy.resources) && policy.resources.length > 0 && !includes(policy.resources, resource)) {
    return deny('resource_denied');
  }
  const requiredApprovals = policy.required_approvals === undefined ? 1 : policy.required_approvals;
  if (!Number.isSafeInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 10) {
    return deny('approval_policy_invalid');
  }
  if (policy.approval_required === true && options.ignoreApproval !== true
    && !hasApproval(ctx, provider, operationId, accountRef, requiredApprovals, now)) {
    return deny('approval_required');
  }

  const apiKey = ctx.apiKey;
  if (ctx.via === 'api_key' && !apiKey) return deny('api_key_context_missing');
  if (apiKey) {
    const operationScope = `operations:${provider}:${operationId}`;
    if (!includes(apiKey.scopes, 'operations:execute') && !includes(apiKey.scopes, operationScope)) return deny('scope_denied');
    if (!includes(apiKey.allowed_services, provider)) return deny('key_service_denied');
    if (!includes(apiKey.allowed_operations, `${provider}:${operationId}`)) return deny('key_operation_denied');
    if (!includes(apiKey.allowed_accounts, accountRef)) return deny('key_account_denied');
    if (!includes(apiKey.allowed_environments, environment)) return deny('key_environment_denied');
    if (!includes(apiKey.allowed_resources, resource)) return deny('key_resource_denied');
    if (Array.isArray(policy.secret_refs) && policy.secret_refs.some((name) => !includes(apiKey.allowed_secrets, name))) return deny('key_secret_denied');
  }

  return {
    allow: true,
    executionMode: policy.execution_mode || 'adapter',
    ttlMs: policy.ttl_seconds ? Number(policy.ttl_seconds) * 1000 : undefined,
    otpRequired: policy.otp?.required === true,
    otp: policy.otp ? {
      deviceId: policy.otp.device_id,
      simBinding: policy.otp.sim_binding,
      templateGroup: policy.otp.template_group,
      senderAllowlist: policy.otp.sender_allowlist,
      recipientRef: policy.otp.recipient_ref,
      challenge: policy.otp.challenge_ref || '',
      ttlMs: policy.otp.ttl_seconds ? Number(policy.otp.ttl_seconds) * 1000 : undefined,
    } : undefined,
  };
}
