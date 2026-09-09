const SAFE_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/;

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

export function validateTypedParameters(value, schema) {
  if (!schema || schema.type !== 'object' || !schema.properties || typeof schema.properties !== 'object') {
    return { ok: false, reason: 'parameter_schema_missing' };
  }
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
    if (!rule || !matchesType(item, rule.type)) return { ok: false, reason: 'parameter_type_mismatch' };
    if (Array.isArray(rule.enum) && !rule.enum.includes(item)) return { ok: false, reason: 'parameter_enum_mismatch' };
    if (typeof item === 'string') {
      if (item.length < Number(rule.min_length || 0)) return { ok: false, reason: 'parameter_too_short' };
      if (item.length > Number(rule.max_length || 4096)) return { ok: false, reason: 'parameter_too_long' };
      if (rule.format === 'identifier' && !SAFE_ID.test(item)) return { ok: false, reason: 'parameter_format_mismatch' };
    }
    if (Array.isArray(item) && item.length > Number(rule.max_items || 100)) {
      return { ok: false, reason: 'parameter_array_too_large' };
    }
  }
  return { ok: true };
}

function hasApproval(ctx, provider, operationId, accountRef, now) {
  return (ctx?.approvalGrants || []).some((grant) => grant
    && grant.provider === provider
    && grant.operation_id === operationId
    && grant.account_ref === accountRef
    && grant.approved_by !== ctx.clientName
    && Number(grant.expires_at_ms) > now);
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

  const serviceAllowed = includes(client.allowed_services, provider)
    || (client.allowed_proxy || []).some((entry) => entry?.service === provider);
  if (!serviceAllowed) return deny('service_denied');

  const parameters = validateTypedParameters(typedParameters, policy.parameter_schema);
  if (!parameters.ok) return deny(parameters.reason);

  const resource = typedParameters.resource_ref;
  if (Array.isArray(policy.resources) && policy.resources.length > 0 && !includes(policy.resources, resource)) {
    return deny('resource_denied');
  }
  if (policy.approval_required === true && options.ignoreApproval !== true
    && !hasApproval(ctx, provider, operationId, accountRef, now)) {
    return deny('approval_required');
  }

  const apiKey = ctx.apiKey;
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
