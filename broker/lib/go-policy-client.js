import http from 'node:http';

const MAX_RESPONSE_BYTES = 64 * 1024;

function listOr(value, fallback) {
  return Array.isArray(value) && value.length > 0 ? [...value] : [...fallback];
}

function approvalsFor(ctx, provider, operationId, accountRef, now) {
  const approvers = new Set();
  for (const grant of ctx?.approvalGrants || []) {
    if (grant?.provider !== provider || grant.operation_id !== operationId || grant.account_ref !== accountRef) continue;
    if (Number(grant.expires_at_ms) <= now || !grant.approved_by || grant.approved_by === ctx.clientName) continue;
    approvers.add(grant.approved_by);
  }
  return approvers.size;
}

export function corePolicyPayload(config, operation, preliminary, now = Date.now(), options = {}) {
  const { identity, provider, operationId, accountRef, environment, typedParameters } = operation;
  const ctx = identity.context;
  const client = ctx.client;
  const policy = config.operation_policies[provider][operationId];
  const key = ctx.apiKey;
  const resource = typeof typedParameters.resource_ref === 'string' ? typedParameters.resource_ref : '';
  const policyTTL = Math.min(Math.max(Number(policy.ttl_seconds || 300) * 1000, 10_000), 900_000);
  const operationValues = (key?.allowed_operations || []).map((value) => {
    const prefix = `${provider}:`;
    return value.startsWith(prefix) ? value.slice(prefix.length) : value;
  });
  const serviceValues = listOr(key?.allowed_services, listOr(client.allowed_services, [provider]));
  const accountValues = listOr(key?.allowed_accounts, listOr(client.allowed_accounts, policy.accounts));
  const resourceValues = listOr(key?.allowed_resources, listOr(client.allowed_resources, policy.resources || []));
  const environmentValues = listOr(key?.allowed_environments, listOr(client.allowed_environments, policy.environments));
  const configuredApprovals = Math.max(Number(policy.required_approvals || 0), policy.approval_required ? 1 : 0);
  const requiredApprovals = options.ignoreApproval === true ? 0 : configuredApprovals;
  return {
    subject: {
      id: identity.name,
      role: client.role,
      security_profile: client.security_profile,
      providers: serviceValues,
      operations: listOr(operationValues, [operationId]),
      accounts: accountValues,
      resources: resourceValues,
      environments: environmentValues,
      maximum_ttl_ms: policyTTL,
      requires_approval: false,
      requires_two_persons: configuredApprovals >= 2,
    },
    request: {
      provider,
      operation: operationId,
      account: accountRef,
      resource,
      environment,
      requested_ttl_ms: Math.min(Number(preliminary.ttlMs || policyTTL), policyTTL),
      step_up: (ctx.authFactors || []).includes('webauthn'),
      approval_count: approvalsFor(ctx, provider, operationId, accountRef, now),
      source_ip: ctx.sourceIp || '',
      at: new Date(now).toISOString(),
    },
    rule: {
      enabled: policy.enabled === true,
      roles: policy.roles,
      security_profiles: policy.security_profiles,
      providers: [provider],
      operations: [operationId],
      accounts: policy.accounts,
      resources: policy.resources || [],
      environments: policy.environments,
      maximum_ttl_ms: policyTTL,
      require_step_up: policy.step_up_required === true,
      required_approvals: requiredApprovals,
    },
  };
}

export function evaluateWithCore(socketPath, payload, timeoutMs = 2_000) {
  return new Promise((resolve) => {
    const encoded = Buffer.from(JSON.stringify(payload));
    const request = http.request({
      socketPath,
      path: '/v1/evaluate',
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'content-length': encoded.length,
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) request.destroy(new Error('policy response too large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          if (response.statusCode !== 200) return resolve({ allow: false, reason: 'core_rejected' });
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (typeof value.allow !== 'boolean' || typeof value.code !== 'string') throw new Error('invalid policy response');
          resolve({ allow: value.allow, reason: value.code, ttlMs: Number(value.ttl_ms) || undefined });
        } catch {
          resolve({ allow: false, reason: 'core_invalid_response' });
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('policy timeout')));
    request.on('error', () => resolve({ allow: false, reason: 'core_unavailable' }));
    request.end(encoded);
  });
}

export function createOperationAuthorizer(configSource, options = {}) {
  const socketPath = options.socketPath || process.env.BROKER_CORE_SOCKET;
  const requireCore = options.requireCore ?? process.env.NODE_ENV === 'production';
  return async (operation, preliminary, evaluationOptions = {}) => {
    if (!preliminary?.allow) return preliminary;
    if (!socketPath) return requireCore ? { allow: false, reason: 'core_required' } : preliminary;
    const config = typeof configSource === 'function' ? configSource() : configSource;
    if (!config) return { allow: false, reason: 'core_config_missing' };
    const decision = await evaluateWithCore(
      socketPath,
      corePolicyPayload(config, operation, preliminary, Date.now(), evaluationOptions),
    );
    if (!decision.allow) return decision;
    return { ...preliminary, ttlMs: Math.min(Number(preliminary.ttlMs || 900_000), decision.ttlMs) };
  };
}
