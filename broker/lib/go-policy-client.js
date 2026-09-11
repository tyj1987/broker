import { createHash } from 'node:crypto';
import http from 'node:http';

const MAX_RESPONSE_BYTES = 64 * 1024;
const DECISION_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

function listOr(value, fallback) {
  return Array.isArray(value) && value.length > 0 ? [...value] : [...fallback];
}

function approvalsFor(ctx, actorName, provider, operationId, accountRef, environment, resource, now) {
  const approvers = new Set();
  for (const grant of ctx?.approvalGrants || []) {
    if (grant?.provider !== provider || grant.operation_id !== operationId || grant.account_ref !== accountRef
      || grant.environment !== environment || grant.resource_ref !== resource) continue;
    const expiresAt = grant.expires_at_ms;
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now
      || typeof grant.approved_by !== 'string' || grant.approved_by.length === 0
      || grant.approved_by === actorName) continue;
    approvers.add(grant.approved_by);
  }
  return approvers.size;
}

export function corePolicyPayload(config, operation, preliminary, now = Date.now(), options = {}) {
  const { identity, provider, operationId, accountRef, environment, typedParameters } = operation;
  const ctx = identity.context;
  const client = ctx.client;
  const policy = config.operation_policies[provider][operationId];
  const tool = preliminary.tool;
  const toolIdentity = tool?.name && tool?.version ? `${tool.name}@${tool.version}` : '';
  const targetKind = tool?.target?.kind || '';
  const riskLevel = tool?.risk_level || '';
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
  const configuredApprovalsInput = policy.required_approvals === undefined ? 0 : policy.required_approvals;
  if (!Number.isSafeInteger(configuredApprovalsInput) || configuredApprovalsInput < 0 || configuredApprovalsInput > 10) {
    throw new Error('invalid required_approvals policy');
  }
  const configuredApprovals = Math.max(configuredApprovalsInput, policy.approval_required ? 1 : 0);
  return {
    subject: {
      id: identity.name,
      role: client.role,
      principal_type: client.principal_type || (ctx.via === 'session' ? 'human' : 'agent'),
      security_profile: client.security_profile,
      tools: toolIdentity ? [toolIdentity] : [],
      target_kinds: targetKind ? [targetKind] : [],
      risk_levels: riskLevel ? [riskLevel] : [],
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
      tool: toolIdentity,
      target_kind: targetKind,
      risk_level: riskLevel,
      provider,
      operation: operationId,
      account: accountRef,
      resource,
      environment,
      requested_ttl_ms: Math.min(Number(preliminary.ttlMs || policyTTL), policyTTL),
      step_up: (ctx.authFactors || []).includes('webauthn'),
      approval_count: approvalsFor(ctx, identity.name, provider, operationId, accountRef, environment, resource, now),
      approval_phase: options.ignoreApproval === true,
      source_ip: ctx.sourceIp || '',
      at: new Date(now).toISOString(),
    },
    rule: {
      enabled: policy.enabled === true,
      tools: toolIdentity ? [toolIdentity] : [],
      target_kinds: targetKind ? [targetKind] : [],
      risk_levels: riskLevel ? [riskLevel] : [],
      allow_agent_execute: tool?.agent_execution === true,
      roles: policy.roles,
      security_profiles: policy.security_profiles,
      providers: [provider],
      operations: [operationId],
      accounts: policy.accounts,
      resources: policy.resources || [],
      environments: policy.environments,
      maximum_ttl_ms: policyTTL,
      require_step_up: policy.step_up_required === true,
      required_approvals: configuredApprovals,
      source_cidrs: policy.source_cidrs || [],
      not_before: policy.not_before || '',
      not_after: policy.not_after || '',
    },
  };
}

export function evaluateWithCore(socketPath, payload, timeoutMs = 2_000) {
  return new Promise((resolve) => {
    const encoded = Buffer.from(JSON.stringify(payload));
    const requestBinding = createHash('sha256').update(encoded).digest('base64url');
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
          const keys = Object.keys(value || {}).sort().join(',');
          const requestedTTL = payload?.request?.requested_ttl_ms;
          if (
            keys !== 'allow,code,request_binding,ttl_ms' ||
            typeof value.allow !== 'boolean' ||
            !DECISION_CODE_RE.test(value.code || '') ||
            value.request_binding !== requestBinding ||
            !Number.isSafeInteger(value.ttl_ms) ||
            (value.allow && (
              value.code !== 'allowed' ||
              value.ttl_ms < 1 ||
              !Number.isSafeInteger(requestedTTL) ||
              value.ttl_ms > requestedTTL
            )) ||
            (!value.allow && (value.code === 'allowed' || value.ttl_ms !== 0))
          ) {
            throw new Error('invalid policy response');
          }
          resolve({
            allow: value.allow,
            reason: value.code,
            ttlMs: value.allow ? value.ttl_ms : undefined,
          });
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
    let payload;
    try {
      payload = corePolicyPayload(config, operation, preliminary, Date.now(), evaluationOptions);
    } catch {
      return { allow: false, reason: 'core_config_invalid' };
    }
    const decision = await evaluateWithCore(socketPath, payload);
    if (!decision.allow) return decision;
    return { ...preliminary, ttlMs: Math.min(Number(preliminary.ttlMs || 900_000), decision.ttlMs) };
  };
}
