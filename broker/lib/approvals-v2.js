import { randomUUID } from 'node:crypto';
import { V2Error, canonicalJson, sha256Base64Url } from './operations-v2.js';
import { validateTypedParameters } from './operation-policy.js';

const ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const STATES = new Set(['REQUESTED', 'APPROVED', 'EXECUTING', 'SUCCEEDED', 'DENIED', 'FAILED', 'EXPIRED', 'CANCELLED']);

function requireId(value, field) {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new V2Error('invalid_request', `${field} has an invalid format`);
  }
  return value;
}

function publicApproval(record) {
  return {
    id: record.id,
    requester: record.requester,
    provider: record.provider,
    operation_id: record.operationId,
    account_ref: record.accountRef,
    environment: record.environment,
    resource_ref: record.resourceRef,
    required_approvals: record.requiredApprovals,
    approvals: record.approvers.map((item) => ({ approved_by: item.name, approved_at: item.approvedAt })),
    status: record.status,
    created_at: record.createdAt,
    expires_at: record.expiresAt,
  };
}

function requestHash(input) {
  return sha256Base64Url(canonicalJson({
    provider: input.provider,
    operation_id: input.operation_id,
    account_ref: input.account_ref,
    environment: input.environment,
    typed_parameters: input.typed_parameters,
  }));
}

function apiKeyAllowsApproval(identity, record) {
  const context = identity?.context;
  if (context?.via !== 'api_key') return true;
  const key = context.apiKey;
  const exactScope = `operations:${record.provider}:${record.operationId}`;
  return (key?.scopes?.includes('operations:execute') || key?.scopes?.includes(exactScope))
    && key.allowed_services?.includes(record.provider)
    && key.allowed_operations?.includes(`${record.provider}:${record.operationId}`)
    && key.allowed_accounts?.includes(record.accountRef)
    && key.allowed_environments?.includes(record.environment)
    && key.allowed_resources?.includes(record.resourceRef);
}

export class ApprovalBroker {
  constructor({ now = () => Date.now(), getPolicy = () => null, maxRecords = 10_000 } = {}) {
    this.now = now;
    this.getPolicy = getPolicy;
    this.maxRecords = maxRecords;
    this.records = new Map();
  }

  create(identity, input) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    this.prune();
    if (this.records.size >= this.maxRecords) throw new V2Error('capacity', 'approval capacity reached', 503);
    const provider = requireId(input?.provider, 'provider');
    const operationId = requireId(input?.operation_id, 'operation_id');
    const accountRef = requireId(input?.account_ref, 'account_ref');
    const resourceRef = requireId(input?.typed_parameters?.resource_ref, 'resource_ref');
    const policy = this.getPolicy(provider, operationId);
    if (!policy || policy.enabled !== true || policy.approval_required !== true) {
      throw new V2Error('approval_not_required', 'operation does not accept approval requests', 409);
    }
    const validation = validateTypedParameters(input.typed_parameters, policy.parameter_schema);
    if (!validation.ok) throw new V2Error('invalid_request', validation.reason);
    if (!apiKeyAllowsApproval(identity, {
      provider, operationId, accountRef, environment: input.environment, resourceRef,
    })) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    if (!Array.isArray(policy.accounts) || !policy.accounts.includes(accountRef)
      || !Array.isArray(policy.environments) || !policy.environments.includes(input.environment)
      || (Array.isArray(policy.resources) && policy.resources.length > 0 && !policy.resources.includes(resourceRef))) {
      throw new V2Error('forbidden', 'approval request is outside policy', 403);
    }
    const requiredApprovals = Number(policy.required_approvals || 1);
    if (!Number.isSafeInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 10) {
      throw new V2Error('invalid_policy', 'required_approvals must be an integer from 1 to 10', 500);
    }
    const now = this.now();
    const record = {
      id: randomUUID(), requester: identity.name, provider, operationId, accountRef,
      environment: input.environment, resourceRef, requestHash: requestHash(input), requiredApprovals,
      approvalRoles: [...new Set(policy.approval_roles || ['admin'])], approvers: [], status: 'REQUESTED',
      createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 5 * 60_000).toISOString(),
    };
    this.records.set(record.id, record);
    return publicApproval(record);
  }

  decide(identity, id, decision) {
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status)) throw new V2Error('not_found', 'approval request not found', 404);
    if (!identity?.name || !identity.context || identity.context.via !== 'session'
      || !identity.context.authFactors?.includes('webauthn')) {
      throw new V2Error('step_up_required', 'approval requires a fresh WebAuthn session', 403);
    }
    if (!record.approvalRoles.includes(identity.context.client?.role)) {
      throw new V2Error('forbidden', 'identity is not an approver', 403);
    }
    if (record.requester === identity.name) {
      throw new V2Error('separation_of_duties', 'requester cannot approve the request', 403);
    }
    this.getActive(id);
    if (record.status !== 'REQUESTED') {
      throw new V2Error('invalid_state', 'approval request is already decided', 409);
    }
    if (decision === 'reject') {
      record.status = 'DENIED';
      return publicApproval(record);
    }
    if (decision !== 'approve') throw new V2Error('invalid_request', 'decision must be approve or reject');
    if (record.approvers.some((item) => item.name === identity.name)) {
      throw new V2Error('duplicate_approval', 'approver has already decided', 409);
    }
    record.approvers.push({ name: identity.name, approvedAt: new Date(this.now()).toISOString() });
    if (record.approvers.length >= record.requiredApprovals) record.status = 'APPROVED';
    return publicApproval(record);
  }

  list(identity) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    this.prune();
    const context = identity.context;
    const role = context?.client?.role;
    const canReviewOthers = context?.via === 'session'
      && context.authFactors?.includes('webauthn');
    return [...this.records.values()]
      .filter((record) => apiKeyAllowsApproval(identity, record)
        && (record.requester === identity.name
          || (canReviewOthers && record.approvalRoles.includes(role))))
      .map(publicApproval);
  }

  claimFor(identity, input) {
    const id = input?.approval_request_id;
    if (!id) return null;
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const candidate = this.records.get(id);
    if (!candidate || !STATES.has(candidate.status)) throw new V2Error('not_found', 'approval request not found', 404);
    if (!apiKeyAllowsApproval(identity, candidate)) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    const record = this.getActive(id);
    if (record.status !== 'APPROVED' || record.requester !== identity?.name
      || record.requestHash !== requestHash(input)) {
      throw new V2Error('approval_mismatch', 'approval does not match this operation', 403);
    }
    record.status = 'EXECUTING';
    const grants = record.approvers.map((item) => ({
      provider: record.provider,
      operation_id: record.operationId,
      account_ref: record.accountRef,
      approved_by: item.name,
      expires_at_ms: new Date(record.expiresAt).getTime(),
    }));
    return { id, grants };
  }

  markSucceeded(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'EXECUTING') throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    record.status = 'SUCCEEDED';
  }

  markFailed(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'EXECUTING') throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    record.status = 'FAILED';
  }

  cancel(identity, id) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status)) throw new V2Error('not_found', 'approval request not found', 404);
    const isAdmin = identity.context?.client?.role === 'admin';
    if (record.requester !== identity.name && !isAdmin) throw new V2Error('forbidden', 'identity cannot cancel this request', 403);
    if (record.requester !== identity.name
      && (identity.context?.via !== 'session' || !identity.context?.authFactors?.includes('webauthn'))) {
      throw new V2Error('step_up_required', 'administrator cancellation requires a fresh WebAuthn session', 403);
    }
    if (!apiKeyAllowsApproval(identity, record)) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    if (!['REQUESTED', 'APPROVED'].includes(record.status)) {
      throw new V2Error('invalid_state', 'approval request cannot be cancelled', 409);
    }
    record.status = 'CANCELLED';
    return publicApproval(record);
  }

  getActive(id) {
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status)) throw new V2Error('not_found', 'approval request not found', 404);
    if (new Date(record.expiresAt).getTime() <= this.now()
      && ['REQUESTED', 'APPROVED'].includes(record.status)) {
      record.status = 'EXPIRED';
    }
    if (record.status === 'EXPIRED') throw new V2Error('approval_expired', 'approval request expired', 409);
    if (['DENIED', 'SUCCEEDED', 'FAILED', 'CANCELLED'].includes(record.status)) {
      throw new V2Error('invalid_state', 'approval request is no longer active', 409);
    }
    return record;
  }

  prune() {
    const cutoff = this.now() - 60 * 60_000;
    for (const [id, record] of this.records) {
      if (new Date(record.expiresAt).getTime() < cutoff) this.records.delete(id);
    }
  }
}
