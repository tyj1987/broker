import { randomUUID } from 'node:crypto';
import { V2Error, canonicalJson, sha256Base64Url } from './operations-v2.js';
import { validateTypedParameters } from './operation-policy.js';

const ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const STATES = new Set([
  'REQUESTED',
  'APPROVED',
  'EXECUTING',
  'SUCCEEDED',
  'DENIED',
  'FAILED',
  'EXPIRED',
  'CANCELLED',
]);
const STATE_VERSION = 1;
const APPROVAL_TTL_MS = 5 * 60_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
const RESOURCE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const STATE_RECORD_KEYS = new Set([
  'id',
  'requester',
  'provider',
  'operationId',
  'accountRef',
  'environment',
  'resourceRef',
  'requestHash',
  'requiredApprovals',
  'approvalRoles',
  'approvers',
  'status',
  'createdAt',
  'expiresAt',
]);
const APPROVER_KEYS = new Set(['name', 'approvedAt']);

function requireId(value, field) {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new V2Error('invalid_request', `${field} has an invalid format`);
  }
  return value;
}

function requireResourceRef(value) {
  if (
    typeof value !== 'string' ||
    !RESOURCE_REF_RE.test(value) ||
    value.includes('..') ||
    value.includes('//') ||
    value.endsWith('/') ||
    value.endsWith('.')
  ) {
    throw new V2Error('invalid_request', 'resource_ref has an invalid format');
  }
  return value;
}

function stateCorrupt(message) {
  return new V2Error('state_corrupt', `approval state is invalid: ${message}`, 500);
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validBoundedString(value, max = 256) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

function validateStateRecord(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !hasExactKeys(value, STATE_RECORD_KEYS)
  ) {
    throw stateCorrupt('record fields are invalid');
  }
  if (!UUID_RE.test(value.id || '')) throw stateCorrupt('id is invalid');
  if (!validBoundedString(value.requester)) throw stateCorrupt('requester is invalid');
  for (const field of ['provider', 'operationId', 'accountRef', 'environment']) {
    if (!ID_RE.test(value[field] || '')) throw stateCorrupt(`${field} is invalid`);
  }
  try {
    requireResourceRef(value.resourceRef);
  } catch {
    throw stateCorrupt('resourceRef is invalid');
  }
  if (!DIGEST_RE.test(value.requestHash || '')) throw stateCorrupt('request hash is invalid');
  if (
    !Number.isSafeInteger(value.requiredApprovals) ||
    value.requiredApprovals < 1 ||
    value.requiredApprovals > 10
  ) {
    throw stateCorrupt('required approvals is invalid');
  }
  if (
    !Array.isArray(value.approvalRoles) ||
    value.approvalRoles.length < 1 ||
    value.approvalRoles.length > 20 ||
    value.approvalRoles.some((role) => !ID_RE.test(role || '')) ||
    new Set(value.approvalRoles).size !== value.approvalRoles.length
  ) {
    throw stateCorrupt('approval roles are invalid');
  }
  if (!STATES.has(value.status)) throw stateCorrupt('status is invalid');
  if (
    !validTimestamp(value.createdAt) ||
    !validTimestamp(value.expiresAt) ||
    Date.parse(value.expiresAt) - Date.parse(value.createdAt) !== APPROVAL_TTL_MS
  ) {
    throw stateCorrupt('timestamps are invalid');
  }
  if (!Array.isArray(value.approvers) || value.approvers.length > 10) {
    throw stateCorrupt('approvers are invalid');
  }
  const names = new Set();
  for (const approver of value.approvers) {
    if (
      !approver ||
      typeof approver !== 'object' ||
      Array.isArray(approver) ||
      !hasExactKeys(approver, APPROVER_KEYS) ||
      !validBoundedString(approver.name) ||
      approver.name === value.requester ||
      names.has(approver.name) ||
      !validTimestamp(approver.approvedAt) ||
      Date.parse(approver.approvedAt) < Date.parse(value.createdAt) ||
      Date.parse(approver.approvedAt) > Date.parse(value.expiresAt)
    ) {
      throw stateCorrupt('approver entry is invalid');
    }
    names.add(approver.name);
  }
  const quorumReached = value.approvers.length >= value.requiredApprovals;
  if (
    (['REQUESTED', 'DENIED'].includes(value.status) && quorumReached) ||
    (['APPROVED', 'EXECUTING', 'SUCCEEDED', 'FAILED'].includes(value.status) && !quorumReached)
  ) {
    throw stateCorrupt('status conflicts with approval quorum');
  }
  return structuredClone(value);
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
    approvals: record.approvers.map((item) => ({
      approved_by: item.name,
      approved_at: item.approvedAt,
    })),
    status: record.status,
    created_at: record.createdAt,
    expires_at: record.expiresAt,
  };
}

function requestHash(input) {
  return sha256Base64Url(
    canonicalJson({
      provider: input.provider,
      operation_id: input.operation_id,
      account_ref: input.account_ref,
      environment: input.environment,
      typed_parameters: input.typed_parameters,
    }),
  );
}

function apiKeyAllowsApproval(identity, record) {
  const context = identity?.context;
  const key = context?.apiKey;
  if (!key) return context?.via !== 'api_key';
  const exactScope = `operations:${record.provider}:${record.operationId}`;
  return (
    (key?.scopes?.includes('operations:execute') || key?.scopes?.includes(exactScope)) &&
    key.allowed_services?.includes(record.provider) &&
    key.allowed_operations?.includes(`${record.provider}:${record.operationId}`) &&
    key.allowed_accounts?.includes(record.accountRef) &&
    key.allowed_environments?.includes(record.environment) &&
    key.allowed_resources?.includes(record.resourceRef)
  );
}

export class ApprovalBroker {
  constructor({
    now = () => Date.now(),
    getPolicy = () => null,
    onExpire = () => {},
    maxRecords = 10_000,
  } = {}) {
    if (typeof onExpire !== 'function') {
      throw new V2Error('checkpoint_invalid', 'approval expiry handler must be synchronous', 500);
    }
    this.now = now;
    this.getPolicy = getPolicy;
    this.onExpire = onExpire;
    this.maxRecords = maxRecords;
    this.records = new Map();
  }

  create(identity, input) {
    if (!validBoundedString(identity?.name))
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    this.prune();
    if (this.records.size >= this.maxRecords)
      throw new V2Error('capacity', 'approval capacity reached', 503);
    const provider = requireId(input?.provider, 'provider');
    const operationId = requireId(input?.operation_id, 'operation_id');
    const accountRef = requireId(input?.account_ref, 'account_ref');
    const environment = requireId(input?.environment, 'environment');
    const resourceRef = requireResourceRef(input?.typed_parameters?.resource_ref);
    const policy = this.getPolicy(provider, operationId);
    if (!policy || policy.enabled !== true || policy.approval_required !== true) {
      throw new V2Error(
        'approval_not_required',
        'operation does not accept approval requests',
        409,
      );
    }
    const validation = validateTypedParameters(input.typed_parameters, policy.parameter_schema);
    if (!validation.ok) throw new V2Error('invalid_request', validation.reason);
    if (
      !apiKeyAllowsApproval(identity, {
        provider,
        operationId,
        accountRef,
        environment,
        resourceRef,
      })
    ) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    if (
      !Array.isArray(policy.accounts) ||
      !policy.accounts.includes(accountRef) ||
      !Array.isArray(policy.environments) ||
      !policy.environments.includes(environment) ||
      (Array.isArray(policy.resources) &&
        policy.resources.length > 0 &&
        !policy.resources.includes(resourceRef))
    ) {
      throw new V2Error('forbidden', 'approval request is outside policy', 403);
    }
    const requiredApprovals = Number(policy.required_approvals || 1);
    if (
      !Number.isSafeInteger(requiredApprovals) ||
      requiredApprovals < 1 ||
      requiredApprovals > 10
    ) {
      throw new V2Error(
        'invalid_policy',
        'required_approvals must be an integer from 1 to 10',
        500,
      );
    }
    const approvalRoles = [...new Set(policy.approval_roles || ['admin'])];
    if (
      approvalRoles.length < 1 ||
      approvalRoles.length > 20 ||
      approvalRoles.some((role) => !ID_RE.test(role || ''))
    ) {
      throw new V2Error(
        'invalid_policy',
        'approval_roles must contain valid role identifiers',
        500,
      );
    }
    const now = this.now();
    const record = {
      id: randomUUID(),
      requester: identity.name,
      provider,
      operationId,
      accountRef,
      environment,
      resourceRef,
      requestHash: requestHash(input),
      requiredApprovals,
      approvalRoles,
      approvers: [],
      status: 'REQUESTED',
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
    };
    this.records.set(record.id, record);
    return publicApproval(record);
  }

  rollbackCreation(identity, id) {
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status)) {
      throw new V2Error('not_found', 'approval request not found', 404);
    }
    if (!validBoundedString(identity?.name)) {
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    }
    if (record.requester !== identity.name) {
      throw new V2Error('forbidden', 'approval request access denied', 403);
    }
    if (record.status !== 'REQUESTED' || record.approvers.length !== 0) {
      throw new V2Error('invalid_state', 'approval creation cannot be rolled back', 409);
    }
    this.records.delete(id);
  }

  decide(identity, id, decision) {
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status))
      throw new V2Error('not_found', 'approval request not found', 404);
    if (!validBoundedString(identity?.name)) {
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    }
    if (
      !identity.context ||
      identity.context.via !== 'session' ||
      !identity.context.authFactors?.includes('webauthn')
    ) {
      throw new V2Error('step_up_required', 'approval requires a fresh WebAuthn session', 403);
    }
    if (!apiKeyAllowsApproval(identity, record)) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    if (!record.approvalRoles.includes(identity.context.client?.role)) {
      throw new V2Error('forbidden', 'identity is not an approver', 403);
    }
    if (record.requester === identity.name) {
      throw new V2Error('separation_of_duties', 'requester cannot approve the request', 403);
    }
    this.getActive(id, identity);
    if (record.status !== 'REQUESTED') {
      throw new V2Error('invalid_state', 'approval request is already decided', 409);
    }
    if (decision === 'reject') {
      record.status = 'DENIED';
      return publicApproval(record);
    }
    if (decision !== 'approve')
      throw new V2Error('invalid_request', 'decision must be approve or reject');
    if (record.approvers.some((item) => item.name === identity.name)) {
      throw new V2Error('duplicate_approval', 'approver has already decided', 409);
    }
    record.approvers.push({ name: identity.name, approvedAt: new Date(this.now()).toISOString() });
    if (record.approvers.length >= record.requiredApprovals) record.status = 'APPROVED';
    return publicApproval(record);
  }

  decideAndAudit(identity, id, decision, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const record = this.records.get(id);
    const previous = record
      ? {
          status: record.status,
          approvers: record.approvers.map((item) => ({ ...item })),
        }
      : null;
    const result = this.decide(identity, id, decision);
    try {
      commitAudit(result);
    } catch (error) {
      if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
      if (!previous || this.records.get(id) !== record) {
        throw new V2Error('audit_rollback_failed', 'approval audit rollback failed', 503);
      }
      record.status = previous.status;
      record.approvers = previous.approvers;
      throw error;
    }
    return result;
  }

  list(identity) {
    if (!validBoundedString(identity?.name))
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    this.prune();
    const context = identity.context;
    const role = context?.client?.role;
    const canReviewOthers = context?.via === 'session' && context.authFactors?.includes('webauthn');
    return [...this.records.values()]
      .filter(
        (record) =>
          apiKeyAllowsApproval(identity, record) &&
          (record.requester === identity.name ||
            (canReviewOthers && record.approvalRoles.includes(role))),
      )
      .map(publicApproval);
  }

  claimFor(identity, input) {
    const id = input?.approval_request_id;
    if (!id) return null;
    if (!validBoundedString(identity?.name))
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const candidate = this.records.get(id);
    if (!candidate || !STATES.has(candidate.status))
      throw new V2Error('not_found', 'approval request not found', 404);
    if (!apiKeyAllowsApproval(identity, candidate)) {
      throw new V2Error('forbidden', 'API key is not authorized for this approval', 403);
    }
    const record = this.getActive(id, identity);
    if (
      record.status !== 'APPROVED' ||
      record.requester !== identity?.name ||
      record.requestHash !== requestHash(input)
    ) {
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
    if (!record || record.status !== 'EXECUTING')
      throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    record.status = 'SUCCEEDED';
  }

  rollbackSucceeded(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'SUCCEEDED') {
      throw new V2Error('approval_mismatch', 'approval outcome cannot be rolled back', 409);
    }
    record.status = 'EXECUTING';
  }

  markFailed(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'EXECUTING')
      throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    record.status = 'FAILED';
  }

  rollbackFailed(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'FAILED') {
      throw new V2Error('approval_mismatch', 'approval failure cannot be rolled back', 409);
    }
    record.status = 'EXECUTING';
  }

  releaseClaim(id) {
    if (!id) return;
    const record = this.records.get(id);
    if (!record || record.status !== 'EXECUTING')
      throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    record.status = 'APPROVED';
  }

  cancelForTask(id) {
    if (!id) return null;
    const record = this.records.get(id);
    if (!record || !['REQUESTED', 'APPROVED', 'CANCELLED'].includes(record.status)) {
      throw new V2Error('approval_mismatch', 'approval is unavailable', 409);
    }
    const previousStatus = record.status;
    record.status = 'CANCELLED';
    return previousStatus;
  }

  restoreTaskCancellation(id, previousStatus) {
    if (!id) return;
    const record = this.records.get(id);
    if (
      !record ||
      record.status !== 'CANCELLED' ||
      !['REQUESTED', 'APPROVED', 'CANCELLED'].includes(previousStatus)
    ) {
      throw new V2Error('state_rollback_failed', 'approval cancellation rollback failed', 503);
    }
    record.status = previousStatus;
  }

  cancel(identity, id) {
    if (!validBoundedString(identity?.name))
      throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status))
      throw new V2Error('not_found', 'approval request not found', 404);
    const isAdmin = identity.context?.client?.role === 'admin';
    if (record.requester !== identity.name && !isAdmin)
      throw new V2Error('forbidden', 'identity cannot cancel this request', 403);
    if (
      record.requester !== identity.name &&
      (identity.context?.via !== 'session' || !identity.context?.authFactors?.includes('webauthn'))
    ) {
      throw new V2Error(
        'step_up_required',
        'administrator cancellation requires a fresh WebAuthn session',
        403,
      );
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

  cancelAndAudit(identity, id, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const record = this.records.get(id);
    const previousStatus = record?.status;
    const result = this.cancel(identity, id);
    try {
      commitAudit(result);
    } catch (error) {
      if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
      if (!record || this.records.get(id) !== record) {
        throw new V2Error('audit_rollback_failed', 'approval audit rollback failed', 503);
      }
      record.status = previousStatus;
      throw error;
    }
    return result;
  }

  exportState() {
    this.prune();
    return {
      version: STATE_VERSION,
      records: [...this.records.values()].map((record) => structuredClone(record)),
    };
  }

  restoreState(snapshot) {
    if (
      !snapshot ||
      typeof snapshot !== 'object' ||
      Array.isArray(snapshot) ||
      !hasExactKeys(snapshot, new Set(['version', 'records'])) ||
      snapshot.version !== STATE_VERSION ||
      !Array.isArray(snapshot.records)
    ) {
      throw stateCorrupt('snapshot envelope is invalid');
    }
    if (snapshot.records.length > this.maxRecords) throw stateCorrupt('snapshot exceeds capacity');
    const records = new Map();
    for (const candidate of snapshot.records) {
      const record = validateStateRecord(candidate);
      if (records.has(record.id)) throw stateCorrupt('snapshot contains duplicate records');
      records.set(record.id, record);
    }
    this.records = records;
    this.prune();
  }

  getActive(id, identity = null) {
    const record = this.records.get(id);
    if (!record || !STATES.has(record.status))
      throw new V2Error('not_found', 'approval request not found', 404);
    if (
      new Date(record.expiresAt).getTime() <= this.now() &&
      ['REQUESTED', 'APPROVED'].includes(record.status)
    ) {
      const previousStatus = record.status;
      record.status = 'EXPIRED';
      try {
        const result = this.onExpire(publicApproval(record), identity);
        if (result && typeof result.then === 'function') {
          Promise.resolve(result).catch(() => {});
          throw new V2Error(
            'checkpoint_invalid',
            'approval expiry handler must be synchronous',
            500,
          );
        }
      } catch (error) {
        if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
        record.status = previousStatus;
        throw error;
      }
    }
    if (record.status === 'EXPIRED')
      throw new V2Error('approval_expired', 'approval request expired', 409);
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
