import assert from 'node:assert/strict';
import { ApprovalBroker } from '../broker/lib/approvals-v2.js';
import { V2Error } from '../broker/lib/operations-v2.js';

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
let now = 1_900_000_000_000;
const policy = {
  enabled: true,
  approval_required: true,
  required_approvals: 2,
  approval_roles: ['admin'],
  accounts: ['primary'],
  environments: ['production'],
  resources: ['billing-summary'],
  parameter_schema: {
    type: 'object',
    required: ['resource_ref'],
    properties: { resource_ref: { type: 'string', format: 'identifier' } },
  },
};
const broker = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
});
const requester = {
  name: 'requester',
  context: {
    via: 'api_key',
    client: { role: 'developer' },
    apiKey: {
      scopes: ['operations:execute'],
      allowed_services: ['aliyun'],
      allowed_operations: ['aliyun:billing.read'],
      allowed_accounts: ['primary'],
      allowed_environments: ['production'],
      allowed_resources: ['billing-summary'],
    },
  },
};
const revokedRequester = {
  ...requester,
  context: {
    ...requester.context,
    apiKey: { ...requester.context.apiKey, allowed_operations: [] },
  },
};
const approver = (name, role = 'admin') => ({
  name,
  context: { via: 'session', authFactors: ['webauthn'], client: { role } },
});
const input = {
  provider: 'aliyun',
  operation_id: 'billing.read',
  account_ref: 'primary',
  environment: 'production',
  typed_parameters: { resource_ref: 'billing-summary' },
};
const atomicBroker = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
});

assert.throws(() => broker.create(null, input), expectCode('unauthorized'));
const invalidPrincipal = { ...requester, name: 'invalid\0principal' };
assert.throws(() => broker.create(invalidPrincipal, input), expectCode('unauthorized'));
assert.throws(() => broker.list(invalidPrincipal), expectCode('unauthorized'));
assert.throws(
  () => broker.create(requester, { ...input, operation_id: 'unapproved' }),
  expectCode('approval_not_required'),
);
assert.throws(
  () => broker.create(requester, { ...input, account_ref: 'other' }),
  expectCode('forbidden'),
);
assert.throws(
  () => broker.create(requester, { ...input, environment: 'invalid environment' }),
  expectCode('invalid_request'),
);
assert.throws(
  () => broker.create(requester, { ...input, typed_parameters: {} }),
  expectCode('invalid_request'),
);
for (const resource_ref of [
  '../billing',
  'https://evil.example/steal',
  'billing/',
  'billing.',
  'bad\nresource',
]) {
  assert.throws(
    () => broker.create(requester, { ...input, typed_parameters: { resource_ref } }),
    expectCode('invalid_request'),
  );
}
assert.throws(() => broker.create(revokedRequester, input), expectCode('forbidden'));

const repositoryPolicy = {
  ...policy,
  required_approvals: 1,
  resources: ['tyj1987/broker'],
  parameter_schema: {
    type: 'object',
    required: ['resource_ref'],
    properties: { resource_ref: { type: 'string' } },
  },
};
const repositoryBroker = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) =>
    provider === 'github' && operationId === 'pull_request.create' ? repositoryPolicy : null,
});
const repositoryRequester = {
  ...requester,
  context: {
    ...requester.context,
    apiKey: {
      ...requester.context.apiKey,
      allowed_services: ['github'],
      allowed_operations: ['github:pull_request.create'],
      allowed_resources: ['tyj1987/broker'],
    },
  },
};
const repositoryApproval = repositoryBroker.create(repositoryRequester, {
  provider: 'github',
  operation_id: 'pull_request.create',
  account_ref: 'primary',
  environment: 'production',
  typed_parameters: { resource_ref: 'tyj1987/broker' },
});
assert.equal(repositoryApproval.resource_ref, 'tyj1987/broker');
assert.equal(
  repositoryBroker.cancel(repositoryRequester, repositoryApproval.id).status,
  'CANCELLED',
);

const unpublished = broker.create(requester, input);
assert.throws(
  () => broker.rollbackCreation(invalidPrincipal, unpublished.id),
  expectCode('unauthorized'),
);
assert.throws(
  () => broker.claimFor(invalidPrincipal, { ...input, approval_request_id: unpublished.id }),
  expectCode('unauthorized'),
);
assert.throws(() => broker.cancel(invalidPrincipal, unpublished.id), expectCode('unauthorized'));
assert.throws(
  () =>
    broker.decide(
      { ...approver('invalid'), name: 'invalid\nprincipal' },
      unpublished.id,
      'approve',
    ),
  expectCode('unauthorized'),
);
assert.throws(
  () => broker.rollbackCreation({ ...requester, name: 'other-requester' }, unpublished.id),
  expectCode('forbidden'),
);
broker.rollbackCreation(requester, unpublished.id);
assert.throws(() => broker.rollbackCreation(requester, unpublished.id), expectCode('not_found'));

const decisionRollback = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.decideAndAudit(approver('admin-rollback'), decisionRollback.id, 'approve', () => {
      throw new Error('audit unavailable');
    }),
  /audit unavailable/,
);
assert.equal(
  atomicBroker.list(requester).find((item) => item.id === decisionRollback.id).approvals.length,
  0,
  'a failed decision audit restores the approver set',
);
assert.equal(
  atomicBroker.decide(approver('admin-rollback'), decisionRollback.id, 'approve').status,
  'REQUESTED',
);
assert.equal(atomicBroker.cancel(requester, decisionRollback.id).status, 'CANCELLED');
const indeterminateDecision = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.decideAndAudit(
      approver('admin-indeterminate'),
      indeterminateDecision.id,
      'approve',
      () => {
        throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
      },
    ),
  expectCode('state_commit_indeterminate'),
);
assert.equal(
  atomicBroker.list(requester).find((item) => item.id === indeterminateDecision.id).approvals
    .length,
  1,
  'an indeterminate durable commit must retain the matching in-memory decision',
);
assert.equal(atomicBroker.cancel(requester, indeterminateDecision.id).status, 'CANCELLED');
const decisionWithoutAudit = atomicBroker.create(requester, input);
assert.throws(
  () => atomicBroker.decideAndAudit(approver('admin-no-audit'), decisionWithoutAudit.id, 'approve'),
  expectCode('audit_unavailable'),
);
assert.equal(atomicBroker.cancel(requester, decisionWithoutAudit.id).status, 'CANCELLED');
const auditedDecision = atomicBroker.create(requester, input);
let decisionAuditCommitted = false;
assert.equal(
  atomicBroker.decideAndAudit(approver('admin-audited'), auditedDecision.id, 'approve', () => {
    decisionAuditCommitted = true;
  }).status,
  'REQUESTED',
);
assert.equal(decisionAuditCommitted, true);
assert.equal(atomicBroker.cancel(requester, auditedDecision.id).status, 'CANCELLED');
const rejectedRollback = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.decideAndAudit(approver('admin-reject'), rejectedRollback.id, 'reject', () => {
      throw new Error('audit unavailable');
    }),
  /audit unavailable/,
);
assert.equal(
  atomicBroker.decide(approver('admin-reject'), rejectedRollback.id, 'reject').status,
  'DENIED',
);
const decisionRollbackFailure = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.decideAndAudit(
      approver('admin-map-change'),
      decisionRollbackFailure.id,
      'approve',
      () => {
        atomicBroker.records.delete(decisionRollbackFailure.id);
        throw new Error('audit unavailable');
      },
    ),
  expectCode('audit_rollback_failed'),
);

const request = broker.create(requester, input);
assert.equal(request.status, 'REQUESTED');
assert.equal(request.required_approvals, 2);
assert.equal(broker.list(requester).length, 1);
assert.equal(
  broker.list({ name: 'admin-key', context: { via: 'api_key', client: { role: 'admin' } } }).length,
  0,
  'an admin API key cannot enumerate other requesters approvals',
);
assert.equal(
  broker.list({
    name: 'admin-session',
    context: { via: 'session', authFactors: [], client: { role: 'admin' } },
  }).length,
  0,
  'an unstepped-up admin session cannot enumerate other requesters approvals',
);
assert.equal(broker.list(approver('admin-reviewer')).length, 1);
const narrowedApprover = {
  ...approver('admin-narrowed'),
  context: {
    ...approver('admin-narrowed').context,
    apiKey: { ...requester.context.apiKey, allowed_operations: [] },
  },
};
assert.equal(
  broker.list(narrowedApprover).length,
  0,
  'a bearer key narrows approval visibility on a session',
);
assert.throws(
  () => broker.decide(narrowedApprover, request.id, 'approve'),
  expectCode('forbidden'),
);
assert.throws(
  () =>
    broker.decide(
      { name: 'admin-a', context: { via: 'mtls', client: { role: 'admin' } } },
      request.id,
      'approve',
    ),
  expectCode('step_up_required'),
);
assert.throws(
  () => broker.decide(approver('requester'), request.id, 'approve'),
  expectCode('separation_of_duties'),
);
assert.throws(
  () => broker.decide(approver('developer-a', 'developer'), request.id, 'approve'),
  expectCode('forbidden'),
);
assert.throws(
  () => broker.decide(approver('admin-a'), request.id, 'invalid'),
  expectCode('invalid_request'),
);
assert.equal(broker.decide(approver('admin-a'), request.id, 'approve').status, 'REQUESTED');
assert.throws(() => broker.rollbackCreation(requester, request.id), expectCode('invalid_state'));
assert.throws(
  () => broker.decide(approver('admin-a'), request.id, 'approve'),
  expectCode('duplicate_approval'),
);
assert.equal(broker.decide(approver('admin-b'), request.id, 'approve').status, 'APPROVED');
assert.throws(
  () => broker.decide(approver('developer-terminal', 'developer'), request.id, 'approve'),
  expectCode('forbidden'),
  'an unauthorized role cannot use a terminal approval as a state oracle',
);
assert.throws(
  () =>
    broker.decide(
      {
        name: 'admin-unstepped',
        context: { via: 'session', authFactors: [], client: { role: 'admin' } },
      },
      request.id,
      'approve',
    ),
  expectCode('step_up_required'),
  'a session without WebAuthn cannot use a terminal approval as a state oracle',
);
assert.throws(
  () => broker.decide(approver('admin-c'), request.id, 'approve'),
  expectCode('invalid_state'),
);

assert.equal(
  broker.list(revokedRequester).length,
  0,
  'revoked API key cannot list its former approvals',
);
assert.throws(
  () => broker.claimFor(revokedRequester, { ...input, approval_request_id: request.id }),
  expectCode('forbidden'),
);
assert.equal(broker.list(requester).find((item) => item.id === request.id).status, 'APPROVED');
assert.throws(
  () =>
    broker.claimFor(requester, { ...input, account_ref: 'other', approval_request_id: request.id }),
  expectCode('approval_mismatch'),
);
const claim = broker.claimFor(requester, { ...input, approval_request_id: request.id });
assert.equal(claim.grants.length, 2);
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: request.id }),
  expectCode('approval_mismatch'),
);
broker.markFailed(claim.id);
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: request.id }),
  expectCode('invalid_state'),
);
assert.throws(() => broker.rollbackSucceeded(request.id), expectCode('approval_mismatch'));

const failedRetryable = broker.create(requester, input);
broker.decide(approver('admin-a'), failedRetryable.id, 'approve');
broker.decide(approver('admin-b'), failedRetryable.id, 'approve');
broker.claimFor(requester, { ...input, approval_request_id: failedRetryable.id });
broker.markFailed(failedRetryable.id);
broker.rollbackFailed(failedRetryable.id);
broker.releaseClaim(failedRetryable.id);
assert.equal(broker.list(requester).find((item) => item.id === failedRetryable.id).status, 'APPROVED');
broker.rollbackFailed(null);
assert.throws(() => broker.rollbackFailed(failedRetryable.id), expectCode('approval_mismatch'));

const successful = broker.create(requester, input);
broker.decide(approver('admin-a'), successful.id, 'approve');
broker.decide(approver('admin-b'), successful.id, 'approve');
broker.claimFor(requester, { ...input, approval_request_id: successful.id });
broker.markSucceeded(successful.id);
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: successful.id }),
  expectCode('invalid_state'),
);

const retryable = broker.create(requester, input);
broker.decide(approver('admin-a'), retryable.id, 'approve');
broker.decide(approver('admin-b'), retryable.id, 'approve');
broker.claimFor(requester, { ...input, approval_request_id: retryable.id });
broker.releaseClaim(retryable.id);
assert.equal(broker.list(requester).find((item) => item.id === retryable.id).status, 'APPROVED');
const retryClaim = broker.claimFor(requester, { ...input, approval_request_id: retryable.id });
broker.markSucceeded(retryClaim.id);
broker.rollbackSucceeded(retryClaim.id);
broker.releaseClaim(retryClaim.id);
assert.equal(broker.list(requester).find((item) => item.id === retryable.id).status, 'APPROVED');
const finalRetryClaim = broker.claimFor(requester, { ...input, approval_request_id: retryable.id });
broker.markSucceeded(finalRetryClaim.id);
broker.rollbackSucceeded(null);
broker.releaseClaim(null);
assert.throws(() => broker.releaseClaim(finalRetryClaim.id), expectCode('approval_mismatch'));

const taskBound = broker.create(requester, input);
broker.decide(approver('admin-a'), taskBound.id, 'approve');
broker.decide(approver('admin-b'), taskBound.id, 'approve');
broker.cancelForTask(taskBound.id);
broker.cancelForTask(taskBound.id);
assert.equal(broker.list(requester).find((item) => item.id === taskBound.id).status, 'CANCELLED');
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: taskBound.id }),
  expectCode('invalid_state'),
);
broker.cancelForTask(null);
assert.throws(() => broker.cancelForTask(retryClaim.id), expectCode('approval_mismatch'));

const executingAcrossExpiry = broker.create(requester, input);
broker.decide(approver('admin-a'), executingAcrossExpiry.id, 'approve');
broker.decide(approver('admin-b'), executingAcrossExpiry.id, 'approve');
broker.claimFor(requester, { ...input, approval_request_id: executingAcrossExpiry.id });
now += 5 * 60_000 + 1;
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: executingAcrossExpiry.id }),
  expectCode('approval_mismatch'),
  'a replay cannot expire an approval already bound to an execution',
);
broker.markSucceeded(executingAcrossExpiry.id);
assert.equal(
  broker.list(requester).find((item) => item.id === executingAcrossExpiry.id).status,
  'SUCCEEDED',
);

const rejected = broker.create(requester, input);
assert.equal(broker.decide(approver('admin-a'), rejected.id, 'reject').status, 'DENIED');
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: rejected.id }),
  expectCode('invalid_state'),
);

const expiring = broker.create(requester, input);
now += 5 * 60_000 + 1;
assert.throws(
  () => broker.decide(approver('admin-a'), expiring.id, 'approve'),
  expectCode('approval_expired'),
);

let expiryCommitMode = 'pass';
const expiryCommits = [];
const expiryCommitBroker = new ApprovalBroker({
  now: () => now,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
  onExpire: (approval, identity) => {
    expiryCommits.push({ approval: structuredClone(approval), identity: identity?.name || null });
    if (expiryCommitMode === 'fail') throw new Error('expiry persistence unavailable');
    if (expiryCommitMode === 'async') return Promise.resolve();
    if (expiryCommitMode === 'indeterminate') {
      throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
    }
    return undefined;
  },
});
const expiryCommitted = expiryCommitBroker.create(requester, input);
now += 5 * 60_000 + 1;
assert.throws(
  () => expiryCommitBroker.claimFor(requester, { ...input, approval_request_id: expiryCommitted.id }),
  expectCode('approval_expired'),
);
assert.equal(expiryCommits.length, 1);
assert.equal(expiryCommits[0].approval.status, 'EXPIRED');
assert.equal(expiryCommits[0].identity, requester.name);
assert.equal(
  expiryCommitBroker.list(requester).find((item) => item.id === expiryCommitted.id).status,
  'EXPIRED',
  'a committed expiry remains terminal',
);

const expiryRollback = expiryCommitBroker.create(requester, input);
now += 5 * 60_000 + 1;
expiryCommitMode = 'fail';
assert.throws(
  () => expiryCommitBroker.decide(approver('admin-expiry-rollback'), expiryRollback.id, 'approve'),
  /expiry persistence unavailable/,
);
expiryCommitMode = 'pass';
assert.equal(
  expiryCommitBroker.list(requester).find((item) => item.id === expiryRollback.id).status,
  'REQUESTED',
  'a failed expiry commit restores the approval state for a safe retry',
);
assert.throws(
  () => expiryCommitBroker.decide(approver('admin-expiry-rollback'), expiryRollback.id, 'approve'),
  expectCode('approval_expired'),
);

const expiryIndeterminate = expiryCommitBroker.create(requester, input);
now += 5 * 60_000 + 1;
expiryCommitMode = 'indeterminate';
assert.throws(
  () => expiryCommitBroker.claimFor(requester, { ...input, approval_request_id: expiryIndeterminate.id }),
  expectCode('state_commit_indeterminate'),
);
expiryCommitMode = 'pass';
assert.equal(
  expiryCommitBroker.list(requester).find((item) => item.id === expiryIndeterminate.id).status,
  'EXPIRED',
  'an indeterminate expiry commit retains fail-closed in-memory state',
);

const expiryAsync = expiryCommitBroker.create(requester, input);
now += 5 * 60_000 + 1;
expiryCommitMode = 'async';
assert.throws(
  () => expiryCommitBroker.claimFor(requester, { ...input, approval_request_id: expiryAsync.id }),
  expectCode('checkpoint_invalid'),
);
expiryCommitMode = 'pass';
assert.equal(
  expiryCommitBroker.list(requester).find((item) => item.id === expiryAsync.id).status,
  'REQUESTED',
  'an async expiry handler is rejected and rolled back',
);
assert.throws(
  () => new ApprovalBroker({ onExpire: null }),
  expectCode('checkpoint_invalid'),
);

const cancelled = broker.create(requester, input);
assert.throws(
  () =>
    broker.cancel({ name: 'outsider', context: { client: { role: 'developer' } } }, cancelled.id),
  expectCode('forbidden'),
);
assert.throws(() => broker.cancel(revokedRequester, cancelled.id), expectCode('forbidden'));
assert.equal(broker.list(requester).find((item) => item.id === cancelled.id).status, 'REQUESTED');
assert.equal(broker.cancel(requester, cancelled.id).status, 'CANCELLED');
assert.throws(
  () =>
    broker.cancel(
      { name: 'outsider-terminal', context: { client: { role: 'developer' } } },
      cancelled.id,
    ),
  expectCode('forbidden'),
  'an unauthorized identity cannot use cancellation to probe terminal state',
);
assert.throws(
  () =>
    broker.cancel(
      { name: 'admin-terminal', context: { via: 'api_key', client: { role: 'admin' } } },
      cancelled.id,
    ),
  expectCode('step_up_required'),
  'an admin without WebAuthn cannot use cancellation to probe terminal state',
);
assert.throws(
  () => broker.claimFor(requester, { ...input, approval_request_id: cancelled.id }),
  expectCode('invalid_state'),
);
const adminCancelled = broker.create(requester, input);
assert.throws(
  () =>
    broker.cancel(
      { name: 'admin-c', context: { via: 'api_key', client: { role: 'admin' } } },
      adminCancelled.id,
    ),
  expectCode('step_up_required'),
);
assert.equal(broker.cancel(approver('admin-c'), adminCancelled.id).status, 'CANCELLED');

const cancellationRollback = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.cancelAndAudit(requester, cancellationRollback.id, () => {
      throw new Error('audit unavailable');
    }),
  /audit unavailable/,
);
assert.equal(
  atomicBroker.list(requester).find((item) => item.id === cancellationRollback.id).status,
  'REQUESTED',
  'a failed cancellation audit restores the active request',
);
assert.equal(atomicBroker.cancel(requester, cancellationRollback.id).status, 'CANCELLED');
const indeterminateCancellation = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.cancelAndAudit(requester, indeterminateCancellation.id, () => {
      throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
    }),
  expectCode('state_commit_indeterminate'),
);
assert.equal(
  atomicBroker.list(requester).find((item) => item.id === indeterminateCancellation.id).status,
  'CANCELLED',
  'an indeterminate durable commit must retain the matching in-memory cancellation',
);
const auditedCancellation = atomicBroker.create(requester, input);
let cancellationAuditCommitted = false;
assert.equal(
  atomicBroker.cancelAndAudit(requester, auditedCancellation.id, () => {
    cancellationAuditCommitted = true;
  }).status,
  'CANCELLED',
);
assert.equal(cancellationAuditCommitted, true);
const missingAudit = atomicBroker.create(requester, input);
assert.throws(
  () => atomicBroker.cancelAndAudit(requester, missingAudit.id),
  expectCode('audit_unavailable'),
);
assert.equal(atomicBroker.cancel(requester, missingAudit.id).status, 'CANCELLED');
const cancellationRollbackFailure = atomicBroker.create(requester, input);
assert.throws(
  () =>
    atomicBroker.cancelAndAudit(requester, cancellationRollbackFailure.id, () => {
      atomicBroker.records.delete(cancellationRollbackFailure.id);
      throw new Error('audit unavailable');
    }),
  expectCode('audit_rollback_failed'),
);

const capped = new ApprovalBroker({ maxRecords: 1, getPolicy: () => policy });
capped.create(requester, input);
assert.throws(() => capped.create(requester, input), expectCode('capacity'));
assert.equal(broker.claimFor(requester, input), null);
const invalidPolicy = new ApprovalBroker({
  getPolicy: () => ({ ...policy, required_approvals: 11 }),
});
assert.throws(() => invalidPolicy.create(requester, input), expectCode('invalid_policy'));
const invalidRolePolicy = new ApprovalBroker({
  getPolicy: () => ({ ...policy, approval_roles: [] }),
});
assert.throws(() => invalidRolePolicy.create(requester, input), expectCode('invalid_policy'));

const restartNow = 1_920_000_000_000;
const beforeRestart = new ApprovalBroker({
  now: () => restartNow,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
});
const executingBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.decide(approver('restart-admin-a'), executingBeforeRestart.id, 'approve');
beforeRestart.decide(approver('restart-admin-b'), executingBeforeRestart.id, 'approve');
beforeRestart.claimFor(requester, { ...input, approval_request_id: executingBeforeRestart.id });
const deniedBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.decide(approver('restart-admin-c'), deniedBeforeRestart.id, 'reject');
const requestedBeforeRestart = beforeRestart.create(requester, input);
const approvedBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.decide(approver('restart-admin-d'), approvedBeforeRestart.id, 'approve');
beforeRestart.decide(approver('restart-admin-e'), approvedBeforeRestart.id, 'approve');
const cancelledBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.cancel(requester, cancelledBeforeRestart.id);
const succeededBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.decide(approver('restart-admin-f'), succeededBeforeRestart.id, 'approve');
beforeRestart.decide(approver('restart-admin-g'), succeededBeforeRestart.id, 'approve');
beforeRestart.claimFor(requester, { ...input, approval_request_id: succeededBeforeRestart.id });
beforeRestart.markSucceeded(succeededBeforeRestart.id);
const failedBeforeRestart = beforeRestart.create(requester, input);
beforeRestart.decide(approver('restart-admin-h'), failedBeforeRestart.id, 'approve');
beforeRestart.decide(approver('restart-admin-i'), failedBeforeRestart.id, 'approve');
beforeRestart.claimFor(requester, { ...input, approval_request_id: failedBeforeRestart.id });
beforeRestart.markFailed(failedBeforeRestart.id);
let expiryNow = restartNow;
const expiryBroker = new ApprovalBroker({
  now: () => expiryNow,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
});
const expiredBeforeRestart = expiryBroker.create(requester, input);
expiryNow += 5 * 60_000 + 1;
assert.throws(
  () => expiryBroker.getActive(expiredBeforeRestart.id),
  expectCode('approval_expired'),
);
const durableState = beforeRestart.exportState();
durableState.records.push(...expiryBroker.exportState().records);
assert.equal(durableState.version, 1);
assert.equal(durableState.records.length, 8);

const afterRestart = new ApprovalBroker({ now: () => restartNow });
afterRestart.restoreState(durableState);
assert.throws(
  () =>
    afterRestart.claimFor(requester, { ...input, approval_request_id: executingBeforeRestart.id }),
  expectCode('approval_mismatch'),
  'an in-flight approval must remain claimed after restart',
);
afterRestart.markSucceeded(executingBeforeRestart.id);
assert.equal(
  afterRestart.list(requester).find((item) => item.id === executingBeforeRestart.id).status,
  'SUCCEEDED',
);
assert.throws(
  () => afterRestart.claimFor(requester, { ...input, approval_request_id: deniedBeforeRestart.id }),
  expectCode('invalid_state'),
  'a denied approval tombstone must survive restart',
);
assert.equal(
  afterRestart.list(requester).find((item) => item.id === requestedBeforeRestart.id).status,
  'REQUESTED',
);
assert.equal(
  afterRestart.list(requester).find((item) => item.id === approvedBeforeRestart.id).status,
  'APPROVED',
);
for (const [approval, status] of [
  [cancelledBeforeRestart, 'CANCELLED'],
  [succeededBeforeRestart, 'SUCCEEDED'],
  [failedBeforeRestart, 'FAILED'],
  [expiredBeforeRestart, 'EXPIRED'],
]) {
  assert.equal(
    afterRestart.list(requester).find((item) => item.id === approval.id).status,
    status,
    `${status} approval state must survive restart`,
  );
}

const restoreGuard = new ApprovalBroker({
  now: () => restartNow,
  getPolicy: (provider, operationId) =>
    provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
});
const guardApproval = restoreGuard.create(requester, input);
const validRecord = durableState.records[0];
for (const corrupt of [
  null,
  { version: 2, records: [] },
  { version: 1, records: 'not-an-array' },
  { version: 1, records: [null] },
  { version: 1, records: [[validRecord]] },
  { version: 1, records: [{ ...validRecord, unexpected: true }] },
  { version: 1, records: [{ ...validRecord, id: 'not-a-uuid' }] },
  { version: 1, records: [{ ...validRecord, requester: '' }] },
  { version: 1, records: [{ ...validRecord, provider: 'invalid provider' }] },
  { version: 1, records: [{ ...validRecord, resourceRef: '../billing' }] },
  { version: 1, records: [{ ...validRecord, requestHash: 'not-a-digest' }] },
  { version: 1, records: [{ ...validRecord, requiredApprovals: 0 }] },
  { version: 1, records: [{ ...validRecord, approvalRoles: [] }] },
  { version: 1, records: [{ ...validRecord, approvalRoles: ['admin', 'admin'] }] },
  { version: 1, records: [{ ...validRecord, status: 'UNKNOWN' }] },
  { version: 1, records: [validRecord, validRecord] },
  { version: 1, records: [{ ...validRecord, status: 'REQUESTED' }] },
  { version: 1, records: [{ ...validRecord, approvers: [] }] },
  { version: 1, records: [{ ...validRecord, createdAt: 'not-a-timestamp' }] },
  {
    version: 1,
    records: [{ ...validRecord, expiresAt: new Date(restartNow + 1_000).toISOString() }],
  },
  { version: 1, records: [{ ...validRecord, approvers: 'not-an-array' }] },
  { version: 1, records: [{ ...validRecord, approvers: [null] }] },
  {
    version: 1,
    records: [
      {
        ...validRecord,
        approvers: [{ ...validRecord.approvers[0], unexpected: true }],
      },
    ],
  },
  {
    version: 1,
    records: [
      {
        ...validRecord,
        approvers: [{ name: validRecord.requester, approvedAt: validRecord.createdAt }],
      },
    ],
  },
  {
    version: 1,
    records: [
      {
        ...validRecord,
        approvers: [{ name: 'early-approver', approvedAt: new Date(restartNow - 1).toISOString() }],
      },
    ],
  },
  {
    version: 1,
    records: [
      {
        ...validRecord,
        approvers: [validRecord.approvers[0], validRecord.approvers[0]],
      },
    ],
  },
  { ...durableState, unexpected: true },
]) {
  assert.throws(() => restoreGuard.restoreState(corrupt), expectCode('state_corrupt'));
}
assert.equal(
  restoreGuard.cancel(requester, guardApproval.id).status,
  'CANCELLED',
  'a rejected restore must not replace the last valid in-memory state',
);
assert.throws(
  () => new ApprovalBroker({ maxRecords: 0 }).restoreState({ version: 1, records: [validRecord] }),
  expectCode('state_corrupt'),
);

console.log(
  'v2 approvals: WebAuthn step-up, separation of duties, binding, expiry and one-time use passed',
);
