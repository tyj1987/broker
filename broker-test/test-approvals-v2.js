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
  getPolicy: (provider, operationId) => provider === 'aliyun' && operationId === 'billing.read' ? policy : null,
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
  context: { ...requester.context, apiKey: { ...requester.context.apiKey, allowed_operations: [] } },
};
const approver = (name, role = 'admin') => ({
  name,
  context: { via: 'session', authFactors: ['webauthn'], client: { role } },
});
const input = {
  provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production',
  typed_parameters: { resource_ref: 'billing-summary' },
};

assert.throws(() => broker.create(null, input), expectCode('unauthorized'));
assert.throws(() => broker.create(requester, { ...input, operation_id: 'unapproved' }), expectCode('approval_not_required'));
assert.throws(() => broker.create(requester, { ...input, account_ref: 'other' }), expectCode('forbidden'));
assert.throws(() => broker.create(requester, { ...input, typed_parameters: {} }), expectCode('invalid_request'));
assert.throws(() => broker.create(revokedRequester, input), expectCode('forbidden'));

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
  broker.list({ name: 'admin-session', context: { via: 'session', authFactors: [], client: { role: 'admin' } } }).length,
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
assert.equal(broker.list(narrowedApprover).length, 0, 'a bearer key narrows approval visibility on a session');
assert.throws(() => broker.decide(narrowedApprover, request.id, 'approve'), expectCode('forbidden'));
assert.throws(() => broker.decide({ name: 'admin-a', context: { via: 'mtls', client: { role: 'admin' } } }, request.id, 'approve'), expectCode('step_up_required'));
assert.throws(() => broker.decide(approver('requester'), request.id, 'approve'), expectCode('separation_of_duties'));
assert.throws(() => broker.decide(approver('developer-a', 'developer'), request.id, 'approve'), expectCode('forbidden'));
assert.throws(() => broker.decide(approver('admin-a'), request.id, 'invalid'), expectCode('invalid_request'));
assert.equal(broker.decide(approver('admin-a'), request.id, 'approve').status, 'REQUESTED');
assert.throws(() => broker.decide(approver('admin-a'), request.id, 'approve'), expectCode('duplicate_approval'));
assert.equal(broker.decide(approver('admin-b'), request.id, 'approve').status, 'APPROVED');
assert.throws(
  () => broker.decide(approver('developer-terminal', 'developer'), request.id, 'approve'),
  expectCode('forbidden'),
  'an unauthorized role cannot use a terminal approval as a state oracle',
);
assert.throws(
  () => broker.decide({ name: 'admin-unstepped', context: { via: 'session', authFactors: [], client: { role: 'admin' } } }, request.id, 'approve'),
  expectCode('step_up_required'),
  'a session without WebAuthn cannot use a terminal approval as a state oracle',
);
assert.throws(() => broker.decide(approver('admin-c'), request.id, 'approve'), expectCode('invalid_state'));

assert.equal(broker.list(revokedRequester).length, 0, 'revoked API key cannot list its former approvals');
assert.throws(
  () => broker.claimFor(revokedRequester, { ...input, approval_request_id: request.id }),
  expectCode('forbidden'),
);
assert.equal(broker.list(requester).find((item) => item.id === request.id).status, 'APPROVED');
assert.throws(() => broker.claimFor(requester, { ...input, account_ref: 'other', approval_request_id: request.id }), expectCode('approval_mismatch'));
const claim = broker.claimFor(requester, { ...input, approval_request_id: request.id });
assert.equal(claim.grants.length, 2);
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: request.id }), expectCode('approval_mismatch'));
broker.markFailed(claim.id);
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: request.id }), expectCode('invalid_state'));

const successful = broker.create(requester, input);
broker.decide(approver('admin-a'), successful.id, 'approve');
broker.decide(approver('admin-b'), successful.id, 'approve');
broker.claimFor(requester, { ...input, approval_request_id: successful.id });
broker.markSucceeded(successful.id);
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: successful.id }), expectCode('invalid_state'));

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
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: rejected.id }), expectCode('invalid_state'));

const expiring = broker.create(requester, input);
now += 5 * 60_000 + 1;
assert.throws(() => broker.decide(approver('admin-a'), expiring.id, 'approve'), expectCode('approval_expired'));

const cancelled = broker.create(requester, input);
assert.throws(() => broker.cancel({ name: 'outsider', context: { client: { role: 'developer' } } }, cancelled.id), expectCode('forbidden'));
assert.throws(() => broker.cancel(revokedRequester, cancelled.id), expectCode('forbidden'));
assert.equal(broker.list(requester).find((item) => item.id === cancelled.id).status, 'REQUESTED');
assert.equal(broker.cancel(requester, cancelled.id).status, 'CANCELLED');
assert.throws(
  () => broker.cancel({ name: 'outsider-terminal', context: { client: { role: 'developer' } } }, cancelled.id),
  expectCode('forbidden'),
  'an unauthorized identity cannot use cancellation to probe terminal state',
);
assert.throws(
  () => broker.cancel({ name: 'admin-terminal', context: { via: 'api_key', client: { role: 'admin' } } }, cancelled.id),
  expectCode('step_up_required'),
  'an admin without WebAuthn cannot use cancellation to probe terminal state',
);
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: cancelled.id }), expectCode('invalid_state'));
const adminCancelled = broker.create(requester, input);
assert.throws(() => broker.cancel({ name: 'admin-c', context: { via: 'api_key', client: { role: 'admin' } } }, adminCancelled.id), expectCode('step_up_required'));
assert.equal(broker.cancel(approver('admin-c'), adminCancelled.id).status, 'CANCELLED');

const capped = new ApprovalBroker({ maxRecords: 1, getPolicy: () => policy });
capped.create(requester, input);
assert.throws(() => capped.create(requester, input), expectCode('capacity'));
assert.equal(broker.claimFor(requester, input), null);
const invalidPolicy = new ApprovalBroker({ getPolicy: () => ({ ...policy, required_approvals: 11 }) });
assert.throws(() => invalidPolicy.create(requester, input), expectCode('invalid_policy'));

console.log('v2 approvals: WebAuthn step-up, separation of duties, binding, expiry and one-time use passed');
