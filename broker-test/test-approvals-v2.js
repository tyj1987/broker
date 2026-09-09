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
const requester = { name: 'requester', context: { via: 'api_key', client: { role: 'developer' } } };
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

const request = broker.create(requester, input);
assert.equal(request.status, 'REQUESTED');
assert.equal(request.required_approvals, 2);
assert.equal(broker.list(requester).length, 1);
assert.throws(() => broker.decide({ name: 'admin-a', context: { via: 'mtls', client: { role: 'admin' } } }, request.id, 'approve'), expectCode('step_up_required'));
assert.throws(() => broker.decide(approver('requester'), request.id, 'approve'), expectCode('separation_of_duties'));
assert.throws(() => broker.decide(approver('developer-a', 'developer'), request.id, 'approve'), expectCode('forbidden'));
assert.throws(() => broker.decide(approver('admin-a'), request.id, 'invalid'), expectCode('invalid_request'));
assert.equal(broker.decide(approver('admin-a'), request.id, 'approve').status, 'REQUESTED');
assert.throws(() => broker.decide(approver('admin-a'), request.id, 'approve'), expectCode('duplicate_approval'));
assert.equal(broker.decide(approver('admin-b'), request.id, 'approve').status, 'APPROVED');
assert.throws(() => broker.decide(approver('admin-c'), request.id, 'approve'), expectCode('invalid_state'));

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

const rejected = broker.create(requester, input);
assert.equal(broker.decide(approver('admin-a'), rejected.id, 'reject').status, 'DENIED');
assert.throws(() => broker.claimFor(requester, { ...input, approval_request_id: rejected.id }), expectCode('invalid_state'));

const expiring = broker.create(requester, input);
now += 5 * 60_000 + 1;
assert.throws(() => broker.decide(approver('admin-a'), expiring.id, 'approve'), expectCode('approval_expired'));

const cancelled = broker.create(requester, input);
assert.throws(() => broker.cancel({ name: 'outsider', context: { client: { role: 'developer' } } }, cancelled.id), expectCode('forbidden'));
assert.equal(broker.cancel(requester, cancelled.id).status, 'CANCELLED');
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
