import assert from 'node:assert/strict';
import { createV2Routes } from '../broker/routes/v2.js';

let identity = null;
let body = {};
let response = null;
let auditFailure = false;
const calls = [];
const handler = createV2Routes({
  operationBroker: {
    async createOperation(subject, input) {
      calls.push(['operation', subject.name, input, subject.context.approvalGrants || []]);
      return { id: 'operation-id', provider: input.provider, status: 'waiting' };
    },
    claimBrowserOtp(subject, input) {
      calls.push(['claim', subject.name, input]);
      return { type: 'approved-otp', provider: input.provider };
    },
    finishBrowserOtp(subject, input) {
      calls.push(['finish', subject.name, input]);
      return { id: 'operation-id', status: input.completed ? 'completed' : 'failed' };
    },
  },
  approvalBroker: {
    create(subject, input) {
      calls.push(['approval-create', subject.name, input]);
      return { id: 'approval-id', status: 'pending' };
    },
    list(subject) { return [{ id: 'approval-id', requester: subject.name }]; },
    decide(subject, id, decision) {
      calls.push(['approval-decision', subject.name, id, decision]);
      return { id, status: decision === 'approve' ? 'approved' : 'rejected' };
    },
    claimFor(_subject, input) {
      return input.approval_request_id ? { id: input.approval_request_id, grants: [{ approved_by: 'admin-a' }] } : null;
    },
    consume(id) { calls.push(['approval-consume', id]); },
    release(id) { calls.push(['approval-release', id]); },
  },
  webAuthnService: {},
  getIdentity: () => identity,
  readBody: async () => body,
  send: (_res, status, value) => { response = { status, value }; },
  audit: (_event, options) => {
    if (auditFailure && options?.mandatory) throw new Error('disk unavailable');
  },
  makeSession: () => '',
  sessionCookieHeader: () => '',
  authorizeApprovalRequest: async (operation) => {
    calls.push(['approval-authorize', operation.identity.name, operation.provider]);
    return operation.provider === 'denied' ? { allow: false, reason: 'service_denied' } : { allow: true };
  },
  consumeRateLimit: () => true,
});

const request = { method: 'POST', headers: {} };
const route = async (pathname) => {
  response = null;
  await handler(request, {}, { method: 'POST', pathname });
  return response;
};
const getRoute = async (pathname) => {
  response = null;
  await handler({ method: 'GET', headers: {} }, {}, { method: 'GET', pathname });
  return response;
};

identity = { clientName: 'owner-1', via: 'session', client: { role: 'operator' } };
body = { provider: 'aliyun' };
assert.equal((await route('/api/v2/browser/otp/claim')).status, 403);

identity = { clientName: 'owner-1', via: 'api_key', client: { role: 'operator' }, apiKey: { scopes: [] } };
assert.equal((await route('/api/v2/browser/otp/claim')).value.error, 'scope_denied');

identity.apiKey.scopes = ['browser:otp:fill'];
assert.equal((await route('/api/v2/browser/otp/claim')).status, 200);
assert.equal(calls[0][0], 'claim');

body = { receipt: 'receipt', completed: true };
assert.equal((await route('/api/v2/browser/otp/finish')).value.status, 'completed');
assert.equal(calls[1][0], 'finish');

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' }, apiKey: { scopes: ['operations:execute'] } };
body = { provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', typed_parameters: { resource_ref: 'summary' } };
assert.equal((await route('/api/v2/approvals')).status, 201);
assert.ok(calls.some((item) => item[0] === 'approval-authorize'));
assert.equal((await getRoute('/api/v2/approvals')).value.approvals.length, 1);

body = { ...body, provider: 'denied' };
assert.equal((await route('/api/v2/approvals')).value.error, 'forbidden');
assert.equal(calls.filter((item) => item[0] === 'approval-create').length, 1);

body = { ...body, provider: 'aliyun' };
auditFailure = true;
assert.equal((await route('/api/v2/approvals')).value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'approval-create').length, 1, 'mutation is blocked before audit intent');
auditFailure = false;

identity = { clientName: 'admin-a', via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } };
body = { decision: 'approve' };
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000001/decision')).value.status, 'approved');

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' }, apiKey: { scopes: ['operations:execute'] } };
body = { provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', typed_parameters: { resource_ref: 'summary' }, approval_request_id: 'approval-id' };
assert.equal((await route('/api/v2/operations')).status, 202);
assert.equal(calls.find((item) => item[0] === 'operation')[3].length, 1);
assert.ok(calls.some((item) => item[0] === 'approval-consume'));

const limitedHandler = createV2Routes({
  operationBroker: {}, approvalBroker: {}, webAuthnService: {}, getIdentity: () => identity,
  readBody: async () => ({}), send: (_res, status, value) => { response = { status, value }; },
  audit: () => {}, makeSession: () => '', sessionCookieHeader: () => '',
  authorizeApprovalRequest: async () => ({ allow: true }), consumeRateLimit: () => false,
});
response = null;
await limitedHandler(request, {}, { method: 'POST', pathname: '/api/v2/operations' });
assert.equal(response.status, 429);
assert.equal(response.value.error, 'rate_limited');

console.log('v2 routes: browser bridge and approval orchestration checks passed');
