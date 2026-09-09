import assert from 'node:assert/strict';
import { createV2Routes } from '../broker/routes/v2.js';

let identity = null;
let body = {};
let response = null;
let auditFailure = false;
const calls = [];
const handler = createV2Routes({
  operationBroker: {
    verifyDeviceRequest(deviceId, signed) {
      calls.push(['device-verify', deviceId, signed]);
      return { id: deviceId, platform: 'browser-worker' };
    },
    beginEnrollment(owner, input) {
      calls.push(['enroll-begin', owner, input]);
      return { enrollment_id: '00000000-0000-4000-8000-000000000099' };
    },
    async setDeviceState(requester, deviceId, state, isAdmin) {
      calls.push(['device-state', requester, deviceId, state, isAdmin]);
      return { id: deviceId, state };
    },
    async suspendDevice(deviceId) {
      calls.push(['device-self-suspend', deviceId]);
      return { id: deviceId, state: 'suspended' };
    },
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
    claimBrowserOperation(deviceId) {
      calls.push(['worker-claim', deviceId]);
      return { id: '00000000-0000-4000-8000-000000000002', operation: { id: 'operation-id' } };
    },
    claimBrowserOperationOtp(deviceId, leaseId, receipt) {
      calls.push(['worker-otp', deviceId, leaseId, receipt]);
      return { code: '123456', expires_at: new Date().toISOString() };
    },
    completeBrowserOperation(deviceId, leaseId, input) {
      calls.push(['worker-complete', deviceId, leaseId, input]);
      return { id: 'operation-id', status: input.status };
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
      if (!input.approval_request_id) return null;
      const grants = input.approval_request_id === 'one-approval'
        ? [{ approved_by: 'admin-b' }]
        : input.provider === 'broker'
        ? [{ approved_by: 'admin-b' }, { approved_by: 'admin-c' }]
        : [{ approved_by: 'admin-a' }];
      return { id: input.approval_request_id, grants };
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
const patchRoute = async (pathname) => {
  response = null;
  await handler({ method: 'PATCH', headers: {} }, {}, { method: 'PATCH', pathname });
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

identity = {
  clientName: 'admin-a', via: 'session', authFactors: ['webauthn'],
  client: { role: 'admin', security_profile: 'strict' },
};
body = { label: 'isolated-worker', platform: 'browser-worker', capabilities: ['browser.execute:aliyun:billing.read:primary:production'] };
assert.equal((await route('/api/v2/devices/enroll/begin')).value.error, 'approval_required');
body.approval_request_id = 'one-approval';
assert.equal((await route('/api/v2/devices/enroll/begin')).value.error, 'approval_required');
assert.equal(calls.filter((item) => item[0] === 'enroll-begin').length, 0, 'one approval cannot mutate device enrollment');
body.approval_request_id = 'device-enroll-approval';
assert.equal((await route('/api/v2/devices/enroll/begin')).status, 201);
assert.ok(calls.some((item) => item[0] === 'enroll-begin'));

identity = { clientName: 'operator-a', via: 'session', authFactors: ['webauthn'], client: { role: 'operator', security_profile: 'strict' } };
assert.equal((await route('/api/v2/devices/enroll/begin')).value.error, 'step_up_required', 'non-admin cannot enroll browser workers');
identity = { clientName: 'admin-a', via: 'session', authFactors: [], client: { role: 'admin', security_profile: 'strict' } };
assert.equal((await route('/api/v2/devices/enroll/begin')).value.error, 'step_up_required', 'browser worker enrollment requires WebAuthn');

identity = {
  clientName: 'admin-a', via: 'session', authFactors: ['webauthn'],
  client: { role: 'admin', security_profile: 'strict' },
};
body = { state: 'revoked', approval_request_id: 'device-state-approval' };
assert.equal((await patchRoute('/api/v2/devices/00000000-0000-4000-8000-000000000001')).status, 200);
assert.ok(calls.some((item) => item[0] === 'device-state' && item[3] === 'revoked'));

const deviceId = '00000000-0000-4000-8000-000000000001';
const leaseId = '00000000-0000-4000-8000-000000000002';
const signedHeaders = {
  'x-broker-device-timestamp': '1234',
  'x-broker-device-nonce': 'route-nonce',
  'x-broker-device-signature': 'route-signature',
};
body = {};
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/suspend` });
assert.equal(response.status, 200);
assert.equal(response.value.state, 'suspended');
assert.ok(calls.some((item) => item[0] === 'device-self-suspend'));
const suspendVerify = calls.findLast((item) => item[0] === 'device-verify');
assert.equal(suspendVerify[2].body, '{}');

body = { state: 'active' };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/suspend` });
assert.equal(response.value.error, 'invalid_request');

auditFailure = true;
const suspensionsBeforeAuditFailure = calls.filter((item) => item[0] === 'device-self-suspend').length;
body = {};
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/suspend` });
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'device-self-suspend').length, suspensionsBeforeAuditFailure);
auditFailure = false;

body = {};
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/claim` });
assert.equal(response.status, 200);
const claimVerify = calls.findLast((item) => item[0] === 'device-verify');
assert.equal(claimVerify[2].body, '{}');
assert.equal(claimVerify[2].nonce, 'route-nonce');
assert.ok(calls.some((item) => item[0] === 'worker-claim'));

body = { receipt: 'a'.repeat(43) };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/otp` });
assert.equal(response.status, 200);
assert.ok(calls.some((item) => item[0] === 'worker-otp' && item[3] === body.receipt));

body = { receipt: 'b'.repeat(43), status: 'completed', result: { count: 1 } };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/complete` });
assert.equal(response.status, 200);
assert.ok(calls.some((item) => item[0] === 'worker-complete' && item[3].status === 'completed'));

auditFailure = true;
const claimsBeforeAuditFailure = calls.filter((item) => item[0] === 'worker-claim').length;
body = {};
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/claim` });
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'worker-claim').length, claimsBeforeAuditFailure, 'audit intent blocks lease mutation');
auditFailure = false;

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
