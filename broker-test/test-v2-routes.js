import assert from 'node:assert/strict';
import { createV2Routes } from '../broker/routes/v2.js';
import { requireTrustedBrowserMutation } from '../broker/lib/browser-request.js';
import { V2Error } from '../broker/lib/operations-v2.js';

let identity = null;
let body = {};
let response = null;
let auditFailure = false;
const calls = [];
const auditEvents = [];
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
    listDeviceOtpTasks(deviceId) {
      calls.push(['device-otp-list', deviceId]);
      return [{ id: 'otp-task-id', status: 'waiting' }];
    },
    async createOperation(subject, input) {
      calls.push(['operation', subject.name, input, subject.context.approvalGrants || []]);
      return { id: 'operation-id', provider: input.provider, status: 'waiting' };
    },
    getOperation(subject, id) {
      calls.push(['operation-get', subject.name, subject.context.via, subject.context.authFactors || []]);
      if (subject.name !== 'owner-1'
        && !(subject.context.via === 'session'
          && subject.context.client?.role === 'admin'
          && subject.context.authFactors?.includes('webauthn'))) {
        throw new V2Error('forbidden', 'operation access denied', 403);
      }
      return { id, status: 'waiting' };
    },
    listDevices(subject) {
      calls.push(['device-list', subject.name, subject.context.via, subject.context.authFactors || []]);
      const crossOwner = subject.context.via === 'session'
        && subject.context.client?.role === 'admin'
        && subject.context.authFactors?.includes('webauthn');
      return [{ id: crossOwner ? 'all-devices' : `${subject.name}-device` }];
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
      return { id: 'approval-id', status: 'REQUESTED' };
    },
    list(subject) { return [{ id: 'approval-id', requester: subject.name }]; },
    decide(subject, id, decision) {
      calls.push(['approval-decision', subject.name, id, decision]);
      return { id, status: decision === 'approve' ? 'APPROVED' : 'DENIED' };
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
    markSucceeded(id) { calls.push(['approval-succeeded', id]); },
    markFailed(id) { calls.push(['approval-failed', id]); },
    cancel(subject, id) {
      calls.push(['approval-cancel', subject.name, id]);
      return { id, status: 'CANCELLED' };
    },
  },
  taskBroker: {
    listTools(subject) {
      calls.push(['tool-list', subject.name]);
      return [{ name: 'github.repository.read', version: '1.0.0' }];
    },
    async create(subject, input) {
      calls.push(['task-create', subject.name, input]);
      return { id: '00000000-0000-4000-8000-000000000010', state: 'READY', risk_level: 'LOW' };
    },
    async run(subject, id) {
      calls.push(['task-run', subject.name, id]);
      return { id, state: 'SUCCEEDED', result: { ok: true } };
    },
    cancel(subject, id) {
      calls.push(['task-cancel', subject.name, id]);
      return { id, state: 'CANCELLED' };
    },
    get(subject, id) { return { id, owner: subject.name, state: 'SUCCEEDED' }; },
    eventsFor(_subject, id) { return [{ sequence: 1, task_id: id, state: 'REQUESTED' }]; },
  },
  webAuthnService: {},
  toolRegistry: {
    listFor(subject) {
      calls.push(['tool-list', subject.name]);
      return [{ name: 'github.repository.read', version: '1.0.0' }];
    },
  },
  getIdentity: () => identity,
  readBody: async () => body,
  send: (_res, status, value) => { response = { status, value }; },
  audit: (event, options) => {
    auditEvents.push(event);
    if (auditFailure && options?.mandatory) throw new Error('disk unavailable');
  },
  makeSession: () => '',
  sessionCookieHeader: () => '',
  authorizeApprovalRequest: async (operation) => {
    calls.push(['approval-authorize', operation.identity.name, operation.provider]);
    return operation.provider === 'denied' ? { allow: false, reason: 'service_denied' } : { allow: true };
  },
  consumeRateLimit: () => true,
  requireBrowserMutation: (req, ctx) => {
    calls.push(['browser-mutation', req.headers.origin, ctx.via]);
    requireTrustedBrowserMutation(req, ctx, 'https://broker.test');
  },
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
assert.equal((await getRoute('/api/v2/tools')).value.tools[0].name, 'github.repository.read');
assert.ok(calls.some((item) => item[0] === 'tool-list'));
assert.equal((await getRoute('/api/v2/operations/00000000-0000-4000-8000-000000000011')).status, 200);
assert.equal((await getRoute('/api/v2/devices')).value.devices[0].id, 'owner-1-device');
assert.ok(auditEvents.some((event) => event.action === 'v2_operation_get' && event.operation_id));
assert.ok(auditEvents.some((event) => event.action === 'v2_device_list' && event.count === 1));

identity = { clientName: 'admin-key', via: 'api_key', client: { role: 'admin' } };
assert.equal((await getRoute('/api/v2/operations/00000000-0000-4000-8000-000000000011')).value.error, 'forbidden');
assert.equal((await getRoute('/api/v2/devices')).value.error, 'identity_denied');
assert.ok(auditEvents.some((event) => event.action === 'v2_request'
  && event.reason === 'forbidden' && event.actor === 'admin-key'));

identity = { clientName: 'admin-session', via: 'session', authFactors: [], client: { role: 'admin' } };
assert.equal((await getRoute('/api/v2/operations/00000000-0000-4000-8000-000000000011')).value.error, 'forbidden');
assert.equal((await getRoute('/api/v2/devices')).value.devices[0].id, 'admin-session-device');

identity = { clientName: 'admin-session', via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } };
assert.equal((await getRoute('/api/v2/operations/00000000-0000-4000-8000-000000000011')).status, 200);
assert.equal((await getRoute('/api/v2/devices')).value.devices[0].id, 'all-devices');

identity = { clientName: 'owner-1', via: 'session', client: { role: 'operator' } };
body = {
  tool: 'broker.tools.inspect', tool_version: '1.0.0', account_ref: 'control-plane',
  environment: 'production', parameters: { resource_ref: 'tool-registry' }, idempotency_key: 'route-task-000001',
};
const taskCreated = await route('/api/v2/tasks');
assert.equal(taskCreated.status, 202);
const routeTaskId = taskCreated.value.id;
body = {};
assert.equal((await route(`/api/v2/tasks/${routeTaskId}/run`)).value.state, 'SUCCEEDED');
assert.equal((await getRoute(`/api/v2/tasks/${routeTaskId}`)).value.state, 'SUCCEEDED');
assert.equal((await getRoute(`/api/v2/tasks/${routeTaskId}/events`)).value.events.length, 1);
assert.equal((await route(`/api/v2/tasks/${routeTaskId}/cancel`)).value.state, 'CANCELLED');
assert.ok(calls.some((item) => item[0] === 'task-run'));
assert.ok(auditEvents.some((event) => event.action === 'v2_task_get' && event.task_state === 'SUCCEEDED'));
assert.ok(auditEvents.some((event) => event.action === 'v2_task_event_list' && event.count === 1));
const taskCreatesBeforeAuditFailure = calls.filter((item) => item[0] === 'task-create').length;
auditFailure = true;
body = {
  tool: 'broker.tools.inspect', tool_version: '1.0.0', account_ref: 'control-plane',
  environment: 'production', parameters: { resource_ref: 'tool-registry' }, idempotency_key: 'route-task-audit01',
};
assert.equal((await route('/api/v2/tasks')).value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'task-create').length, taskCreatesBeforeAuditFailure);
auditFailure = false;
body = { provider: 'aliyun' };
assert.equal((await route('/api/v2/browser/otp/claim')).status, 403);

identity = { clientName: 'owner-1', via: 'api_key', client: { role: 'operator' }, apiKey: { scopes: [] } };
assert.equal((await route('/api/v2/browser/otp/claim')).value.error, 'scope_denied');

identity.apiKey.scopes = ['browser:otp:fill'];
assert.equal((await route('/api/v2/browser/otp/claim')).status, 200);
assert.ok(calls.some((item) => item[0] === 'claim'));

body = { receipt: 'receipt', completed: true };
assert.equal((await route('/api/v2/browser/otp/finish')).value.status, 'completed');
assert.ok(calls.some((item) => item[0] === 'finish'));

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' }, apiKey: { scopes: ['operations:execute'] } };
body = { provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', typed_parameters: { resource_ref: 'summary' } };
assert.equal((await route('/api/v2/approvals')).status, 201);
assert.ok(calls.some((item) => item[0] === 'approval-authorize'));
assert.equal((await getRoute('/api/v2/approvals')).value.approvals.length, 1);
assert.ok(auditEvents.some((event) => event.action === 'v2_approval_list' && event.count === 1));

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
request.headers.origin = 'https://broker.test';
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000001/decision')).value.status, 'APPROVED');
assert.ok(calls.some((item) => item[0] === 'browser-mutation'));
const decisionsBeforeDenials = calls.filter((item) => item[0] === 'approval-decision').length;
request.headers.origin = 'https://attacker.test';
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000002/decision')).value.error, 'origin_denied');
request.headers.origin = 'https://broker.test';
body = { decision: 'approve', ignored: true };
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000002/decision')).value.error, 'invalid_request');
assert.equal(calls.filter((item) => item[0] === 'approval-decision').length, decisionsBeforeDenials);
delete request.headers.origin;

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' } };
body = {};
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000003/cancel')).value.status, 'CANCELLED');
assert.ok(calls.some((item) => item[0] === 'approval-cancel'));

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' }, apiKey: { scopes: ['operations:execute'] } };
body = { provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', typed_parameters: { resource_ref: 'summary' }, approval_request_id: 'approval-id' };
assert.equal((await route('/api/v2/operations')).status, 202);
assert.equal(calls.find((item) => item[0] === 'operation')[3].length, 1);
assert.ok(calls.some((item) => item[0] === 'approval-succeeded'));

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

response = null;
await handler({ method: 'GET', headers: signedHeaders }, {}, { method: 'GET', pathname: `/api/v2/devices/${deviceId}/otp-tasks` });
assert.equal(response.status, 200);
assert.ok(auditEvents.some((event) => event.action === 'v2_device_otp_task_list'
  && event.device_id === deviceId));

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
  operationBroker: {}, approvalBroker: {}, taskBroker: {}, webAuthnService: {}, toolRegistry: {}, getIdentity: () => identity,
  readBody: async () => ({}), send: (_res, status, value) => { response = { status, value }; },
  audit: () => {}, makeSession: () => '', sessionCookieHeader: () => '',
  authorizeApprovalRequest: async () => ({ allow: true }), consumeRateLimit: () => false,
  requireBrowserMutation: () => {},
});
response = null;
await limitedHandler(request, {}, { method: 'POST', pathname: '/api/v2/operations' });
assert.equal(response.status, 429);
assert.equal(response.value.error, 'rate_limited');

console.log('v2 routes: browser bridge and approval orchestration checks passed');
