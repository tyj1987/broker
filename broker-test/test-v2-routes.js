import assert from 'node:assert/strict';
import { createV2Routes } from '../broker/routes/v2.js';
import { requireTrustedBrowserMutation } from '../broker/lib/browser-request.js';
import { V2Error } from '../broker/lib/operations-v2.js';

let identity = null;
let body = {};
let response = null;
let auditFailure = false;
let auditFailureAction = null;
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
    rollbackEnrollment(owner, enrollmentId) {
      calls.push(['enroll-rollback', owner, enrollmentId]);
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
    submitOtp(deviceId, taskId, input) {
      calls.push(['otp-submit', deviceId, taskId, input]);
      return { id: taskId, operation_id: 'operation-id', status: 'received' };
    },
    submitOtpAndAudit(deviceId, taskId, input, commitAudit) {
      const result = this.submitOtp(deviceId, taskId, input);
      commitAudit(result);
      return result;
    },
    async createOperation(subject, input) {
      calls.push(['operation', subject.name, input, subject.context.approvalGrants || []]);
      return { id: 'operation-id', provider: input.provider, status: 'waiting' };
    },
    rollbackOperationCreation(subject, id) {
      calls.push(['operation-rollback', subject.name, id]);
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
    claimBrowserOtpAndAudit(subject, input, commitAudit) {
      const result = this.claimBrowserOtp(subject, input);
      commitAudit({ provider: result.provider, operation_id: 'operation-id' });
      return result;
    },
    finishBrowserOtp(subject, input) {
      calls.push(['finish', subject.name, input]);
      return { id: 'operation-id', status: input.completed ? 'completed' : 'failed' };
    },
    finishBrowserOtpAndAudit(subject, input, commitAudit) {
      const result = this.finishBrowserOtp(subject, input);
      commitAudit({ operation_id: result.id, status: result.status });
      return result;
    },
    claimBrowserOperation(deviceId) {
      calls.push(['worker-claim', deviceId]);
      return { id: '00000000-0000-4000-8000-000000000002', operation: { id: 'operation-id' } };
    },
    claimBrowserOperationAndAudit(deviceId, commitAudit) {
      const result = this.claimBrowserOperation(deviceId);
      commitAudit(result);
      return result;
    },
    claimBrowserOperationOtp(deviceId, leaseId, receipt) {
      calls.push(['worker-otp', deviceId, leaseId, receipt]);
      return { code: '123456', expires_at: new Date().toISOString() };
    },
    claimBrowserOperationOtpAndAudit(deviceId, leaseId, receipt, commitAudit) {
      const result = this.claimBrowserOperationOtp(deviceId, leaseId, receipt);
      commitAudit({ expires_at: result.expires_at });
      return result;
    },
    completeBrowserOperation(deviceId, leaseId, input) {
      calls.push(['worker-complete', deviceId, leaseId, input]);
      return { id: 'operation-id', status: input.status };
    },
    completeBrowserOperationAndAudit(deviceId, leaseId, input, commitAudit) {
      const result = this.completeBrowserOperation(deviceId, leaseId, input);
      commitAudit({ operation_id: result.id, status: result.status });
      return result;
    },
  },
  approvalBroker: {
    create(subject, input) {
      calls.push(['approval-create', subject.name, input]);
      return { id: 'approval-id', status: 'REQUESTED' };
    },
    rollbackCreation(subject, id) {
      calls.push(['approval-create-rollback', subject.name, id]);
    },
    list(subject) { return [{ id: 'approval-id', requester: subject.name }]; },
    decide(subject, id, decision) {
      calls.push(['approval-decision', subject.name, id, decision]);
      return { id, status: decision === 'approve' ? 'APPROVED' : 'DENIED' };
    },
    decideAndAudit(subject, id, decision, commitAudit) {
      const result = this.decide(subject, id, decision);
      commitAudit(result);
      return result;
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
    releaseClaim(id) { calls.push(['approval-released', id]); },
    cancel(subject, id) {
      calls.push(['approval-cancel', subject.name, id]);
      return { id, status: 'CANCELLED' };
    },
    cancelAndAudit(subject, id, commitAudit) {
      const result = this.cancel(subject, id);
      commitAudit(result);
      return result;
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
  webAuthnService: {
    async beginAuthentication(input) {
      calls.push(['webauthn-begin', input]);
      return { flow_id: 'authentication-flow', options: {} };
    },
    async beginRegistration(subject, input) {
      calls.push(['webauthn-registration-begin', subject.name, input]);
      return { flow_id: 'registration-flow', options: {} };
    },
    async finishRegistration(subject, input) {
      calls.push(['webauthn-registration-finish', subject.name, input]);
      return { credential: { id: 'new-credential' }, strict_ready: true };
    },
    async finishRegistrationAndAudit(subject, input, commitAudit) {
      const result = await this.finishRegistration(subject, input);
      commitAudit({ credential_id: result.credential.id });
      return result;
    },
    rollbackFlowCreation(id, kind, clientName) {
      calls.push(['webauthn-flow-rollback', id, kind, clientName]);
    },
    async finishAuthentication(input) {
      calls.push(['webauthn-finish', input]);
      return {
        clientName: 'admin-a',
        client: { role: 'admin', security_profile: 'strict' },
        credential: { id: 'credential-id' },
        strictReady: true,
      };
    },
  },
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
    if ((auditFailure || event.action === auditFailureAction) && options?.mandatory) throw new Error('disk unavailable');
  },
  makeSession: (session) => {
    calls.push(['session-create', session]);
    return 'opaque-session-token';
  },
  sessionCookieHeader: (token) => {
    calls.push(['session-cookie', token]);
    return 'broker_session=opaque; Secure; HttpOnly; SameSite=Strict';
  },
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

body = { client: 'admin-a' };
assert.equal((await route('/api/v2/auth/webauthn/begin')).status, 200);
assert.ok(auditEvents.some((event) => event.action === 'webauthn_authentication_begin'));
auditFailureAction = 'webauthn_authentication_begin';
assert.equal((await route('/api/v2/auth/webauthn/begin')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.ok(calls.some((item) => item[0] === 'webauthn-flow-rollback'
  && item[1] === 'authentication-flow' && item[2] === 'authentication' && item[3] === 'admin-a'));

body = { flow_id: 'flow-id', response: { id: 'credential-id' } };
const authHeaders = {};
response = null;
await handler(request, { setHeader: (name, value) => { authHeaders[name] = value; } }, {
  method: 'POST', pathname: '/api/v2/auth/webauthn/finish',
});
assert.equal(response.status, 200);
assert.equal(response.value.strict_ready, true);
assert.equal(Object.hasOwn(response.value, 'token'), false);
assert.ok(authHeaders['Set-Cookie']?.includes('HttpOnly'));
assert.ok(auditEvents.some((event) => event.action === 'webauthn_authentication'
  && event.status === 'verified' && event.credential_id === 'credential-id'));
const sessionsBeforeAuthenticationAuditFailure = calls.filter((item) => item[0] === 'session-create').length;
auditFailureAction = 'webauthn_authentication';
response = null;
await handler(request, { setHeader: () => { throw new Error('cookie must not be created'); } }, {
  method: 'POST', pathname: '/api/v2/auth/webauthn/finish',
});
auditFailureAction = null;
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(
  calls.filter((item) => item[0] === 'session-create').length,
  sessionsBeforeAuthenticationAuditFailure,
  'mandatory authentication audit failure blocks session creation',
);

identity = { clientName: 'owner-1', via: 'session', client: { role: 'operator' } };
body = { label: 'hardware-key' };
assert.equal((await route('/api/v2/me/webauthn/registration/begin')).status, 200);
assert.ok(auditEvents.some((event) => event.action === 'webauthn_registration_begin_intent'));
auditFailureAction = 'webauthn_registration_begin';
assert.equal((await route('/api/v2/me/webauthn/registration/begin')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.ok(calls.some((item) => item[0] === 'webauthn-flow-rollback'
  && item[1] === 'registration-flow' && item[2] === 'registration' && item[3] === 'owner-1'));
body = { flow_id: 'registration-flow', response: { id: 'new-credential' } };
assert.equal((await route('/api/v2/me/webauthn/registration/finish')).status, 201);
assert.ok(auditEvents.some((event) => event.action === 'webauthn_registration_finish_intent'));
assert.ok(auditEvents.some((event) => event.action === 'webauthn_registration_verified'
  && event.credential_id === 'new-credential'));
const registrationsBeforeAuditFailure = calls.filter((item) => item[0] === 'webauthn-registration-finish').length;
auditFailureAction = 'webauthn_registration_verified';
assert.equal((await route('/api/v2/me/webauthn/registration/finish')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(
  calls.filter((item) => item[0] === 'webauthn-registration-finish').length,
  registrationsBeforeAuditFailure + 1,
);
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
assert.ok(auditEvents.some((event) => event.action === 'v2_task_create_intent' && event.status === 'attempt'));
assert.ok(auditEvents.some((event) => event.action === 'v2_task_run_intent' && event.status === 'attempt'));
assert.ok(auditEvents.some((event) => event.action === 'v2_task_cancel_intent' && event.status === 'attempt'));
assert.equal(
  auditEvents.some((event) => event.action?.startsWith('v2_task_')
    && event.action.endsWith('_intent') && event.status === 'authorized'),
  false,
  'pre-policy task intents must not be mislabeled as authorization decisions',
);
assert.ok(auditEvents.some((event) => event.action === 'v2_task_get' && event.task_state === 'SUCCEEDED'));
assert.ok(auditEvents.some((event) => event.action === 'v2_task_event_list' && event.count === 1));
const taskCreatesBeforeAuditFailure = calls.filter((item) => item[0] === 'task-create').length;
const taskRunsBeforeAuditFailure = calls.filter((item) => item[0] === 'task-run').length;
const taskCancelsBeforeAuditFailure = calls.filter((item) => item[0] === 'task-cancel').length;
auditFailure = true;
body = {};
assert.equal((await route(`/api/v2/tasks/${routeTaskId}/run`)).value.error, 'audit_unavailable');
assert.equal((await route(`/api/v2/tasks/${routeTaskId}/cancel`)).value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'task-run').length, taskRunsBeforeAuditFailure);
assert.equal(calls.filter((item) => item[0] === 'task-cancel').length, taskCancelsBeforeAuditFailure);
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
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_otp_claim_intent'));
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_otp_claim'
  && event.operation_id === 'operation-id'));
const extensionClaimsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'claim').length;
auditFailureAction = 'v2_browser_otp_claim';
assert.equal((await route('/api/v2/browser/otp/claim')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'claim').length, extensionClaimsBeforeResultAuditFailure + 1);

body = { receipt: 'receipt', completed: true };
assert.equal((await route('/api/v2/browser/otp/finish')).value.status, 'completed');
assert.ok(calls.some((item) => item[0] === 'finish'));
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_otp_finish_intent'));
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_otp_finish'
  && event.status === 'completed'));
const extensionFinishesBeforeResultAuditFailure = calls.filter((item) => item[0] === 'finish').length;
auditFailureAction = 'v2_browser_otp_finish';
assert.equal((await route('/api/v2/browser/otp/finish')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'finish').length, extensionFinishesBeforeResultAuditFailure + 1);

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

const approvalCreatesBeforeResultAuditFailure = calls.filter((item) => item[0] === 'approval-create').length;
auditFailureAction = 'v2_approval_create';
assert.equal((await route('/api/v2/approvals')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'approval-create').length, approvalCreatesBeforeResultAuditFailure + 1);
assert.ok(calls.some((item) => item[0] === 'approval-create-rollback'
  && item[1] === 'requester' && item[2] === 'approval-id'));

identity = { clientName: 'admin-a', via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } };
body = { decision: 'approve' };
request.headers.origin = 'https://broker.test';
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000001/decision')).value.status, 'APPROVED');
assert.ok(calls.some((item) => item[0] === 'browser-mutation'));
assert.ok(auditEvents.some((event) => event.action === 'v2_approval_decision' && event.status === 'APPROVED'));
const decisionsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'approval-decision').length;
auditFailureAction = 'v2_approval_decision';
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000004/decision')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'approval-decision').length, decisionsBeforeResultAuditFailure + 1);
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
assert.ok(auditEvents.some((event) => event.action === 'v2_approval_cancel' && event.status === 'CANCELLED'));
const cancellationsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'approval-cancel').length;
auditFailureAction = 'v2_approval_cancel';
assert.equal((await route('/api/v2/approvals/00000000-0000-4000-8000-000000000005/cancel')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'approval-cancel').length, cancellationsBeforeResultAuditFailure + 1);

identity = { clientName: 'requester', via: 'api_key', client: { role: 'developer' }, apiKey: { scopes: ['operations:execute'] } };
body = { provider: 'aliyun', operation_id: 'billing.read', account_ref: 'primary', environment: 'production', typed_parameters: { resource_ref: 'summary' }, approval_request_id: 'approval-id' };
assert.equal((await route('/api/v2/operations')).status, 202);
assert.equal(calls.find((item) => item[0] === 'operation')[3].length, 1);
assert.ok(calls.some((item) => item[0] === 'approval-succeeded'));
assert.ok(auditEvents.some((event) => event.action === 'v2_operation_create' && event.status === 'ok'));

const operationsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'operation').length;
auditFailureAction = 'v2_operation_create';
assert.equal((await route('/api/v2/operations')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'operation').length, operationsBeforeResultAuditFailure + 1);
assert.ok(calls.some((item) => item[0] === 'operation-rollback' && item[2] === 'operation-id'));
assert.ok(calls.some((item) => item[0] === 'approval-released' && item[1] === 'approval-id'));

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
assert.ok(auditEvents.some((event) => event.action === 'v2_device_enroll_begin' && event.status === 'ok'));
const enrollmentsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'enroll-begin').length;
auditFailureAction = 'v2_device_enroll_begin';
assert.equal((await route('/api/v2/devices/enroll/begin')).value.error, 'audit_unavailable');
auditFailureAction = null;
assert.equal(calls.filter((item) => item[0] === 'enroll-begin').length, enrollmentsBeforeResultAuditFailure + 1);
assert.ok(calls.some((item) => item[0] === 'enroll-rollback'
  && item[1] === 'admin-a' && item[2] === '00000000-0000-4000-8000-000000000099'));
assert.ok(calls.some((item) => item[0] === 'approval-released' && item[1] === 'device-enroll-approval'));

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
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_lease_claim'
  && event.operation_id === 'operation-id'));
const claimsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'worker-claim').length;
auditFailureAction = 'v2_browser_lease_claim';
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/claim` });
auditFailureAction = null;
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'worker-claim').length, claimsBeforeResultAuditFailure + 1);

response = null;
await handler({ method: 'GET', headers: signedHeaders }, {}, { method: 'GET', pathname: `/api/v2/devices/${deviceId}/otp-tasks` });
assert.equal(response.status, 200);
assert.ok(auditEvents.some((event) => event.action === 'v2_device_otp_task_list'
  && event.device_id === deviceId));

body = { code: '654321', sim_binding: 'sim-primary', challenge: 'route-challenge' };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, {
  method: 'POST', pathname: `/api/v2/devices/${deviceId}/otp-tasks/${leaseId}/submit`,
});
assert.equal(response.status, 202);
assert.ok(auditEvents.some((event) => event.action === 'v2_otp_received'
  && event.operation_id === 'operation-id'));
const submissionsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'otp-submit').length;
auditFailureAction = 'v2_otp_received';
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, {
  method: 'POST', pathname: `/api/v2/devices/${deviceId}/otp-tasks/${leaseId}/submit`,
});
auditFailureAction = null;
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'otp-submit').length, submissionsBeforeResultAuditFailure + 1);

body = { receipt: 'a'.repeat(43) };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/otp` });
assert.equal(response.status, 200);
assert.ok(calls.some((item) => item[0] === 'worker-otp' && item[3] === body.receipt));
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_lease_otp'
  && event.lease_id === leaseId));
const otpClaimsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'worker-otp').length;
auditFailureAction = 'v2_browser_lease_otp';
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/otp` });
auditFailureAction = null;
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'worker-otp').length, otpClaimsBeforeResultAuditFailure + 1);

body = { receipt: 'b'.repeat(43), status: 'completed', result: { count: 1 } };
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/complete` });
assert.equal(response.status, 200);
assert.ok(calls.some((item) => item[0] === 'worker-complete' && item[3].status === 'completed'));
assert.ok(auditEvents.some((event) => event.action === 'v2_browser_lease_complete'
  && event.status === 'completed'));
const completionsBeforeResultAuditFailure = calls.filter((item) => item[0] === 'worker-complete').length;
auditFailureAction = 'v2_browser_lease_complete';
response = null;
await handler({ method: 'POST', headers: signedHeaders }, {}, { method: 'POST', pathname: `/api/v2/devices/${deviceId}/browser-leases/${leaseId}/complete` });
auditFailureAction = null;
assert.equal(response.value.error, 'audit_unavailable');
assert.equal(calls.filter((item) => item[0] === 'worker-complete').length, completionsBeforeResultAuditFailure + 1);

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
