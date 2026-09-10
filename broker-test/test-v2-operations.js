import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  OperationBroker,
  V2Error,
  canonicalDeviceMessage,
  canonicalJson,
} from '../broker/lib/operations-v2.js';

const indeterminateCheckpoint = () => {
  throw new V2Error('state_commit_indeterminate', 'state requires reconciliation', 503);
};

let now = 1_800_000_000_000;
const broker = new OperationBroker({
  now: () => now,
  authorize: ({ provider, operationId }) => ({
    allow: provider === 'aliyun' && ['console.login', 'browser.otp.fill'].includes(operationId),
    otpRequired: true,
    ttlMs: 180_000,
    otp: {
      deviceId: currentDeviceId,
      simBinding: 'sim-primary',
      templateGroup: 'aliyun-login',
      senderAllowlist: ['95555'],
      recipientRef: 'account-phone',
      challenge: 'login-challenge',
    },
  }),
});

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const unpublishedEnrollment = broker.beginEnrollment('owner-1', {
  label: 'unpublished-device', platform: 'android', capabilities: ['otp.receive'],
});
assert.throws(
  () => broker.rollbackEnrollment('other-owner', unpublishedEnrollment.enrollment_id),
  (error) => error instanceof V2Error && error.code === 'forbidden',
);
broker.rollbackEnrollment('owner-1', unpublishedEnrollment.enrollment_id);
assert.throws(
  () => broker.rollbackEnrollment('owner-1', unpublishedEnrollment.enrollment_id),
  (error) => error instanceof V2Error && error.code === 'not_found',
);
const enrollment = broker.beginEnrollment('owner-1', {
  label: 'xiaomi-12s-ultra',
  platform: 'android',
  capabilities: ['otp.receive', 'approval'],
});
const enrollmentMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${enrollment.enrollment_id}\n${enrollment.challenge}`,
);
// A mobile device finishes pairing without a browser session. Ownership must
// remain bound to the authenticated principal that created the challenge.
const device = await broker.completeEnrollment(null, {
  enrollment_id: enrollment.enrollment_id,
  public_key_pem: publicKeyPem,
  signature: sign(null, enrollmentMessage, privateKey).toString('base64url'),
});
const currentDeviceId = device.id;
const browserIdentity = {
  name: 'owner-1',
  context: { apiKey: {
    allowed_services: ['aliyun'], allowed_operations: ['aliyun:browser.otp.fill'],
    allowed_accounts: ['primary'], allowed_environments: ['production'],
    allowed_resources: ['account.aliyun.com'],
  } },
};

assert.equal(device.state, 'active');
assert.equal(Object.hasOwn(device, 'owner'), false);
assert.equal(broker.listDevices({ name: 'owner-1' }).length, 1);
assert.equal(broker.listDevices({ name: 'another-owner' }).length, 0);
assert.equal(broker.listDevices({
  name: 'admin-key',
  context: { via: 'api_key', client: { role: 'admin' } },
}).length, 0);
assert.equal(broker.listDevices({
  name: 'owner-1',
  context: { via: 'api_key', client: { role: 'operator' } },
}).length, 0);
assert.equal(broker.listDevices({
  name: 'admin-session',
  context: { via: 'session', authFactors: [], client: { role: 'admin' } },
}).length, 0);
assert.equal(broker.listDevices({
  name: 'admin-session',
  context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin' } },
}).length, 1);
assert.equal(broker.listDevices({
  name: 'admin-session',
  context: { via: 'session', authFactors: ['webauthn'], client: { role: 'admin' }, apiKey: {} },
}).length, 0, 'a bearer delegation narrows interactive device inventory access');

await assert.rejects(
  broker.createOperation({ name: 'owner-1' }, {
    provider: 'unknown',
    operation_id: 'console.login',
    account_ref: 'primary',
    environment: 'production',
    typed_parameters: {},
  }),
  (error) => error instanceof V2Error && error.code === 'forbidden',
);

const rollbackOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun',
  operation_id: 'console.login',
  account_ref: 'primary',
  environment: 'production',
  typed_parameters: { requested_action: 'rollback-test' },
});
assert.throws(
  () => broker.rollbackOperationCreation({ name: 'another-owner' }, rollbackOperation.id),
  (error) => error instanceof V2Error && error.code === 'forbidden',
);
broker.rollbackOperationCreation({ name: 'owner-1' }, rollbackOperation.id);
assert.throws(
  () => broker.getOperation({ name: 'owner-1' }, rollbackOperation.id),
  (error) => error instanceof V2Error && error.code === 'not_found',
);
assert.equal(broker.listDeviceOtpTasks(device.id).length, 0, 'rollback removes the unpublished OTP task and lock');
assert.throws(
  () => broker.rollbackOperationCreation({ name: 'owner-1' }, rollbackOperation.id),
  (error) => error instanceof V2Error && error.code === 'not_found',
);

const operation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun',
  operation_id: 'console.login',
  account_ref: 'primary',
  environment: 'production',
  typed_parameters: { requested_action: 'read-only-console' },
});
assert.equal(operation.status, 'waiting');
assert.ok(operation.otp_task_id);
assert.equal(JSON.stringify(operation).includes('login-challenge'), false);

const pendingTask = broker.listDeviceOtpTasks(device.id).find((task) => task.id === operation.otp_task_id);
assert.ok(pendingTask?.challenge);
assert.notEqual(pendingTask.challenge, 'login-challenge');

await assert.rejects(
  broker.createOperation({ name: 'owner-1' }, {
    provider: 'aliyun',
    operation_id: 'console.login',
    account_ref: 'secondary',
    environment: 'production',
    typed_parameters: {},
  }),
  (error) => error instanceof V2Error && error.code === 'otp_conflict',
);

const body = { code: '482913', sim_binding: 'sim-primary', challenge: pendingTask.challenge };
const signed = {
  timestamp: now,
  nonce: 'request-1',
  method: 'POST',
  path: `/api/v2/devices/${device.id}/otp-tasks/${operation.otp_task_id}/submit`,
  body: canonicalJson(body),
};
signed.signature = sign(null, Buffer.from(canonicalDeviceMessage({ ...signed, deviceId: device.id })), privateKey)
  .toString('base64url');
broker.verifyDeviceRequest(device.id, signed);
assert.throws(
  () => broker.verifyDeviceRequest(device.id, signed),
  (error) => error instanceof V2Error && error.code === 'replay',
);

const beforeIndeterminateSubmit = broker.exportState();
assert.throws(
  () => broker.submitOtpAndAudit(device.id, operation.otp_task_id, body, indeterminateCheckpoint),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
assert.equal(broker.getOperation({ name: 'owner-1' }, operation.id).status, 'received');
broker.restoreState(beforeIndeterminateSubmit);

assert.throws(
  () => broker.submitOtpAndAudit(device.id, operation.otp_task_id, body, () => {
    throw new Error('audit unavailable');
  }),
  /audit unavailable/,
);
assert.equal(
  broker.listDeviceOtpTasks(device.id).find((task) => task.id === operation.otp_task_id).status,
  'waiting',
  'an OTP result audit failure restores the waiting task',
);
assert.equal(broker.getOperation({ name: 'owner-1' }, operation.id).status, 'waiting');
let otpAuditCommitted = false;
const submitted = broker.submitOtpAndAudit(device.id, operation.otp_task_id, body, () => {
  otpAuditCommitted = true;
});
assert.equal(otpAuditCommitted, true);
assert.equal(submitted.status, 'received');
assert.equal(JSON.stringify(submitted).includes(body.code), false);
assert.throws(
  () => broker.rollbackOperationCreation({ name: 'owner-1' }, operation.id),
  (error) => error instanceof V2Error && error.code === 'invalid_state',
  'a published or progressing operation cannot use the creation rollback path',
);

let consumedCode = null;
const result = await broker.consumeOtp(operation.otp_task_id, async (code) => {
  consumedCode = code;
  return { status: 'authenticated' };
});
assert.equal(consumedCode, body.code);
assert.deepEqual(result, { status: 'authenticated' });
assert.equal(broker.getOperation({ name: 'owner-1' }, operation.id).status, 'completed');
await assert.rejects(
  broker.consumeOtp(operation.otp_task_id, async () => ({})),
  (error) => error instanceof V2Error && error.code === 'invalid_state',
);

const revokedInFlightOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun',
  operation_id: 'console.login',
  account_ref: 'secondary',
  environment: 'production',
  typed_parameters: {},
});
const revokedInFlightTask = broker.listDeviceOtpTasks(device.id)
  .find((task) => task.id === revokedInFlightOperation.otp_task_id);
broker.submitOtp(device.id, revokedInFlightTask.id, {
  code: '628405', sim_binding: 'sim-primary', challenge: revokedInFlightTask.challenge,
});
let releaseConsumer;
let markConsumerStarted;
const consumerStarted = new Promise((resolve) => { markConsumerStarted = resolve; });
const consumerGate = new Promise((resolve) => { releaseConsumer = resolve; });
const inFlightConsumption = broker.consumeOtp(revokedInFlightTask.id, async () => {
  markConsumerStarted();
  await consumerGate;
  return { status: 'must-not-commit' };
});
await consumerStarted;
await broker.setDeviceState('owner-1', device.id, 'suspended');
releaseConsumer();
await assert.rejects(
  inFlightConsumption,
  (error) => error instanceof V2Error && error.code === 'operation_revoked',
);
assert.equal(
  broker.getOperation({ name: 'owner-1' }, revokedInFlightOperation.id).status,
  'revoked',
);
await broker.setDeviceState('owner-1', device.id, 'active');

const browserOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun',
  operation_id: 'browser.otp.fill',
  account_ref: 'primary',
  environment: 'production',
  typed_parameters: { resource_ref: 'account.aliyun.com' },
});
const browserTask = broker.listDeviceOtpTasks(device.id).find((task) => task.id === browserOperation.otp_task_id);
const browserBody = { code: '193742', sim_binding: 'sim-primary', challenge: browserTask.challenge };
const browserSigned = {
  timestamp: now,
  nonce: 'request-2',
  method: 'POST',
  path: `/api/v2/devices/${device.id}/otp-tasks/${browserTask.id}/submit`,
  body: canonicalJson(browserBody),
};
browserSigned.signature = sign(
  null,
  Buffer.from(canonicalDeviceMessage({ ...browserSigned, deviceId: device.id })),
  privateKey,
).toString('base64url');
broker.verifyDeviceRequest(device.id, browserSigned);
broker.submitOtp(device.id, browserTask.id, browserBody);
assert.throws(
  () => broker.claimBrowserOtp({ name: 'another-owner' }, {
    provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 1, frame_id: 0, document_id: 'doc-1',
  }),
  (error) => error instanceof V2Error && error.code === 'not_found',
);
const browserClaimInput = {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 1, frame_id: 0, document_id: 'doc-1',
};
const beforeIndeterminateBrowserClaim = broker.exportState();
assert.throws(
  () => broker.claimBrowserOtpAndAudit(browserIdentity, browserClaimInput, indeterminateCheckpoint),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
assert.equal(broker.getOperation({ name: 'owner-1' }, browserOperation.id).status, 'consuming');
broker.restoreState(beforeIndeterminateBrowserClaim);
assert.throws(
  () => broker.claimBrowserOtpAndAudit(browserIdentity, browserClaimInput, () => {
    throw new Error('audit unavailable');
  }),
  /audit unavailable/,
);
assert.equal(broker.getOperation({ name: 'owner-1' }, browserOperation.id).status, 'received');
let extensionClaimAudited = false;
const claim = broker.claimBrowserOtpAndAudit(browserIdentity, browserClaimInput, () => {
  extensionClaimAudited = true;
});
assert.equal(extensionClaimAudited, true);
assert.equal(claim.code, browserBody.code);
assert.equal(JSON.stringify(broker.getOperation({ name: 'owner-1' }, browserOperation.id)).includes(browserBody.code), false);
assert.throws(
  () => broker.finishBrowserOtp(browserIdentity, { receipt: claim.receipt, completed: true, ignored: true }),
  (error) => error instanceof V2Error && error.code === 'invalid_request',
);
const beforeIndeterminateBrowserFinish = broker.exportState();
assert.throws(
  () => broker.finishBrowserOtpAndAudit(
    browserIdentity,
    { receipt: claim.receipt, completed: true },
    indeterminateCheckpoint,
  ),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
assert.equal(broker.getOperation({ name: 'owner-1' }, browserOperation.id).status, 'completed');
broker.restoreState(beforeIndeterminateBrowserFinish);
assert.throws(
  () => broker.claimBrowserOtp(browserIdentity, {
    provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 1, frame_id: 0, document_id: 'doc-1',
  }),
  (error) => error instanceof V2Error && error.code === 'not_found',
);
assert.throws(
  () => broker.finishBrowserOtpAndAudit(
    browserIdentity,
    { receipt: claim.receipt, completed: true },
    () => { throw new Error('audit unavailable'); },
  ),
  /audit unavailable/,
);
assert.equal(broker.getOperation({ name: 'owner-1' }, browserOperation.id).status, 'consuming');
let extensionFinishAudited = false;
const browserFinished = broker.finishBrowserOtpAndAudit(
  browserIdentity,
  { receipt: claim.receipt, completed: true },
  () => { extensionFinishAudited = true; },
);
assert.equal(extensionFinishAudited, true);
assert.equal(browserFinished.status, 'completed');
assert.throws(
  () => broker.finishBrowserOtp(browserIdentity, { receipt: claim.receipt, completed: true }),
  (error) => error instanceof V2Error && error.code === 'invalid_claim',
);

const next = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun',
  operation_id: 'console.login',
  account_ref: 'secondary',
  environment: 'production',
  typed_parameters: {},
});
now += 181_000;
assert.equal(broker.getOperation({ name: 'owner-1' }, next.id).status, 'expired');

await broker.setDeviceState('owner-1', device.id, 'revoked');
await assert.rejects(
  broker.setDeviceState('owner-1', device.id, 'active'),
  (error) => error instanceof V2Error && error.code === 'invalid_state',
);

let persistedRecords = null;
const auditedEnrollmentBroker = new OperationBroker();
const auditedEnrollment = auditedEnrollmentBroker.beginEnrollment('owner-audited', {
  label: 'audited-device', platform: 'android', capabilities: ['otp.receive'],
});
const auditedEnrollmentMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${auditedEnrollment.enrollment_id}\n${auditedEnrollment.challenge}`,
);
const auditedEnrollmentInput = {
  enrollment_id: auditedEnrollment.enrollment_id,
  public_key_pem: publicKeyPem,
  signature: sign(null, auditedEnrollmentMessage, privateKey).toString('base64url'),
};
await assert.rejects(
  auditedEnrollmentBroker.completeEnrollmentAndAudit(null, auditedEnrollmentInput, () => {
    throw new Error('audit unavailable');
  }),
  /audit unavailable/,
);
assert.equal(auditedEnrollmentBroker.listDevices({ name: 'owner-audited' }).length, 0);
let deviceEnrollmentAudited = false;
const auditedDevice = await auditedEnrollmentBroker.completeEnrollmentAndAudit(
  null,
  auditedEnrollmentInput,
  () => { deviceEnrollmentAudited = true; },
);
assert.equal(deviceEnrollmentAudited, true);
assert.ok(auditedDevice.id);
assert.equal(auditedEnrollmentBroker.listDevices({ name: 'owner-audited' }).length, 1);

const durable = new OperationBroker({ persistDevices: async (records) => { persistedRecords = structuredClone(records); } });
const durableEnrollment = durable.beginEnrollment('owner-2', {
  label: 'android-backup', platform: 'android', capabilities: ['otp.receive'],
});
const durableMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${durableEnrollment.enrollment_id}\n${durableEnrollment.challenge}`,
);
const durableDevice = await durable.completeEnrollment(null, {
  enrollment_id: durableEnrollment.enrollment_id,
  public_key_pem: publicKeyPem,
  signature: sign(null, durableMessage, privateKey).toString('base64url'),
});
assert.equal(persistedRecords.length, 1);
const restored = new OperationBroker();
restored.hydrateDevices(persistedRecords);
assert.equal(restored.listDevices({ name: 'owner-2' })[0].id, durableDevice.id);
assert.throws(
  () => restored.commitDeviceRegistry({}),
  (error) => error instanceof V2Error && error.code === 'invalid_device_registry',
);
const restoredSnapshot = restored.deviceRecords();
assert.throws(
  () => restored.hydrateDevices([...persistedRecords, { id: 'invalid-device' }]),
  (error) => error instanceof V2Error && error.code === 'invalid_request',
);
assert.deepEqual(restored.deviceRecords(), restoredSnapshot, 'failed hydration preserves the active device registry');

const failing = new OperationBroker({ persistDevices: async () => { throw new Error('disk unavailable'); } });
const failingEnrollment = failing.beginEnrollment('owner-3', {
  label: 'android-fail', platform: 'android', capabilities: [],
});
const failingMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${failingEnrollment.enrollment_id}\n${failingEnrollment.challenge}`,
);
await assert.rejects(
  failing.completeEnrollment(null, {
    enrollment_id: failingEnrollment.enrollment_id,
    public_key_pem: publicKeyPem,
    signature: sign(null, failingMessage, privateKey).toString('base64url'),
  }),
  (error) => error instanceof V2Error && error.code === 'persistence_failed',
);
assert.equal(failing.listDevices({ name: 'owner-3' }).length, 0);

const workerBroker = new OperationBroker({
  now: () => now,
  authorize: () => ({ allow: true, executionMode: 'browser', ttlMs: 120_000 }),
});
const workerEnrollment = workerBroker.beginEnrollment('worker-service', {
  label: 'browser-worker-staging', platform: 'browser-worker',
  capabilities: ['browser.execute:aliyun:account.summary:primary:staging'],
});
const workerMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${workerEnrollment.enrollment_id}\n${workerEnrollment.challenge}`,
);
const workerDevice = await workerBroker.completeEnrollment(null, {
  enrollment_id: workerEnrollment.enrollment_id,
  public_key_pem: publicKeyPem,
  signature: sign(null, workerMessage, privateKey).toString('base64url'),
});
const workerOperation = await workerBroker.createOperation({ name: 'owner-4' }, {
  provider: 'aliyun', operation_id: 'account.summary', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'summary' },
});
assert.equal(workerOperation.execution_mode, 'browser');
const beforeIndeterminateLeaseClaim = workerBroker.exportState();
assert.throws(
  () => workerBroker.claimBrowserOperationAndAudit(workerDevice.id, indeterminateCheckpoint),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
assert.equal(workerBroker.getOperation({ name: 'owner-4' }, workerOperation.id).status, 'consuming');
workerBroker.restoreState(beforeIndeterminateLeaseClaim);
assert.throws(
  () => workerBroker.claimBrowserOperationAndAudit(workerDevice.id, () => {
    throw new Error('audit unavailable');
  }),
  /audit unavailable/,
);
assert.equal(
  workerBroker.getOperation({ name: 'owner-4' }, workerOperation.id).status,
  'waiting',
  'a failed lease audit restores the unpublished operation',
);
let leaseAuditCommitted = false;
const lease = workerBroker.claimBrowserOperationAndAudit(workerDevice.id, () => {
  leaseAuditCommitted = true;
});
assert.equal(leaseAuditCommitted, true);
assert.equal(lease.operation.id, workerOperation.id);
assert.equal(lease.operation.provider, 'aliyun');
assert.equal(Object.hasOwn(lease.operation, 'owner'), false);
assert.equal(Object.hasOwn(lease.operation, 'credentials'), false);
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: { nested: { session_token: 'forbidden' } },
  }),
  (error) => error instanceof V2Error && error.code === 'unsafe_result',
);
const tooDeepResult = {};
let deepCursor = tooDeepResult;
for (let depth = 0; depth < 10; depth += 1) {
  deepCursor.next = {};
  deepCursor = deepCursor.next;
}
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: tooDeepResult,
  }),
  (error) => error instanceof V2Error && error.code === 'unsafe_result',
);
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: { unsupported: undefined },
  }),
  (error) => error instanceof V2Error && error.code === 'unsafe_result',
);
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, lease.id, {
    receipt: lease.receipt,
    status: 'completed',
    result: { status: `gh${'p_'}${'B'.repeat(24)}` },
  }),
  (error) => error instanceof V2Error && error.code === 'unsafe_result',
);
assert.throws(
  () => workerBroker.completeBrowserOperationAndAudit(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: { status: 'ok', records: 1 },
  }, () => {
    throw new Error('audit unavailable');
  }),
  /audit unavailable/,
);
assert.equal(
  workerBroker.getOperation({ name: 'owner-4' }, workerOperation.id).status,
  'consuming',
  'a failed completion audit retains the active lease for a safe report retry',
);
const beforeIndeterminateCompletion = workerBroker.exportState();
assert.throws(
  () => workerBroker.completeBrowserOperationAndAudit(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: { status: 'ok', records: 1 },
  }, indeterminateCheckpoint),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
assert.equal(workerBroker.getOperation({ name: 'owner-4' }, workerOperation.id).status, 'completed');
workerBroker.restoreState(beforeIndeterminateCompletion);
let completionAuditCommitted = false;
const workerCompleted = workerBroker.completeBrowserOperationAndAudit(workerDevice.id, lease.id, {
  receipt: lease.receipt, status: 'completed', result: { status: 'ok', records: 1 },
}, () => {
  completionAuditCommitted = true;
});
assert.equal(completionAuditCommitted, true);
assert.equal(workerCompleted.status, 'completed');
assert.deepEqual(workerCompleted.result, { status: 'ok', records: 1 });

let otpWorkerPhoneId = null;
const otpWorkerBroker = new OperationBroker({
  now: () => now,
  authorize: () => ({
    allow: true,
    executionMode: 'browser',
    ttlMs: 120_000,
    otpRequired: true,
    otp: {
      deviceId: otpWorkerPhoneId,
      simBinding: 'sim-worker',
      templateGroup: 'worker-login',
      senderAllowlist: ['CloudLogin'],
    },
  }),
});
const enrollWorkerDevice = async (label, platform, capabilities) => {
  const pending = otpWorkerBroker.beginEnrollment('owner-otp-worker', { label, platform, capabilities });
  const message = Buffer.from(
    `secret-broker-device-enrollment-v1\n${pending.enrollment_id}\n${pending.challenge}`,
  );
  return otpWorkerBroker.completeEnrollment(null, {
    enrollment_id: pending.enrollment_id,
    public_key_pem: publicKeyPem,
    signature: sign(null, message, privateKey).toString('base64url'),
  });
};
const otpWorkerPhone = await enrollWorkerDevice('otp-worker-phone', 'android', ['otp.receive']);
otpWorkerPhoneId = otpWorkerPhone.id;
const otpBrowserWorker = await enrollWorkerDevice(
  'otp-browser-worker',
  'browser-worker',
  ['browser.execute:aliyun:console.login:primary:staging'],
);
const otpWorkerOperation = await otpWorkerBroker.createOperation({ name: 'owner-otp-worker' }, {
  provider: 'aliyun', operation_id: 'console.login', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'console' },
});
const otpWorkerTask = otpWorkerBroker.listDeviceOtpTasks(otpWorkerPhone.id)[0];
const otpWorkerBody = { code: '927461', sim_binding: 'sim-worker', challenge: otpWorkerTask.challenge };
otpWorkerBroker.submitOtp(otpWorkerPhone.id, otpWorkerTask.id, otpWorkerBody);
const otpWorkerLease = otpWorkerBroker.claimBrowserOperation(otpBrowserWorker.id);
const beforeIndeterminateOtpRelease = otpWorkerBroker.exportState();
assert.throws(
  () => otpWorkerBroker.claimBrowserOperationOtpAndAudit(
    otpBrowserWorker.id,
    otpWorkerLease.id,
    otpWorkerLease.receipt,
    indeterminateCheckpoint,
  ),
  (error) => error instanceof V2Error && error.code === 'state_commit_indeterminate',
);
otpWorkerBroker.restoreState(beforeIndeterminateOtpRelease);
assert.throws(
  () => otpWorkerBroker.claimBrowserOperationOtpAndAudit(
    otpBrowserWorker.id,
    otpWorkerLease.id,
    otpWorkerLease.receipt,
    () => { throw new Error('audit unavailable'); },
  ),
  /audit unavailable/,
);
let otpReleaseAudited = false;
const otpRelease = otpWorkerBroker.claimBrowserOperationOtpAndAudit(
  otpBrowserWorker.id,
  otpWorkerLease.id,
  otpWorkerLease.receipt,
  () => { otpReleaseAudited = true; },
);
assert.equal(otpReleaseAudited, true);
assert.equal(otpRelease.code, otpWorkerBody.code, 'audit rollback retains the server-side OTP for retry');
assert.equal(otpWorkerLease.operation.id, otpWorkerOperation.id);
const operationReader = (overrides = {}) => ({
  name: 'owner-4',
  context: {
    via: 'api_key',
    apiKey: {
      scopes: ['operations:execute'],
      allowed_services: ['aliyun'],
      allowed_operations: ['aliyun:account.summary'],
      allowed_accounts: ['primary'],
      allowed_environments: ['staging'],
      allowed_resources: ['summary'],
      ...overrides,
    },
  },
});
assert.equal(workerBroker.getOperation(operationReader(), workerOperation.id).id, workerOperation.id);
assert.throws(
  () => workerBroker.getOperation({
    name: 'owner-4',
    context: {
      via: 'session', authFactors: ['webauthn'], client: { role: 'admin' },
      apiKey: operationReader({ allowed_resources: ['other'] }).context.apiKey,
    },
  }, workerOperation.id),
  (error) => error instanceof V2Error && error.code === 'forbidden',
  'a bearer key narrows a simultaneous interactive identity',
);
for (const revokedGrant of [
  { scopes: [] },
  { allowed_services: [] },
  { allowed_operations: [] },
  { allowed_accounts: ['other'] },
  { allowed_environments: ['production'] },
  { allowed_resources: ['other'] },
]) {
  assert.throws(
    () => workerBroker.getOperation(operationReader(revokedGrant), workerOperation.id),
    (error) => error instanceof V2Error && error.code === 'forbidden',
  );
}
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, lease.id, {
    receipt: lease.receipt, status: 'completed', result: {},
  }),
  (error) => error instanceof V2Error && error.code === 'invalid_lease',
);

await workerBroker.createOperation({ name: 'owner-4' }, {
  provider: 'aliyun', operation_id: 'account.summary', account_ref: 'primary', environment: 'production',
  typed_parameters: { resource_ref: 'summary' },
});
assert.throws(
  () => workerBroker.claimBrowserOperation(workerDevice.id),
  (error) => error instanceof V2Error && error.code === 'not_found',
  'staging worker capability cannot claim a production operation',
);

await workerBroker.createOperation({ name: 'owner-4' }, {
  provider: 'aliyun', operation_id: 'account.summary', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'summary' },
});
const expiringLease = workerBroker.claimBrowserOperation(workerDevice.id);
now += 61_000;
workerBroker.prune();
assert.equal(workerBroker.getOperation({ name: 'owner-4' }, expiringLease.operation.id).status, 'failed');
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, expiringLease.id, {
    receipt: expiringLease.receipt, status: 'completed', result: {},
  }),
  (error) => error instanceof V2Error && error.code === 'invalid_lease',
);

const revokedWorkerOperation = await workerBroker.createOperation({ name: 'owner-4' }, {
  provider: 'aliyun', operation_id: 'account.summary', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'summary' },
});
const revokedWorkerLease = workerBroker.claimBrowserOperation(workerDevice.id);
await workerBroker.setDeviceState('worker-service', workerDevice.id, 'suspended');
assert.equal(
  workerBroker.getOperation({ name: 'owner-4' }, revokedWorkerOperation.id).status,
  'revoked',
);
assert.throws(
  () => workerBroker.completeBrowserOperation(workerDevice.id, revokedWorkerLease.id, {
    receipt: revokedWorkerLease.receipt, status: 'completed', result: { status: 'must-not-commit' },
  }),
  (error) => error instanceof V2Error && error.code === 'device_denied',
);

const durableOperation = await otpWorkerBroker.createOperation({ name: 'owner-otp-worker' }, {
  provider: 'aliyun', operation_id: 'console.login', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'console' },
});
const durableTask = otpWorkerBroker.listDeviceOtpTasks(otpWorkerPhone.id)
  .find((task) => task.id === durableOperation.otp_task_id);
otpWorkerBroker.submitOtp(otpWorkerPhone.id, durableTask.id, {
  code: '804126', sim_binding: 'sim-worker', challenge: durableTask.challenge,
});
const durableLease = otpWorkerBroker.claimBrowserOperation(otpBrowserWorker.id);
otpWorkerBroker.claimBrowserOperationOtp(
  otpBrowserWorker.id,
  durableLease.id,
  durableLease.receipt,
);
const durableOperationState = otpWorkerBroker.exportState();
assert.equal(durableOperationState.version, 1);
assert.equal(
  JSON.stringify(durableOperationState).includes(durableLease.receipt),
  false,
  'raw browser lease receipts are never persisted',
);
const restoredOtpWorker = new OperationBroker({ now: () => now, authorize: () => ({ allow: true }) });
restoredOtpWorker.hydrateDevices(otpWorkerBroker.deviceRecords());
restoredOtpWorker.restoreState(durableOperationState);
assert.equal(
  restoredOtpWorker.getOperation({ name: 'owner-otp-worker' }, durableOperation.id).status,
  'consuming',
  'a receipt-bound browser lease survives restart',
);
assert.equal(
  restoredOtpWorker.completeBrowserOperation(otpBrowserWorker.id, durableLease.id, {
    receipt: durableLease.receipt,
    status: 'completed',
    result: { status: 'ok-after-restart' },
  }).status,
  'completed',
);
otpWorkerBroker.completeBrowserOperation(otpBrowserWorker.id, durableLease.id, {
  receipt: durableLease.receipt,
  status: 'completed',
  result: { status: 'released-after-snapshot' },
});

const nonceMessage = {
  timestamp: now,
  nonce: 'durable-replay-check',
  method: 'GET',
  path: `/api/v2/devices/${otpWorkerPhone.id}/otp-tasks`,
  body: '',
};
nonceMessage.signature = sign(
  null,
  Buffer.from(canonicalDeviceMessage({ ...nonceMessage, deviceId: otpWorkerPhone.id })),
  privateKey,
).toString('base64url');
otpWorkerBroker.verifyDeviceRequest(otpWorkerPhone.id, nonceMessage);
const replayState = otpWorkerBroker.exportState();
const replayRestored = new OperationBroker({ now: () => now });
replayRestored.hydrateDevices(otpWorkerBroker.deviceRecords());
replayRestored.restoreState(replayState);
assert.throws(
  () => replayRestored.verifyDeviceRequest(otpWorkerPhone.id, nonceMessage),
  (error) => error instanceof V2Error && error.code === 'replay',
  'device request replay tombstones survive restart',
);

const otpWorkerBrowserIdentity = {
  name: 'owner-otp-worker',
  context: { apiKey: {
    allowed_services: ['aliyun'], allowed_operations: ['aliyun:browser.otp.fill'],
    allowed_accounts: ['primary'], allowed_environments: ['staging'], allowed_resources: ['console'],
  } },
};
const durableClaimOperation = await otpWorkerBroker.createOperation({ name: 'owner-otp-worker' }, {
  provider: 'aliyun', operation_id: 'browser.otp.fill', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'console' },
});
const durableClaimTask = otpWorkerBroker.listDeviceOtpTasks(otpWorkerPhone.id)
  .find((task) => task.id === durableClaimOperation.otp_task_id);
otpWorkerBroker.submitOtp(otpWorkerPhone.id, durableClaimTask.id, {
  code: '316405', sim_binding: 'sim-worker', challenge: durableClaimTask.challenge,
});
const durableClaim = otpWorkerBroker.claimBrowserOtp(otpWorkerBrowserIdentity, {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com',
  tab_id: 9, frame_id: 0, document_id: 'durable-document',
});
const claimState = otpWorkerBroker.exportState();
assert.equal(JSON.stringify(claimState).includes(durableClaim.receipt), false, 'raw extension receipts are not persisted');
const claimRestored = new OperationBroker({ now: () => now });
claimRestored.hydrateDevices(otpWorkerBroker.deviceRecords());
claimRestored.restoreState(claimState);
assert.equal(
  claimRestored.finishBrowserOtp(otpWorkerBrowserIdentity, { receipt: durableClaim.receipt, completed: true }).status,
  'completed',
  'a receipt-bound browser extension claim survives restart',
);

const corruptState = structuredClone(replayState);
corruptState.operations[0].status = 'invented';
const beforeCorruptRestore = replayRestored.exportState();
assert.throws(
  () => replayRestored.restoreState(corruptState),
  (error) => error instanceof V2Error && error.code === 'state_corrupt',
);
assert.deepEqual(replayRestored.exportState(), beforeCorruptRestore, 'invalid state cannot partially replace live state');

let failoverDeviceId;
const failoverBroker = new OperationBroker({
  now: () => now,
  authorize: () => ({
    allow: true,
    otpRequired: true,
    otp: {
      deviceId: failoverDeviceId,
      simBinding: 'sim-failover',
      templateGroup: 'failover-login',
      senderAllowlist: ['CloudLogin'],
    },
  }),
});
failoverBroker.hydrateDevices(otpWorkerBroker.deviceRecords());
failoverDeviceId = otpWorkerPhone.id;
const failoverOperation = await failoverBroker.createOperation({ name: 'owner-otp-worker' }, {
  provider: 'aliyun', operation_id: 'console.login', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'console' },
});
const failoverTask = failoverBroker.listDeviceOtpTasks(failoverDeviceId)[0];
failoverBroker.submitOtp(failoverDeviceId, failoverTask.id, {
  code: '615204', sim_binding: 'sim-failover', challenge: failoverTask.challenge,
});
let releaseFailoverConsumer;
let failoverConsumerStarted;
const failoverStarted = new Promise((resolve) => { failoverConsumerStarted = resolve; });
const failoverGate = new Promise((resolve) => { releaseFailoverConsumer = resolve; });
const abandonedConsumption = failoverBroker.consumeOtp(failoverTask.id, async () => {
  failoverConsumerStarted();
  await failoverGate;
  return { status: 'late-result' };
});
await failoverStarted;
const inFlightState = failoverBroker.exportState();
const failoverRestored = new OperationBroker({ now: () => now });
failoverRestored.hydrateDevices(otpWorkerBroker.deviceRecords());
failoverRestored.restoreState(inFlightState);
assert.equal(
  failoverRestored.getOperation({ name: 'owner-otp-worker' }, failoverOperation.id).status,
  'failed',
  'an unleased in-flight side effect is failed closed after restart',
);
assert.equal(
  failoverRestored.getOperation({ name: 'owner-otp-worker' }, failoverOperation.id).error.code,
  'execution_state_indeterminate',
);
releaseFailoverConsumer();
await abandonedConsumption;

console.log('v2 operations: all tests passed');
