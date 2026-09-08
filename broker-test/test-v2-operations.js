import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  OperationBroker,
  V2Error,
  canonicalDeviceMessage,
  canonicalJson,
} from '../broker/lib/operations-v2.js';

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
assert.equal(broker.listDevices('owner-1').length, 1);
assert.equal(broker.listDevices('another-owner').length, 0);

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

const submitted = broker.submitOtp(device.id, operation.otp_task_id, body);
assert.equal(submitted.status, 'received');
assert.equal(JSON.stringify(submitted).includes(body.code), false);

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
const claim = broker.claimBrowserOtp(browserIdentity, {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 1, frame_id: 0, document_id: 'doc-1',
});
assert.equal(claim.code, browserBody.code);
assert.equal(JSON.stringify(broker.getOperation({ name: 'owner-1' }, browserOperation.id)).includes(browserBody.code), false);
assert.throws(
  () => broker.claimBrowserOtp(browserIdentity, {
    provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 1, frame_id: 0, document_id: 'doc-1',
  }),
  (error) => error instanceof V2Error && error.code === 'not_found',
);
const browserFinished = broker.finishBrowserOtp(browserIdentity, { receipt: claim.receipt, completed: true });
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
assert.equal(restored.listDevices('owner-2')[0].id, durableDevice.id);

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
assert.equal(failing.listDevices('owner-3').length, 0);

console.log('v2 operations: all tests passed');
