import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { OperationBroker, V2Error, canonicalDeviceMessage, canonicalJson } from '../broker/lib/operations-v2.js';

const expectCode = (code) => (error) => error instanceof V2Error && error.code === code;
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const p256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const p256PublicKeyPem = p256.publicKey.export({ type: 'spki', format: 'pem' });

async function enroll(broker, owner = 'owner-1', capabilities = ['otp.receive']) {
  const enrollment = broker.beginEnrollment(owner, { label: 'test-device', platform: 'android', capabilities });
  const message = Buffer.from(`secret-broker-device-enrollment-v1\n${enrollment.enrollment_id}\n${enrollment.challenge}`);
  return broker.completeEnrollment(null, {
    enrollment_id: enrollment.enrollment_id,
    public_key_pem: publicKeyPem,
    signature: sign(null, message, privateKey).toString('base64url'),
  });
}

assert.equal(canonicalJson(null), 'null');
assert.equal(canonicalJson([2, { b: 1, a: 0 }]), '[2,{"a":0,"b":1}]');
assert.match(canonicalDeviceMessage({
  deviceId: 'device', timestamp: 1, nonce: 'nonce', method: 'GET', path: '/test', body: null,
}), /secret-broker-device-request-v1/);

const empty = new OperationBroker();
assert.throws(() => empty.hydrateDevices({}), expectCode('invalid_device_registry'));
assert.throws(() => empty.hydrateDevices([{ id: 'device', owner: 'owner', label: 'label', platform: 'bad', state: 'active', public_key_pem: publicKeyPem }]), expectCode('invalid_device_registry'));
assert.throws(() => empty.hydrateDevices([{ id: 'device', owner: 'owner', label: 'label', platform: 'android', state: 'active', public_key_pem: 'bad' }]), expectCode('invalid_device_registry'));
assert.throws(() => empty.hydrateDevices([{ id: 'device', owner: 'owner', label: 'label', platform: 'android', state: 'active', public_key_pem: publicKeyPem, created_at: 'not-a-date' }]), expectCode('invalid_device_registry'));
assert.throws(() => empty.beginEnrollment('owner', { label: 'label', platform: 'desktop' }), expectCode('invalid_request'));
assert.throws(() => empty.beginEnrollment('owner', { label: 'label', platform: 'android', capabilities: ['BAD'] }), expectCode('invalid_request'));
await assert.rejects(empty.completeEnrollment(null, {}), expectCode('invalid_enrollment'));
const expiredEnrollment = empty.beginEnrollment('owner', { label: 'label', platform: 'android' });
await assert.rejects(empty.completeEnrollment('other', { enrollment_id: expiredEnrollment.enrollment_id }), expectCode('invalid_enrollment'));
await assert.rejects(empty.completeEnrollment(null, { enrollment_id: expiredEnrollment.enrollment_id }), expectCode('invalid_request'));
await assert.rejects(empty.completeEnrollment(null, {
  enrollment_id: expiredEnrollment.enrollment_id, public_key_pem: 'not a key', signature: 'bad',
}), expectCode('invalid_signature'));

let now = 1_900_000_000_000;
let currentDeviceId;
const policy = {
  now: () => now,
  authorize: ({ operationId }) => ({
    allow: operationId !== 'denied', ttlMs: 180_000,
    otpRequired: operationId !== 'no.otp',
    otp: {
      deviceId: currentDeviceId, simBinding: 'sim-1', templateGroup: 'login',
      senderAllowlist: ['10690000'], recipientRef: 'phone',
    },
  }),
};
const broker = new OperationBroker(policy);
const device = await enroll(broker);
currentDeviceId = device.id;
assert.equal(device.signature_algorithm, 'ed25519');

const p256Broker = new OperationBroker({ now: () => now });
const p256Enrollment = p256Broker.beginEnrollment('ios-owner', {
  label: 'secure-enclave-device', platform: 'ios', capabilities: [],
});
const p256EnrollmentMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${p256Enrollment.enrollment_id}\n${p256Enrollment.challenge}`,
);
const p256Device = await p256Broker.completeEnrollment(null, {
  enrollment_id: p256Enrollment.enrollment_id,
  signature_algorithm: 'p256-sha256',
  public_key_pem: p256PublicKeyPem,
  signature: sign('sha256', p256EnrollmentMessage, p256.privateKey).toString('base64url'),
});
assert.equal(p256Device.signature_algorithm, 'p256-sha256');
const p256Signed = {
  timestamp: now,
  nonce: 'p256-request-nonce',
  method: 'GET',
  path: `/api/v2/devices/${p256Device.id}/otp-tasks`,
  body: '',
};
const p256Message = canonicalDeviceMessage({ ...p256Signed, deviceId: p256Device.id });
p256Signed.signature = sign('sha256', Buffer.from(p256Message), p256.privateKey).toString('base64url');
assert.equal(p256Broker.verifyDeviceRequest(p256Device.id, p256Signed).id, p256Device.id);

const mismatchedEnrollment = p256Broker.beginEnrollment('ios-owner', {
  label: 'mismatched-device', platform: 'ios', capabilities: [],
});
const mismatchedMessage = Buffer.from(
  `secret-broker-device-enrollment-v1\n${mismatchedEnrollment.enrollment_id}\n${mismatchedEnrollment.challenge}`,
);
await assert.rejects(p256Broker.completeEnrollment(null, {
  enrollment_id: mismatchedEnrollment.enrollment_id,
  signature_algorithm: 'ed25519',
  public_key_pem: p256PublicKeyPem,
  signature: sign('sha256', mismatchedMessage, p256.privateKey).toString('base64url'),
}), expectCode('invalid_signature'));
const browserIdentity = {
  name: 'owner-1',
  context: { apiKey: {
    allowed_services: ['aliyun'], allowed_operations: ['aliyun:browser.otp.fill'],
    allowed_accounts: ['primary', 'secondary', 'expiring'], allowed_environments: ['production'],
    allowed_resources: ['account.aliyun.com'],
  } },
};

await assert.rejects(broker.setDeviceState('owner-1', device.id, 'bad'), expectCode('invalid_request'));
await assert.rejects(broker.setDeviceState('owner-1', 'missing', 'active'), expectCode('not_found'));
await assert.rejects(broker.setDeviceState('other', device.id, 'suspended'), expectCode('forbidden'));
await broker.setDeviceState('admin', device.id, 'active', true);

const selfSuspend = await broker.suspendDevice(device.id);
assert.equal(selfSuspend.state, 'suspended');
await assert.rejects(broker.suspendDevice(device.id), expectCode('device_denied'));
await broker.setDeviceState('admin', device.id, 'active', true);
const failingPersistence = new OperationBroker({
  now: () => now,
  persistDevices: async () => { throw new Error('storage unavailable'); },
});
failingPersistence.hydrateDevices(broker.deviceRecords());
await assert.rejects(failingPersistence.suspendDevice(device.id), expectCode('persistence_failed'));
assert.equal(failingPersistence.listDevices('owner-1')[0].state, 'active', 'failed suspension rolls back');

assert.throws(() => broker.verifyDeviceRequest('missing', {}), expectCode('device_denied'));
assert.throws(() => broker.verifyDeviceRequest(device.id, { timestamp: 'bad' }), expectCode('stale_request'));
assert.throws(() => broker.verifyDeviceRequest(device.id, {
  timestamp: now, nonce: 'nonce-invalid', method: 'GET', path: '/test', body: '', signature: 'bad',
}), expectCode('invalid_signature'));

await assert.rejects(broker.createOperation(null, {}), expectCode('unauthorized'));
await assert.rejects(broker.createOperation({ name: 'owner-1' }, {
  provider: 'Bad', operation_id: 'no.otp', account_ref: 'primary', environment: 'production', typed_parameters: {},
}), expectCode('invalid_request'));
await assert.rejects(broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'no.otp', account_ref: 'primary', environment: 'invalid', typed_parameters: {},
}), expectCode('invalid_request'));
await assert.rejects(broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'no.otp', account_ref: 'primary', environment: 'production',
  typed_parameters: 'invalid',
}), expectCode('invalid_request'));
await assert.rejects(broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'no.otp', account_ref: 'primary', environment: 'production',
  typed_parameters: { payload: 'x'.repeat(70_000) },
}), expectCode('invalid_request'));
await assert.rejects(broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'denied', account_ref: 'primary', environment: 'production', typed_parameters: {},
}), expectCode('forbidden'));
const plain = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'no.otp', account_ref: 'primary', environment: 'production', typed_parameters: {},
});
assert.equal(plain.otp_task_id, null);
assert.throws(() => broker.getOperation({ name: 'owner-1' }, 'missing'), expectCode('not_found'));
assert.throws(() => broker.getOperation({ name: 'other' }, plain.id), expectCode('forbidden'));
assert.equal(broker.getOperation({ name: 'admin', isAdmin: true }, plain.id).id, plain.id);

const noCapacity = new OperationBroker({ ...policy, maxRecords: 0 });
await assert.rejects(noCapacity.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'no.otp', account_ref: 'primary', environment: 'production', typed_parameters: {},
}), expectCode('capacity'));

const noDevice = new OperationBroker({ authorize: () => ({
  allow: true, otpRequired: true,
  otp: { deviceId: 'missing', simBinding: 'sim', templateGroup: 'login', senderAllowlist: ['sender'] },
}) });
await assert.rejects(noDevice.createOperation({ name: 'owner' }, {
  provider: 'aliyun', operation_id: 'login', account_ref: 'primary', environment: 'production', typed_parameters: {},
}), expectCode('device_denied'));

const otpOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'browser.otp.fill', account_ref: 'primary', environment: 'production',
  typed_parameters: { resource_ref: 'account.aliyun.com' },
});
const task = broker.listDeviceOtpTasks(device.id)[0];
assert.throws(() => broker.submitOtp('missing', task.id, {}), expectCode('not_found'));
assert.throws(() => broker.submitOtp(device.id, task.id, { sim_binding: 'wrong' }), expectCode('otp_mismatch'));
assert.throws(() => broker.submitOtp(device.id, task.id, { sim_binding: 'sim-1', challenge: 'wrong' }), expectCode('otp_mismatch'));
assert.throws(() => broker.submitOtp(device.id, task.id, { sim_binding: 'sim-1', challenge: task.challenge, code: 'abc' }), expectCode('invalid_request'));
broker.submitOtp(device.id, task.id, { sim_binding: 'sim-1', challenge: task.challenge, code: '123456' });
assert.throws(() => broker.submitOtp(device.id, task.id, { sim_binding: 'sim-1', challenge: task.challenge, code: '123456' }), expectCode('invalid_state'));
assert.throws(() => broker.listDeviceOtpTasks('missing'), expectCode('device_denied'));
await assert.rejects(broker.consumeOtp('missing', async () => ({})), expectCode('not_found'));

assert.throws(() => broker.claimBrowserOtp(null, {}), expectCode('unauthorized'));
assert.throws(() => broker.claimBrowserOtp({ name: 'owner-1' }, {
  provider: 'github', account_ref: 'primary', origin: 'https://github.com', tab_id: 1, frame_id: 0, document_id: 'doc',
}), expectCode('origin_denied'));
assert.throws(() => broker.claimBrowserOtp({ name: 'owner-1' }, {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: -1, frame_id: 0, document_id: 'doc',
}), expectCode('invalid_request'));
assert.throws(() => broker.claimBrowserOtp({ name: 'owner-1', context: { apiKey: {} } }, {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 2, frame_id: 0, document_id: 'doc',
}), expectCode('forbidden'));
const claim = broker.claimBrowserOtp(browserIdentity, {
  provider: 'aliyun', account_ref: 'primary', origin: 'https://account.aliyun.com', tab_id: 2, frame_id: 0, document_id: 'doc',
});
assert.throws(() => broker.finishBrowserOtp(null, {}), expectCode('unauthorized'));
assert.throws(() => broker.finishBrowserOtp({ name: 'other' }, { receipt: claim.receipt }), expectCode('invalid_claim'));
assert.equal(broker.finishBrowserOtp(browserIdentity, { receipt: claim.receipt, completed: false }).status, 'failed');

const failedOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'browser.otp.fill', account_ref: 'secondary', environment: 'production',
  typed_parameters: { resource_ref: 'account.aliyun.com' },
});
const failedTask = broker.listDeviceOtpTasks(device.id).find((item) => item.id === failedOperation.otp_task_id);
broker.submitOtp(device.id, failedTask.id, { sim_binding: 'sim-1', challenge: failedTask.challenge, code: '654321' });
const failedClaim = broker.claimBrowserOtp(browserIdentity, {
  provider: 'aliyun', account_ref: 'secondary', origin: 'https://account.aliyun.com', tab_id: 3, frame_id: 0, document_id: 'doc-2',
});
assert.equal(broker.finishBrowserOtp(browserIdentity, { receipt: failedClaim.receipt, completed: false }).status, 'failed');

const upstreamFailure = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'login', account_ref: 'third', environment: 'production', typed_parameters: {},
});
const upstreamTask = broker.listDeviceOtpTasks(device.id).find((item) => item.id === upstreamFailure.otp_task_id);
broker.submitOtp(device.id, upstreamTask.id, { sim_binding: 'sim-1', challenge: upstreamTask.challenge, code: '777777' });
await assert.rejects(broker.consumeOtp(upstreamTask.id, async () => { throw new Error('secret upstream detail'); }), expectCode('upstream_failed'));
assert.equal(broker.getOperation({ name: 'owner-1' }, upstreamFailure.id).error.code, 'upstream_operation_failed');

const expiringOperation = await broker.createOperation({ name: 'owner-1' }, {
  provider: 'aliyun', operation_id: 'browser.otp.fill', account_ref: 'expiring', environment: 'production',
  typed_parameters: { resource_ref: 'account.aliyun.com' },
});
const expiringTask = broker.listDeviceOtpTasks(device.id).find((item) => item.id === expiringOperation.otp_task_id);
broker.submitOtp(device.id, expiringTask.id, { sim_binding: 'sim-1', challenge: expiringTask.challenge, code: '888888' });
broker.claimBrowserOtp(browserIdentity, {
  provider: 'aliyun', account_ref: 'expiring', origin: 'https://account.aliyun.com', tab_id: 4, frame_id: 0, document_id: 'doc-3',
});

now += 31_000;
broker.prune();
assert.equal(broker.browserClaims.size, 0);
assert.equal(broker.getOperation({ name: 'owner-1' }, expiringOperation.id).status, 'failed');

console.log('v2 operations: boundary and failure-path tests passed');
