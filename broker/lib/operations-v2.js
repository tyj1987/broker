import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { redactDeep } from './redact.js';

const ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const OTP_RE = /^[0-9]{4,10}$/;
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const DEVICE_PLATFORMS = new Set(['android', 'ios', 'windows', 'linux', 'browser-worker']);
const MAX_CLOCK_SKEW_MS = 60_000;
const DEFAULT_OTP_TTL_MS = 120_000;
const MAX_JSON_BYTES = 64 * 1024;
const DEVICE_SIGNATURE_ALGORITHMS = new Set(['ed25519', 'p256-sha256']);
const EXECUTION_MODES = new Set(['adapter', 'browser']);
const SENSITIVE_RESULT_KEY = /(?:secret|token|password|authorization|cookie|session|credential|private.?key|otp|verification.?code)/i;

export class V2Error extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = 'V2Error';
    this.code = code;
    this.status = status;
  }
}

function requireId(value, field) {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new V2Error('invalid_request', `${field} has an invalid format`);
  }
  return value;
}

function requireObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new V2Error('invalid_request', `${field} must be an object`);
  }
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > MAX_JSON_BYTES) {
    throw new V2Error('invalid_request', `${field} is too large`, 413);
  }
  return structuredClone(value);
}

function requireText(value, field, maxLength = 128) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new V2Error('invalid_request', `${field} has an invalid format`);
  }
  return value;
}

function requireTimestamp(value, field, allowNull = false) {
  if (allowNull && value === null) return null;
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new V2Error('invalid_device_registry', `${field} is not a valid timestamp`, 500);
  }
  return value;
}

function publicOperation(op) {
  return {
    id: op.id,
    provider: op.provider,
    operation_id: op.operationId,
    account_ref: op.accountRef,
    environment: op.environment,
    execution_mode: op.executionMode,
    status: op.status,
    created_at: op.createdAt,
    expires_at: op.expiresAt,
    updated_at: op.updatedAt,
    otp_task_id: op.otpTaskId || null,
    result: op.status === 'completed' ? structuredClone(op.result) : undefined,
    error: op.error ? { code: String(op.error) } : undefined,
  };
}

function publicDevice(device, includeOwner = true) {
  const result = {
    id: device.id,
    label: device.label,
    platform: device.platform,
    signature_algorithm: device.signatureAlgorithm,
    capabilities: [...device.capabilities],
    state: device.state,
    created_at: device.createdAt,
    last_seen_at: device.lastSeenAt || null,
  };
  if (includeOwner) result.owner = device.owner;
  return result;
}

function canAdministerOtherOwners(identity) {
  const context = identity?.context;
  return context?.client?.role === 'admin'
    && context.via === 'session'
    && context.authFactors?.includes('webauthn');
}

function apiKeyAllowsOperation(identity, operation) {
  const context = identity?.context;
  const key = context?.apiKey;
  if (!key) return context?.via !== 'api_key';
  const exactScope = `operations:${operation.provider}:${operation.operationId}`;
  return (key?.scopes?.includes('operations:execute') || key?.scopes?.includes(exactScope))
    && key.allowed_services?.includes(operation.provider)
    && key.allowed_operations?.includes(`${operation.provider}:${operation.operationId}`)
    && key.allowed_accounts?.includes(operation.accountRef)
    && key.allowed_environments?.includes(operation.environment)
    && key.allowed_resources?.includes(operation.typedParameters?.resource_ref);
}

function validatedDeviceKey(publicKeyPem, requestedAlgorithm = null) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.includes('BEGIN PUBLIC KEY')) {
    throw new V2Error('invalid_request', 'device public key is invalid');
  }
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new V2Error('invalid_request', 'device public key is invalid');
  }
  const inferred = key.asymmetricKeyType === 'ed25519' ? 'ed25519'
    : key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
      ? 'p256-sha256' : null;
  if (!inferred || (requestedAlgorithm && requestedAlgorithm !== inferred)) {
    throw new V2Error('invalid_request', 'device signature algorithm does not match its public key');
  }
  return { key, algorithm: inferred };
}

function verifyDeviceSignature(algorithm, key, message, signature) {
  if (!DEVICE_SIGNATURE_ALGORITHMS.has(algorithm)) return false;
  return verify(algorithm === 'ed25519' ? null : 'sha256', message, key, signature);
}

function publicOtpTask(task) {
  return {
    id: task.id,
    operation_id: task.operationId,
    device_id: task.deviceId,
    sim_binding: task.simBinding,
    provider: task.provider,
    template_group: task.templateGroup,
    sender_allowlist: [...task.senderAllowlist],
    challenge: task.challenge,
    status: task.status,
    created_at: task.createdAt,
    expires_at: task.expiresAt,
  };
}

export function sha256Base64Url(value) {
  return createHash('sha256').update(value).digest('base64url');
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function canonicalDeviceMessage({ deviceId, timestamp, nonce, method, path, body }) {
  return [
    'secret-broker-device-request-v1',
    deviceId,
    String(timestamp),
    nonce,
    method.toUpperCase(),
    path,
    sha256Base64Url(Buffer.from(body || '')),
  ].join('\n');
}

export class OperationBroker {
  constructor({ now = () => Date.now(), authorize = () => false, persistDevices = async () => {}, maxRecords = 10_000 } = {}) {
    this.now = now;
    this.authorize = authorize;
    this.persistDevices = persistDevices;
    this.maxRecords = maxRecords;
    this.operations = new Map();
    this.otpTasks = new Map();
    this.devices = new Map();
    this.enrollments = new Map();
    this.usedNonces = new Map();
    this.activeOtpLocks = new Map();
    this.browserClaims = new Map();
    this.browserLeases = new Map();
  }

  hydrateDevices(records = []) {
    this.commitDeviceRegistry(this.prepareDeviceRegistry(records));
  }

  prepareDeviceRegistry(records = []) {
    if (!Array.isArray(records)) throw new V2Error('invalid_device_registry', 'device registry must be an array', 500);
    const next = new Map();
    for (const record of records) {
      const id = requireId(record?.id, 'device id');
      const owner = requireId(record?.owner, 'device owner');
      const label = requireId(record?.label, 'device label');
      if (!DEVICE_PLATFORMS.has(record?.platform) || !['active', 'suspended', 'revoked'].includes(record?.state)) {
        throw new V2Error('invalid_device_registry', 'stored device has invalid platform or state', 500);
      }
      let deviceKey;
      try {
        deviceKey = validatedDeviceKey(record.public_key_pem, record.signature_algorithm || null);
      } catch {
        throw new V2Error('invalid_device_registry', 'stored device key is invalid', 500);
      }
      const capabilities = [...new Set(record.capabilities || [])];
      for (const capability of capabilities) requireId(capability, 'capability');
      const createdAt = requireTimestamp(record.created_at, 'created_at');
      const lastSeenAt = requireTimestamp(record.last_seen_at ?? null, 'last_seen_at', true);
      next.set(id, {
        id, owner, label, platform: record.platform, capabilities,
        publicKeyPem: record.public_key_pem, signatureAlgorithm: deviceKey.algorithm, state: record.state,
        createdAt, lastSeenAt,
      });
    }
    return next;
  }

  commitDeviceRegistry(candidate) {
    if (!(candidate instanceof Map)) throw new V2Error('invalid_device_registry', 'prepared device registry must be a map', 500);
    this.devices = candidate;
  }

  deviceRecords() {
    return [...this.devices.values()].map((device) => ({
      id: device.id, owner: device.owner, label: device.label, platform: device.platform,
      capabilities: [...device.capabilities], public_key_pem: device.publicKeyPem,
      signature_algorithm: device.signatureAlgorithm,
      state: device.state, created_at: device.createdAt, last_seen_at: device.lastSeenAt || null,
    }));
  }

  beginEnrollment(owner, input) {
    requireId(owner, 'owner');
    const label = requireId(input?.label, 'label');
    const platform = input?.platform;
    if (!DEVICE_PLATFORMS.has(platform)) {
      throw new V2Error('invalid_request', 'unsupported device platform');
    }
    const capabilities = [...new Set(input?.capabilities || [])];
    for (const capability of capabilities) requireId(capability, 'capability');
    const enrollment = {
      id: randomUUID(),
      owner,
      label,
      platform,
      capabilities,
      challenge: randomBytes(32).toString('base64url'),
      expiresAt: this.now() + 5 * 60_000,
    };
    this.enrollments.set(enrollment.id, enrollment);
    return {
      enrollment_id: enrollment.id,
      challenge: enrollment.challenge,
      expires_at: new Date(enrollment.expiresAt).toISOString(),
      signing_context: 'secret-broker-device-enrollment-v1',
    };
  }

  rollbackEnrollment(owner, enrollmentId) {
    const enrollment = this.enrollments.get(enrollmentId);
    if (!enrollment) throw new V2Error('not_found', 'device enrollment not found', 404);
    if (enrollment.owner !== owner) throw new V2Error('forbidden', 'device enrollment access denied', 403);
    this.enrollments.delete(enrollmentId);
  }

  async completeEnrollment(owner, input) {
    const enrollment = this.enrollments.get(input?.enrollment_id);
    if (!enrollment || (owner && enrollment.owner !== owner) || enrollment.expiresAt <= this.now()) {
      throw new V2Error('invalid_enrollment', 'enrollment is invalid or expired', 401);
    }
    if (typeof input.public_key_pem !== 'string' || typeof input.signature !== 'string') {
      throw new V2Error('invalid_request', 'public_key_pem and signature are required');
    }
    const message = Buffer.from(
      `secret-broker-device-enrollment-v1\n${enrollment.id}\n${enrollment.challenge}`,
    );
    let valid = false;
    let deviceKey;
    try {
      deviceKey = validatedDeviceKey(input.public_key_pem, input.signature_algorithm || 'ed25519');
      valid = verifyDeviceSignature(
        deviceKey.algorithm,
        deviceKey.key,
        message,
        Buffer.from(input.signature, 'base64url'),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw new V2Error('invalid_signature', 'device proof of possession failed', 401);
    this.enrollments.delete(enrollment.id);
    const device = {
      id: randomUUID(),
      owner: enrollment.owner,
      label: enrollment.label,
      platform: enrollment.platform,
      capabilities: enrollment.capabilities,
      publicKeyPem: input.public_key_pem,
      signatureAlgorithm: deviceKey.algorithm,
      state: 'active',
      createdAt: new Date(this.now()).toISOString(),
      lastSeenAt: null,
    };
    this.devices.set(device.id, device);
    try {
      await this.persistDevices(this.deviceRecords());
    } catch {
      this.devices.delete(device.id);
      this.enrollments.set(enrollment.id, enrollment);
      throw new V2Error('persistence_failed', 'device enrollment could not be persisted', 503);
    }
    return publicDevice(device, false);
  }

  listDevices(identity) {
    if (identity?.context?.apiKey || identity?.context?.via === 'api_key') return [];
    return [...this.devices.values()]
      .filter((device) => device.owner === identity?.name || canAdministerOtherOwners(identity))
      .map(publicDevice);
  }

  async setDeviceState(requester, deviceId, state, isAdmin = false) {
    if (!['active', 'suspended', 'revoked'].includes(state)) {
      throw new V2Error('invalid_request', 'invalid device state');
    }
    const device = this.devices.get(deviceId);
    if (!device) throw new V2Error('not_found', 'device not found', 404);
    if (!isAdmin && requester !== device.owner) throw new V2Error('forbidden', 'device access denied', 403);
    if (device.state === 'revoked' && state !== 'revoked') {
      throw new V2Error('invalid_state', 'revoked devices cannot be reactivated', 409);
    }
    const previous = device.state;
    device.state = state;
    try {
      await this.persistDevices(this.deviceRecords());
    } catch {
      device.state = previous;
      throw new V2Error('persistence_failed', 'device state could not be persisted', 503);
    }
    if (state !== 'active') this.cancelDeviceTasks(deviceId);
    return publicDevice(device);
  }

  async suspendDevice(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device || device.state !== 'active') {
      throw new V2Error('device_denied', 'device is unavailable', 401);
    }
    return this.setDeviceState(device.owner, deviceId, 'suspended');
  }

  verifyDeviceRequest(deviceId, signed) {
    const device = this.devices.get(deviceId);
    if (!device || device.state !== 'active') throw new V2Error('device_denied', 'device is unavailable', 401);
    const timestamp = Number(signed.timestamp);
    if (!Number.isSafeInteger(timestamp) || Math.abs(this.now() - timestamp) > MAX_CLOCK_SKEW_MS) {
      throw new V2Error('stale_request', 'device request timestamp is outside the allowed window', 401);
    }
    requireId(signed.nonce, 'nonce');
    this.prune();
    const nonceKey = `${deviceId}:${signed.nonce}`;
    if (this.usedNonces.has(nonceKey)) throw new V2Error('replay', 'device request was already used', 409);
    const message = canonicalDeviceMessage({ ...signed, deviceId });
    let valid = false;
    try {
      valid = verifyDeviceSignature(
        device.signatureAlgorithm,
        device.publicKeyPem,
        Buffer.from(message),
        Buffer.from(signed.signature, 'base64url'),
      );
    } catch {
      valid = false;
    }
    if (!valid) throw new V2Error('invalid_signature', 'device request signature is invalid', 401);
    this.usedNonces.set(nonceKey, this.now() + MAX_CLOCK_SKEW_MS);
    device.lastSeenAt = new Date(this.now()).toISOString();
    return publicDevice(device, false);
  }

  async createOperation(identity, input) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const provider = requireId(input?.provider, 'provider');
    const operationId = requireId(input?.operation_id, 'operation_id');
    const accountRef = requireId(input?.account_ref, 'account_ref');
    const environment = input?.environment;
    if (!ENVIRONMENTS.has(environment)) throw new V2Error('invalid_request', 'unsupported environment');
    const typedParameters = requireObject(input?.typed_parameters || {}, 'typed_parameters');
    const decision = await this.authorize({ identity, provider, operationId, accountRef, environment, typedParameters });
    if (!decision?.allow) throw new V2Error('forbidden', 'operation is not allowed', 403);
    this.prune();
    if (this.operations.size >= this.maxRecords) throw new V2Error('capacity', 'operation capacity reached', 503);
    const now = this.now();
    const ttlMs = Math.min(Math.max(Number(decision.ttlMs || 300_000), 10_000), 900_000);
    const executionMode = decision.executionMode || 'adapter';
    if (!EXECUTION_MODES.has(executionMode)) throw new V2Error('invalid_policy', 'unsupported execution mode', 500);
    const operation = {
      id: randomUUID(),
      owner: identity.name,
      provider,
      operationId,
      accountRef,
      environment,
      executionMode,
      typedParameters,
      status: 'waiting',
      createdAt: new Date(now).toISOString(),
      updatedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
      result: null,
      error: null,
    };
    this.operations.set(operation.id, operation);
    try {
      if (decision.otpRequired) {
        const task = this.createOtpTask(operation, decision.otp);
        operation.otpTaskId = task.id;
      }
    } catch (error) {
      this.operations.delete(operation.id);
      throw error;
    }
    return publicOperation(operation);
  }

  rollbackOperationCreation(identity, id) {
    const operation = this.operations.get(id);
    if (!operation) throw new V2Error('not_found', 'operation not found', 404);
    if (operation.owner !== identity?.name) throw new V2Error('forbidden', 'operation access denied', 403);
    if (operation.status !== 'waiting' || operation.browserLeaseId) {
      throw new V2Error('invalid_state', 'operation creation cannot be rolled back', 409);
    }
    if (operation.otpTaskId) {
      const task = this.otpTasks.get(operation.otpTaskId);
      if (!task || task.status !== 'waiting') {
        throw new V2Error('invalid_state', 'operation OTP task cannot be rolled back', 409);
      }
      this.activeOtpLocks.delete(task.lockKey);
      this.otpTasks.delete(task.id);
    }
    this.operations.delete(id);
  }

  getOperation(identity, id) {
    const operation = this.operations.get(id);
    if (!operation) throw new V2Error('not_found', 'operation not found', 404);
    if (operation.owner !== identity?.name && !canAdministerOtherOwners(identity)) {
      throw new V2Error('forbidden', 'operation access denied', 403);
    }
    if (!apiKeyAllowsOperation(identity, operation)) {
      throw new V2Error('forbidden', 'API key is not authorized for this operation', 403);
    }
    this.expireOperation(operation);
    return publicOperation(operation);
  }

  createOtpTask(operation, otp = {}) {
    const device = this.devices.get(otp.deviceId);
    if (!device || device.state !== 'active' || !device.capabilities.includes('otp.receive')) {
      throw new V2Error('device_denied', 'an active OTP device is required', 409);
    }
    if (device.owner !== operation.owner) throw new V2Error('device_denied', 'OTP device owner mismatch', 403);
    const simBinding = requireId(otp.simBinding, 'sim_binding');
    const templateGroup = requireId(otp.templateGroup, 'template_group');
    const senderAllowlist = [...new Set(otp.senderAllowlist || [])]
      .map((sender) => requireText(sender, 'sender_allowlist', 64));
    if (senderAllowlist.length === 0 || senderAllowlist.length > 16) {
      throw new V2Error('invalid_request', 'sender_allowlist must contain 1 to 16 exact senders');
    }
    const lockKey = `${device.id}:${simBinding}:${operation.provider}:${templateGroup}`;
    const active = this.activeOtpLocks.get(lockKey);
    if (active) {
      const oldTask = this.otpTasks.get(active);
      if (oldTask && !['completed', 'expired', 'revoked'].includes(oldTask.status)) {
        throw new V2Error('otp_conflict', 'an indistinguishable OTP request is already active', 409);
      }
    }
    const now = this.now();
    const ttlMs = Math.min(Math.max(Number(otp.ttlMs || DEFAULT_OTP_TTL_MS), 15_000), DEFAULT_OTP_TTL_MS);
    const task = {
      id: randomUUID(),
      operationId: operation.id,
      owner: operation.owner,
      deviceId: device.id,
      simBinding,
      provider: operation.provider,
      templateGroup,
      senderAllowlist,
      lockKey,
      challenge: randomBytes(32).toString('base64url'),
      recipientHash: sha256Base64Url(String(otp.recipientRef || '')),
      status: 'waiting',
      code: null,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
    };
    task.challengeHash = sha256Base64Url(task.challenge);
    this.otpTasks.set(task.id, task);
    this.activeOtpLocks.set(lockKey, task.id);
    return publicOtpTask(task);
  }

  submitOtp(deviceId, taskId, input) {
    const task = this.otpTasks.get(taskId);
    if (!task || task.deviceId !== deviceId) throw new V2Error('not_found', 'OTP task not found', 404);
    this.expireOtpTask(task);
    if (task.status !== 'waiting') throw new V2Error('invalid_state', 'OTP task is not waiting', 409);
    if (input.sim_binding !== task.simBinding) throw new V2Error('otp_mismatch', 'SIM binding mismatch', 409);
    if (sha256Base64Url(String(input.challenge || '')) !== task.challengeHash) {
      throw new V2Error('otp_mismatch', 'challenge mismatch', 409);
    }
    if (typeof input.code !== 'string' || !OTP_RE.test(input.code)) {
      throw new V2Error('invalid_request', 'OTP code has an invalid format');
    }
    task.code = input.code;
    task.status = 'received';
    const operation = this.operations.get(task.operationId);
    if (operation) {
      if (operation.status !== 'consuming') operation.status = 'received';
      operation.updatedAt = new Date(this.now()).toISOString();
    }
    return publicOtpTask(task);
  }

  submitOtpAndAudit(deviceId, taskId, input, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const task = this.otpTasks.get(taskId);
    const operation = task ? this.operations.get(task.operationId) : null;
    const previous = task ? {
      taskStatus: task.status,
      taskCode: task.code,
      operationStatus: operation?.status,
      operationUpdatedAt: operation?.updatedAt,
    } : null;
    const result = this.submitOtp(deviceId, taskId, input);
    try {
      commitAudit(result);
    } catch (error) {
      if (!previous || this.otpTasks.get(taskId) !== task
        || (operation && this.operations.get(operation.id) !== operation)) {
        throw new V2Error('audit_rollback_failed', 'OTP audit rollback failed', 503);
      }
      task.status = previous.taskStatus;
      task.code = previous.taskCode;
      if (operation) {
        operation.status = previous.operationStatus;
        operation.updatedAt = previous.operationUpdatedAt;
      }
      throw error;
    }
    return result;
  }

  listDeviceOtpTasks(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device || device.state !== 'active') throw new V2Error('device_denied', 'device is unavailable', 401);
    this.prune();
    return [...this.otpTasks.values()]
      .filter((task) => task.deviceId === deviceId && task.status === 'waiting')
      .map(publicOtpTask);
  }

  async consumeOtp(taskId, consumer) {
    const task = this.otpTasks.get(taskId);
    if (!task) throw new V2Error('not_found', 'OTP task not found', 404);
    this.expireOtpTask(task);
    if (task.status !== 'received' || !task.code) throw new V2Error('invalid_state', 'OTP is not available', 409);
    task.status = 'consuming';
    const code = task.code;
    task.code = null;
    const operation = this.operations.get(task.operationId);
    if (operation) {
      operation.status = 'consuming';
      operation.updatedAt = new Date(this.now()).toISOString();
    }
    try {
      const result = await consumer(code);
      if (task.status !== 'consuming' || operation?.status === 'revoked') {
        throw new V2Error('operation_revoked', 'OTP operation was revoked while consuming', 409);
      }
      task.status = 'completed';
      this.activeOtpLocks.delete(task.lockKey);
      if (operation) {
        operation.status = 'completed';
        operation.result = result;
        operation.updatedAt = new Date(this.now()).toISOString();
      }
      return result;
    } catch (error) {
      if (task.status === 'revoked' || operation?.status === 'revoked') {
        throw new V2Error('operation_revoked', 'OTP operation was revoked while consuming', 409);
      }
      task.status = 'failed';
      this.activeOtpLocks.delete(task.lockKey);
      if (operation) {
        operation.status = 'failed';
        operation.error = 'upstream_operation_failed';
        operation.updatedAt = new Date(this.now()).toISOString();
      }
      throw new V2Error('upstream_failed', 'upstream operation failed', 502);
    }
  }

  claimBrowserOtp(identity, input) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const provider = requireId(input?.provider, 'provider');
    const accountRef = requireId(input?.account_ref, 'account_ref');
    const origin = requireText(input?.origin, 'origin', 256);
    const expectedOrigin = provider === 'aliyun' ? 'https://account.aliyun.com'
      : provider === 'tencent' ? 'https://cloud.tencent.com' : null;
    if (origin !== expectedOrigin) throw new V2Error('origin_denied', 'browser origin is not allowed', 403);
    const tabId = Number(input?.tab_id);
    const frameId = Number(input?.frame_id);
    const documentId = requireText(input?.document_id, 'document_id', 256);
    if (!Number.isSafeInteger(tabId) || tabId < 0 || frameId !== 0) {
      throw new V2Error('invalid_request', 'invalid browser frame binding');
    }
    this.prune();
    const task = [...this.otpTasks.values()].find((candidate) => {
      if (candidate.owner !== identity.name || candidate.provider !== provider || candidate.status !== 'received') return false;
      const operation = this.operations.get(candidate.operationId);
      return operation?.operationId === 'browser.otp.fill'
        && operation.accountRef === accountRef
        && operation.status === 'received';
    });
    if (!task?.code) throw new V2Error('not_found', 'no approved OTP is available', 404);
    const operation = this.operations.get(task.operationId);
    const key = identity.context?.apiKey;
    const allowed = key
      && key.allowed_services?.includes(provider)
      && key.allowed_operations?.includes(`${provider}:browser.otp.fill`)
      && key.allowed_accounts?.includes(accountRef)
      && key.allowed_environments?.includes(operation.environment)
      && key.allowed_resources?.includes(operation.typedParameters.resource_ref);
    if (!allowed) throw new V2Error('forbidden', 'browser bridge key constraints denied the operation', 403);
    task.status = 'consuming';
    const previousOperationStatus = operation.status;
    const previousOperationUpdatedAt = operation.updatedAt;
    operation.status = 'consuming';
    operation.updatedAt = new Date(this.now()).toISOString();
    const receipt = randomBytes(32).toString('base64url');
    const expiresAt = Math.min(new Date(task.expiresAt).getTime(), this.now() + 30_000);
    const claim = {
      receipt, owner: identity.name, taskId: task.id, provider, accountRef, origin, tabId, frameId,
      documentId, expiresAt, code: task.code, previousTaskStatus: 'received',
      previousOperationStatus, previousOperationUpdatedAt,
    };
    task.code = null;
    this.browserClaims.set(sha256Base64Url(receipt), claim);
    return {
      type: 'approved-otp', provider, account_ref: accountRef, origin, tab_id: tabId, frame_id: frameId,
      document_id: documentId, expires_at_ms: expiresAt, code: claim.code, receipt,
    };
  }

  claimBrowserOtpAndAudit(identity, input, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const result = this.claimBrowserOtp(identity, input);
    const claimKey = sha256Base64Url(result.receipt);
    const claim = this.browserClaims.get(claimKey);
    const task = claim ? this.otpTasks.get(claim.taskId) : null;
    const operation = task ? this.operations.get(task.operationId) : null;
    try {
      commitAudit({ provider: result.provider, operation_id: operation?.id });
    } catch (error) {
      if (!claim || this.browserClaims.get(claimKey) !== claim || !task || !operation) {
        throw new V2Error('audit_rollback_failed', 'browser OTP claim audit rollback failed', 503);
      }
      this.browserClaims.delete(claimKey);
      task.status = claim.previousTaskStatus;
      task.code = claim.code;
      operation.status = claim.previousOperationStatus;
      operation.updatedAt = claim.previousOperationUpdatedAt;
      claim.code = null;
      throw error;
    }
    return result;
  }

  finishBrowserOtp(identity, input) {
    return this.commitBrowserOtpFinish(this.prepareBrowserOtpFinish(identity, input));
  }

  finishBrowserOtpAndAudit(identity, input, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const completion = this.prepareBrowserOtpFinish(identity, input);
    commitAudit({
      operation_id: completion.operation.id,
      status: completion.completed ? 'completed' : 'failed',
    });
    return this.commitBrowserOtpFinish(completion);
  }

  prepareBrowserOtpFinish(identity, input) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const receipt = requireText(input?.receipt, 'receipt', 128);
    const claimKey = sha256Base64Url(receipt);
    const claim = this.browserClaims.get(claimKey);
    if (!claim || claim.owner !== identity.name || claim.expiresAt <= this.now()) {
      if (claim?.owner === identity.name) this.browserClaims.delete(claimKey);
      throw new V2Error('invalid_claim', 'browser OTP claim is invalid or expired', 409);
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).length !== 2 || typeof input.completed !== 'boolean') {
      throw new V2Error('invalid_request', 'browser OTP finish requires only receipt and completed');
    }
    const task = this.otpTasks.get(claim.taskId);
    const operation = task ? this.operations.get(task.operationId) : null;
    if (!task || task.status !== 'consuming' || !operation) {
      throw new V2Error('invalid_state', 'browser OTP claim is no longer active', 409);
    }
    const completed = input?.completed === true;
    return { claimKey, claim, task, operation, completed };
  }

  commitBrowserOtpFinish({ claimKey, claim, task, operation, completed }) {
    this.browserClaims.delete(claimKey);
    task.status = completed ? 'completed' : 'failed';
    this.activeOtpLocks.delete(task.lockKey);
    operation.status = completed ? 'completed' : 'failed';
    operation.result = completed ? { filled: true, provider: claim.provider } : null;
    operation.error = completed ? null : 'browser_fill_failed';
    operation.updatedAt = new Date(this.now()).toISOString();
    claim.code = null;
    return publicOperation(operation);
  }

  claimBrowserOperation(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device || device.state !== 'active' || device.platform !== 'browser-worker') {
      throw new V2Error('device_denied', 'active browser worker is required', 401);
    }
    this.prune();
    const operation = [...this.operations.values()]
      .filter((candidate) => ['waiting', 'received'].includes(candidate.status)
        && candidate.executionMode === 'browser'
        && device.capabilities.includes([
          'browser.execute', candidate.provider, candidate.operationId, candidate.accountRef, candidate.environment,
        ].join(':')))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (!operation) throw new V2Error('not_found', 'no browser operation is available', 404);
    const previousStatus = operation.status;
    const previousUpdatedAt = operation.updatedAt;
    operation.status = 'consuming';
    operation.updatedAt = new Date(this.now()).toISOString();
    const leaseId = randomUUID();
    const receipt = randomBytes(32).toString('base64url');
    const expiresAt = Math.min(new Date(operation.expiresAt).getTime(), this.now() + 60_000);
    this.browserLeases.set(leaseId, {
      id: leaseId, receiptHash: sha256Base64Url(receipt), deviceId, operationId: operation.id,
      expiresAt, otpClaimed: false, previousStatus, previousUpdatedAt,
    });
    return {
      id: leaseId,
      receipt,
      expires_at: new Date(expiresAt).toISOString(),
      operation: {
        id: operation.id, provider: operation.provider, operation_id: operation.operationId,
        account_ref: operation.accountRef, environment: operation.environment,
        typed_parameters: structuredClone(operation.typedParameters),
        otp_available: operation.otpTaskId
          ? this.otpTasks.get(operation.otpTaskId)?.status === 'received' : false,
      },
    };
  }

  claimBrowserOperationAndAudit(deviceId, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const result = this.claimBrowserOperation(deviceId);
    const lease = this.browserLeases.get(result.id);
    const operation = lease ? this.operations.get(lease.operationId) : null;
    try {
      commitAudit(result);
    } catch (error) {
      if (!lease || this.browserLeases.get(result.id) !== lease || !operation) {
        throw new V2Error('audit_rollback_failed', 'browser lease audit rollback failed', 503);
      }
      this.browserLeases.delete(result.id);
      operation.status = lease.previousStatus;
      operation.updatedAt = lease.previousUpdatedAt;
      throw error;
    }
    return result;
  }

  claimBrowserOperationOtp(deviceId, leaseId, receipt) {
    const { lease, operation } = this.activeBrowserLease(deviceId, leaseId, receipt);
    if (lease.otpClaimed || !operation.otpTaskId) throw new V2Error('invalid_state', 'lease OTP is unavailable', 409);
    const task = this.otpTasks.get(operation.otpTaskId);
    if (!task || task.status !== 'received' || !task.code) throw new V2Error('invalid_state', 'lease OTP is unavailable', 409);
    task.status = 'consuming';
    const code = task.code;
    task.code = null;
    lease.otpClaimed = true;
    return { code, expires_at: task.expiresAt };
  }

  claimBrowserOperationOtpAndAudit(deviceId, leaseId, receipt, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const lease = this.browserLeases.get(leaseId);
    const operation = lease ? this.operations.get(lease.operationId) : null;
    const task = operation?.otpTaskId ? this.otpTasks.get(operation.otpTaskId) : null;
    const previous = task && lease ? {
      otpClaimed: lease.otpClaimed,
      taskStatus: task.status,
      taskCode: task.code,
    } : null;
    const result = this.claimBrowserOperationOtp(deviceId, leaseId, receipt);
    try {
      commitAudit({ expires_at: result.expires_at });
    } catch (error) {
      if (!previous || this.browserLeases.get(leaseId) !== lease
        || this.otpTasks.get(task.id) !== task) {
        throw new V2Error('audit_rollback_failed', 'browser OTP audit rollback failed', 503);
      }
      lease.otpClaimed = previous.otpClaimed;
      task.status = previous.taskStatus;
      task.code = previous.taskCode;
      throw error;
    }
    return result;
  }

  completeBrowserOperation(deviceId, leaseId, input) {
    const { lease, operation } = this.activeBrowserLease(deviceId, leaseId, input?.receipt);
    const completed = input?.status === 'completed';
    if (!completed && input?.status !== 'failed') {
      throw new V2Error('invalid_request', 'lease status must be completed or failed');
    }
    let result = null;
    if (completed) {
      result = requireObject(input?.result || {}, 'result');
      assertSafeResult(result);
      if (canonicalJson(redactDeep(result)) !== canonicalJson(result)) {
        throw new V2Error('unsafe_result', 'browser result contains credential material');
      }
    }
    const errorCode = completed ? null : requireId(input?.error_code || 'browser_operation_failed', 'error_code');
    return this.commitBrowserCompletion({ lease, operation, completed, result, errorCode });
  }

  completeBrowserOperationAndAudit(deviceId, leaseId, input, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    const { lease, operation } = this.activeBrowserLease(deviceId, leaseId, input?.receipt);
    const completed = input?.status === 'completed';
    if (!completed && input?.status !== 'failed') {
      throw new V2Error('invalid_request', 'lease status must be completed or failed');
    }
    let result = null;
    if (completed) {
      result = requireObject(input?.result || {}, 'result');
      assertSafeResult(result);
      if (canonicalJson(redactDeep(result)) !== canonicalJson(result)) {
        throw new V2Error('unsafe_result', 'browser result contains credential material');
      }
    }
    const errorCode = completed ? null : requireId(input?.error_code || 'browser_operation_failed', 'error_code');
    commitAudit({ operation_id: operation.id, status: completed ? 'completed' : 'failed' });
    return this.commitBrowserCompletion({ lease, operation, completed, result, errorCode });
  }

  commitBrowserCompletion({ lease, operation, completed, result, errorCode }) {
    this.browserLeases.delete(lease.id);
    operation.status = completed ? 'completed' : 'failed';
    operation.result = result;
    operation.error = errorCode;
    operation.updatedAt = new Date(this.now()).toISOString();
    if (operation.otpTaskId) {
      const task = this.otpTasks.get(operation.otpTaskId);
      if (task && ['waiting', 'received', 'consuming'].includes(task.status)) {
        task.code = null;
        task.status = completed ? 'completed' : 'failed';
        this.activeOtpLocks.delete(task.lockKey);
      }
    }
    return publicOperation(operation);
  }

  activeBrowserLease(deviceId, leaseId, receipt) {
    const device = this.devices.get(deviceId);
    if (!device || device.state !== 'active' || device.platform !== 'browser-worker') {
      throw new V2Error('device_denied', 'active browser worker is required', 401);
    }
    const lease = this.browserLeases.get(leaseId);
    const suppliedReceiptHash = typeof receipt === 'string' ? sha256Base64Url(receipt) : '';
    const receiptMatches = lease
      && suppliedReceiptHash.length === lease.receiptHash.length
      && timingSafeEqual(Buffer.from(suppliedReceiptHash), Buffer.from(lease.receiptHash));
    if (!lease || lease.deviceId !== deviceId || lease.expiresAt <= this.now()
      || !receiptMatches) {
      throw new V2Error('invalid_lease', 'browser operation lease is invalid or expired', 409);
    }
    const operation = this.operations.get(lease.operationId);
    if (!operation || operation.status !== 'consuming') {
      throw new V2Error('invalid_state', 'browser operation is no longer active', 409);
    }
    return { lease, operation };
  }

  cancelDeviceTasks(deviceId) {
    const revokedAt = new Date(this.now()).toISOString();
    for (const task of this.otpTasks.values()) {
      if (task.deviceId === deviceId && ['waiting', 'received', 'consuming'].includes(task.status)) {
        task.code = null;
        task.status = 'revoked';
        this.activeOtpLocks.delete(task.lockKey);
        const operation = this.operations.get(task.operationId);
        if (operation && !['completed', 'failed'].includes(operation.status)) {
          operation.status = 'revoked';
          operation.error = 'device_revoked';
          operation.updatedAt = revokedAt;
        }
      }
    }
    for (const [key, claim] of this.browserClaims) {
      const task = this.otpTasks.get(claim.taskId);
      if (task?.deviceId === deviceId) {
        claim.code = null;
        this.browserClaims.delete(key);
      }
    }
    for (const [id, lease] of this.browserLeases) {
      if (lease.deviceId === deviceId) {
        this.browserLeases.delete(id);
        const operation = this.operations.get(lease.operationId);
        if (operation && !['completed', 'failed'].includes(operation.status)) {
          operation.status = 'revoked';
          operation.error = 'device_revoked';
          operation.updatedAt = revokedAt;
        }
      }
    }
  }

  expireOtpTask(task) {
    if (new Date(task.expiresAt).getTime() <= this.now() && !['completed', 'revoked'].includes(task.status)) {
      task.code = null;
      task.status = 'expired';
      this.activeOtpLocks.delete(task.lockKey);
      const operation = this.operations.get(task.operationId);
      if (operation && !['completed', 'revoked'].includes(operation.status)) operation.status = 'expired';
    }
  }

  expireOperation(operation) {
    if (new Date(operation.expiresAt).getTime() <= this.now() && !['completed', 'failed', 'revoked'].includes(operation.status)) {
      operation.status = 'expired';
      operation.updatedAt = new Date(this.now()).toISOString();
      if (operation.otpTaskId) {
        const task = this.otpTasks.get(operation.otpTaskId);
        if (task) this.expireOtpTask(task);
      }
    }
  }

  prune() {
    const now = this.now();
    for (const [key, expiresAt] of this.usedNonces) if (expiresAt <= now) this.usedNonces.delete(key);
    for (const [id, enrollment] of this.enrollments) if (enrollment.expiresAt <= now) this.enrollments.delete(id);
    for (const task of this.otpTasks.values()) this.expireOtpTask(task);
    for (const operation of this.operations.values()) this.expireOperation(operation);
    for (const [key, claim] of this.browserClaims) {
      if (claim.expiresAt <= now) {
        claim.code = null;
        this.browserClaims.delete(key);
        const task = this.otpTasks.get(claim.taskId);
        if (task?.status === 'consuming') {
          task.status = 'failed';
          this.activeOtpLocks.delete(task.lockKey);
          const operation = this.operations.get(task.operationId);
          if (operation) {
            operation.status = 'failed';
            operation.error = 'browser_claim_expired';
            operation.updatedAt = new Date(now).toISOString();
          }
        }
      }
    }
    for (const [id, lease] of this.browserLeases) {
      if (lease.expiresAt > now) continue;
      this.browserLeases.delete(id);
      const operation = this.operations.get(lease.operationId);
      if (operation?.status === 'consuming') {
        operation.status = 'failed';
        operation.error = 'browser_lease_expired';
        operation.updatedAt = new Date(now).toISOString();
        if (operation.otpTaskId) {
          const task = this.otpTasks.get(operation.otpTaskId);
          if (task && ['waiting', 'received', 'consuming'].includes(task.status)) {
            task.code = null;
            task.status = 'failed';
            this.activeOtpLocks.delete(task.lockKey);
          }
        }
      }
    }
  }
}

function assertSafeResult(value, depth = 0) {
  if (depth > 8) throw new V2Error('unsafe_result', 'browser result is too deeply nested');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (Array.isArray(value)) {
    for (const item of value) assertSafeResult(item, depth + 1);
    return;
  }
  if (typeof value !== 'object') throw new V2Error('unsafe_result', 'browser result contains an unsupported value');
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_RESULT_KEY.test(key)) throw new V2Error('unsafe_result', 'browser result contains a sensitive field');
    assertSafeResult(item, depth + 1);
  }
}

export const V2_LIMITS = Object.freeze({
  maxClockSkewMs: MAX_CLOCK_SKEW_MS,
  defaultOtpTtlMs: DEFAULT_OTP_TTL_MS,
  maxJsonBytes: MAX_JSON_BYTES,
});
