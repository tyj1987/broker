import { createHash, randomBytes } from 'node:crypto';

const DEVICE_ID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const LEASE_ID_RE = DEVICE_ID_RE;
const ERROR_CODE_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const MAX_RESPONSE_BYTES = 128 * 1024;

export class BrowserBrokerError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.name = 'BrowserBrokerError';
    this.code = code;
    this.status = status;
  }
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

function sha256Base64Url(value) {
  return createHash('sha256').update(value).digest('base64url');
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

function requireUuid(value, field, pattern = DEVICE_ID_RE) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new BrowserBrokerError('invalid_configuration', `${field} is invalid`);
  }
  return value;
}

export class BrowserBrokerClient {
  constructor({
    brokerOrigin,
    deviceId,
    signer,
    fetchImpl = globalThis.fetch,
    timeoutMs = 10_000,
    now = () => Date.now(),
  }) {
    let origin;
    try {
      origin = new URL(brokerOrigin);
    } catch {
      throw new BrowserBrokerError('invalid_configuration', 'broker origin is invalid');
    }
    if (
      origin.protocol !== 'https:' ||
      origin.username ||
      origin.password ||
      origin.pathname !== '/' ||
      origin.search ||
      origin.hash
    ) {
      throw new BrowserBrokerError(
        'invalid_configuration',
        'broker origin must be a credential-free HTTPS origin',
      );
    }
    if (typeof signer !== 'function' || typeof fetchImpl !== 'function') {
      throw new BrowserBrokerError(
        'invalid_configuration',
        'signer and fetch implementation are required',
      );
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 60_000) {
      throw new BrowserBrokerError(
        'invalid_configuration',
        'request timeout must be from 1 to 60 seconds',
      );
    }
    this.origin = origin.origin;
    this.deviceId = requireUuid(deviceId, 'device id');
    this.signer = signer;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.now = now;
  }

  async request(path, body, { allowNotFound = false } = {}) {
    const prefix = `/api/v2/devices/${this.deviceId}/browser-leases/`;
    const allowedPath =
      path === `${prefix}claim` ||
      new RegExp(
        `^${prefix}[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}/(?:otp|complete)$`,
      ).test(path);
    if (!allowedPath) {
      throw new BrowserBrokerError(
        'invalid_request',
        'worker path is outside the signed lease API',
      );
    }
    const encodedBody = canonicalJson(body);
    const timestamp = this.now();
    const nonce = randomBytes(18).toString('base64url');
    const message = canonicalDeviceMessage({
      deviceId: this.deviceId,
      timestamp,
      nonce,
      method: 'POST',
      path,
      body: encodedBody,
    });
    let signature;
    try {
      signature = await this.signer(Buffer.from(message));
    } catch {
      throw new BrowserBrokerError('signing_failed', 'workload signing failed');
    }
    if (typeof signature !== 'string' || signature.length < 32) {
      throw new BrowserBrokerError(
        'signing_failed',
        'workload signer returned an invalid signature',
      );
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    timer.unref?.();
    let response;
    try {
      response = await this.fetchImpl(`${this.origin}${path}`, {
        method: 'POST',
        redirect: 'manual',
        signal: controller.signal,
        body: encodedBody,
        headers: {
          'content-type': 'application/json',
          'x-broker-device-timestamp': String(timestamp),
          'x-broker-device-nonce': nonce,
          'x-broker-device-signature': signature,
        },
      });
    } catch {
      clearTimeout(timer);
      throw new BrowserBrokerError('broker_unavailable', 'broker request failed');
    }
    const contentLength = Number(response.headers?.get?.('content-length') || 0);
    if (contentLength > MAX_RESPONSE_BYTES) {
      clearTimeout(timer);
      await response.body?.cancel?.();
      throw new BrowserBrokerError(
        'invalid_response',
        'broker response is too large',
        response.status,
      );
    }
    let text;
    try {
      text = await response.text();
    } catch {
      clearTimeout(timer);
      throw new BrowserBrokerError(
        'invalid_response',
        'broker response body could not be read',
        response.status,
      );
    }
    clearTimeout(timer);
    if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES)
      throw new BrowserBrokerError(
        'invalid_response',
        'broker response is too large',
        response.status,
      );
    let payload = {};
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new BrowserBrokerError(
        'invalid_response',
        'broker response is not JSON',
        response.status,
      );
    }
    if (allowNotFound && response.status === 404) return null;
    if (!response.ok) {
      const code =
        typeof payload.error === 'string' && ERROR_CODE_RE.test(payload.error)
          ? payload.error
          : 'broker_rejected';
      throw new BrowserBrokerError(code, 'broker rejected the worker request', response.status);
    }
    return payload;
  }

  claim() {
    return this.request(
      `/api/v2/devices/${this.deviceId}/browser-leases/claim`,
      {},
      { allowNotFound: true },
    );
  }

  claimOtp(lease) {
    requireUuid(lease?.id, 'lease id', LEASE_ID_RE);
    return this.request(`/api/v2/devices/${this.deviceId}/browser-leases/${lease.id}/otp`, {
      receipt: lease.receipt,
    });
  }

  complete(lease, result) {
    requireUuid(lease?.id, 'lease id', LEASE_ID_RE);
    return this.request(`/api/v2/devices/${this.deviceId}/browser-leases/${lease.id}/complete`, {
      receipt: lease.receipt,
      status: 'completed',
      result,
    });
  }

  fail(lease, error) {
    requireUuid(lease?.id, 'lease id', LEASE_ID_RE);
    const errorCode =
      typeof error?.code === 'string' && ERROR_CODE_RE.test(error.code)
        ? error.code
        : 'browser_worker_failed';
    return this.request(`/api/v2/devices/${this.deviceId}/browser-leases/${lease.id}/complete`, {
      receipt: lease.receipt,
      status: 'failed',
      error_code: errorCode,
    });
  }

  async runOnce(executor) {
    if (!executor || typeof executor.execute !== 'function') {
      throw new BrowserBrokerError('invalid_configuration', 'operation executor is required');
    }
    const lease = await this.claim();
    if (!lease) return null;
    try {
      const result = await executor.execute(lease.operation, {
        claimOtp: () => this.claimOtp(lease),
      });
      return await this.complete(lease, result);
    } catch (error) {
      try {
        await this.fail(lease, error);
      } catch {
        /* preserve the execution failure */
      }
      throw error;
    }
  }
}
