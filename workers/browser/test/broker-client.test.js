import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import test from 'node:test';
import {
  BrowserBrokerClient,
  BrowserBrokerError,
  canonicalDeviceMessage,
} from '../src/broker-client.js';

const deviceId = '00000000-0000-4000-8000-000000000001';
const leaseId = '00000000-0000-4000-8000-000000000002';
const keys = generateKeyPairSync('ed25519');

function response(status, body) {
  const text = JSON.stringify(body);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => String(Buffer.byteLength(text)) },
    async text() {
      return text;
    },
  };
}

test('signs the exact method, path and canonical body without redirects', async () => {
  let captured;
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    now: () => 1234,
    signer: async (message) => sign(null, message, keys.privateKey).toString('base64url'),
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(404, { error: 'not_found' });
    },
  });
  assert.equal(await client.claim(), null);
  assert.equal(
    captured.url,
    `https://broker.example.test/api/v2/devices/${deviceId}/browser-leases/claim`,
  );
  assert.equal(captured.options.redirect, 'manual');
  assert.equal(captured.options.body, '{}');
  const nonce = captured.options.headers['x-broker-device-nonce'];
  const message = canonicalDeviceMessage({
    deviceId,
    timestamp: 1234,
    nonce,
    method: 'POST',
    path: `/api/v2/devices/${deviceId}/browser-leases/claim`,
    body: '{}',
  });
  assert.equal(
    verify(
      null,
      Buffer.from(message),
      keys.publicKey,
      Buffer.from(captured.options.headers['x-broker-device-signature'], 'base64url'),
    ),
    true,
  );
});

test('runs one lease and returns only the broker completion', async () => {
  const calls = [];
  const lease = {
    id: leaseId,
    receipt: 'r'.repeat(43),
    operation: {
      provider: 'aliyun',
      operation_id: 'account.summary',
      account_ref: 'primary',
      environment: 'staging',
      typed_parameters: {},
    },
  };
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async (url, options) => {
      calls.push([url, JSON.parse(options.body)]);
      if (url.endsWith('/claim')) return response(200, lease);
      return response(200, { id: 'operation-id', status: 'completed' });
    },
  });
  const result = await client.runOnce({
    async execute(operation) {
      assert.equal(operation.provider, 'aliyun');
      return { records: 1 };
    },
  });
  assert.equal(result.status, 'completed');
  assert.deepEqual(calls[1][1], {
    receipt: lease.receipt,
    status: 'completed',
    result: { records: 1 },
  });
});

test('provides one bound OTP callback to the adapter', async () => {
  const calls = [];
  const lease = { id: leaseId, receipt: 'r'.repeat(43), operation: { provider: 'aliyun' } };
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async (url, options) => {
      calls.push([url, JSON.parse(options.body)]);
      if (url.endsWith('/claim')) return response(200, lease);
      if (url.endsWith('/otp')) return response(200, { code: '123456' });
      return response(200, { status: 'completed' });
    },
  });
  await client.runOnce({
    async execute(_operation, runtime) {
      return { used: (await runtime.claimOtp()).code.length };
    },
  });
  assert.ok(calls[1][0].endsWith(`/${leaseId}/otp`));
  assert.deepEqual(calls[1][1], { receipt: lease.receipt });
});

test('cancels an in-flight OTP exchange with the operation signal', async () => {
  const operation = new AbortController();
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async (_url, options) => new Promise((_, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    }),
  });
  const pending = client.claimOtp(
    { id: leaseId, receipt: 'r'.repeat(43) },
    { signal: operation.signal },
  );
  operation.abort();
  await assert.rejects(
    pending,
    (error) => error instanceof BrowserBrokerError && error.code === 'request_cancelled',
  );
});

test('reports a sanitized failure without sending exception messages', async () => {
  const bodies = [];
  const lease = { id: leaseId, receipt: 'r'.repeat(43), operation: {} };
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async (url, options) => {
      bodies.push(JSON.parse(options.body));
      return url.endsWith('/claim') ? response(200, lease) : response(200, { status: 'failed' });
    },
  });
  const failure = Object.assign(new Error('page contained secret-value'), { code: 'page_changed' });
  await assert.rejects(
    () =>
      client.runOnce({
        async execute() {
          throw failure;
        },
      }),
    failure,
  );
  assert.deepEqual(bodies[1], {
    receipt: lease.receipt,
    status: 'failed',
    error_code: 'page_changed',
  });
  assert.equal(JSON.stringify(bodies).includes('secret-value'), false);
});

test('rejects unsafe origins, paths, oversized responses and redirects', async () => {
  assert.throws(
    () => new BrowserBrokerClient({ brokerOrigin: 'http://broker.test', deviceId, signer() {} }),
    BrowserBrokerError,
  );
  const client = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async () => response(302, { error: 'redirect' }),
  });
  await assert.rejects(
    () => client.request('https://evil.test/', {}),
    (error) => error.code === 'invalid_request',
  );
  await assert.rejects(
    () => client.request(`/api/v2/devices/${deviceId}/browser-leases/../otp`, {}),
    (error) => error.code === 'invalid_request',
  );
  await assert.rejects(
    () => client.claim(),
    (error) => error.code === 'redirect',
  );
  const oversized = new BrowserBrokerClient({
    brokerOrigin: 'https://broker.example.test',
    deviceId,
    signer: async () => 's'.repeat(64),
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      headers: { get: () => String(200_000) },
      async text() {
        throw new Error('must not read');
      },
    }),
  });
  await assert.rejects(
    () => oversized.claim(),
    (error) => error.code === 'invalid_response',
  );
});
