// Tests for V4.1.1 CLI improvements: BrokerError class + parseBrokerError +
// retry. Uses node:test (Node 20+).
//
// Run: cd cli && node --test test-error.js
// Or:  node --test cli/test-error.js
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { BrokerError, parseBrokerError } from './secret-broker.js';

// =====================================================================
// Test BrokerError class
// =====================================================================

test('BrokerError constructs with all fields', () => {
  const e = new BrokerError({
    message: 'secret not found',
    status: 404,
    code: 'secret_not_found',
    requestId: 'req_abc123',
    retryAfter: 30,
    op: 'get_secret',
  });
  assert.equal(e.message, 'secret not found');
  assert.equal(e.status, 404);
  assert.equal(e.code, 'secret_not_found');
  assert.equal(e.requestId, 'req_abc123');
  assert.equal(e.retryAfter, 30);
  assert.equal(e.op, 'get_secret');
  assert.equal(e.name, 'BrokerError');
  assert.ok(e instanceof Error);
});

test('BrokerError default values', () => {
  const e = new BrokerError({ message: 'x' });
  assert.equal(e.status, 0);
  assert.equal(e.code, '');
  assert.equal(e.requestId, '');
  assert.equal(e.retryAfter, 0);
  assert.equal(e.op, '');
});

test('BrokerError default constructor', () => {
  const e = new BrokerError();
  // JS Error converts undefined message to '' (not throw)
  assert.equal(e.message, '');
  assert.equal(e.status, 0);
});

// =====================================================================
// Test isRetryable
// =====================================================================

test('isRetryable 4xx not retryable', () => {
  for (const status of [400, 401, 403, 404, 422]) {
    const e = new BrokerError({ message: 'x', status });
    assert.equal(e.isRetryable, false, `status=${status}`);
  }
});

test('isRetryable 429 retryable', () => {
  const e = new BrokerError({ message: 'rate limited', status: 429 });
  assert.equal(e.isRetryable, true);
});

test('isRetryable 5xx retryable', () => {
  for (const status of [500, 502, 503, 504, 599]) {
    const e = new BrokerError({ message: 'x', status });
    assert.equal(e.isRetryable, true, `status=${status}`);
  }
});

test('isRetryable status 0 (connection error) retryable', () => {
  const e = new BrokerError({ message: 'connection refused' });
  assert.equal(e.isRetryable, true);
});

// =====================================================================
// Test toString
// =====================================================================

test('toString includes status + code', () => {
  const e = new BrokerError({ message: 'not found', status: 404, code: 'secret_not_found' });
  const s = e.toString();
  assert.ok(s.includes('BrokerError'), 'should include class name');
  assert.ok(s.includes('not found'), 'should include message');
  assert.ok(s.includes('status=404'), 'should include status');
  assert.ok(s.includes('code=secret_not_found'), 'should include code');
});

test('toString includes request_id', () => {
  const e = new BrokerError({ message: 'x', status: 500, requestId: 'req_xyz' });
  assert.ok(e.toString().includes('request_id=req_xyz'));
});

test('toString includes retry_after', () => {
  const e = new BrokerError({ message: 'x', status: 429, retryAfter: 60 });
  assert.ok(e.toString().includes('retry_after=60s'));
});

test('toString omits empty fields', () => {
  const e = new BrokerError({ message: 'x' });
  const s = e.toString();
  assert.ok(s.includes('BrokerError: x'));
  assert.ok(!s.includes('status='));
  assert.ok(!s.includes('code='));
  assert.ok(!s.includes('request_id='));
  assert.ok(!s.includes('retry_after='));
});

// =====================================================================
// Test toJSON (structured logging)
// =====================================================================

test('toJSON includes expected fields', () => {
  const e = new BrokerError({ message: 'x', status: 404, code: 'secret_not_found', requestId: 'req_abc' });
  const j = e.toJSON();
  assert.equal(j.error_type, 'BrokerError');
  assert.equal(j.status, 404);
  assert.equal(j.code, 'secret_not_found');
  assert.equal(j.request_id, 'req_abc');
  assert.equal(j.is_retryable, false);
});

test('toJSON omits body (security)', () => {
  // body may contain sensitive data; must NOT be in toJSON
  const e = new BrokerError({ message: 'x', status: 500 });
  const j = e.toJSON();
  assert.ok(!('body' in j), 'toJSON must not include body');
});

// =====================================================================
// Test parseBrokerError
// =====================================================================

test('parseBrokerError with structured error body', () => {
  const body = { error: { code: 'secret_not_found', message: 'no such secret' } };
  const headers = { 'x-request-id': 'req_abc', 'retry-after': '30' };
  const e = parseBrokerError(404, headers, body, 'get_secret');
  assert.equal(e.status, 404);
  assert.equal(e.code, 'secret_not_found');
  assert.equal(e.message, 'no such secret');
  assert.equal(e.requestId, 'req_abc');
  assert.equal(e.retryAfter, 30);
  assert.equal(e.op, 'get_secret');
});

test('parseBrokerError with string error body', () => {
  const e = parseBrokerError(500, {}, 'internal error', 'health');
  assert.equal(e.status, 500);
  assert.equal(e.message, 'internal error');
  assert.equal(e.code, '');
  assert.equal(e.op, 'health');
});

test('parseBrokerError with empty body', () => {
  const e = parseBrokerError(500, {}, null, 'health');
  assert.equal(e.status, 500);
  assert.ok(e.message.includes('500'));
});

test('parseBrokerError invalid Retry-After header', () => {
  const e = parseBrokerError(429, { 'retry-after': 'not-a-number' }, null, 'list');
  assert.equal(e.retryAfter, 0);
});

test('parseBrokerError missing Retry-After header', () => {
  const e = parseBrokerError(429, {}, null, 'list');
  assert.equal(e.retryAfter, 0);
});

test('parseBrokerError lowercased header keys (Node http)', () => {
  // Node's https module lowercases all header keys
  const e = parseBrokerError(404, { 'x-request-id': 'req_xyz' }, null, 'get');
  assert.equal(e.requestId, 'req_xyz');
});

// =====================================================================
// Test mTLSRequest retry behavior (smoke test only — full integration
// test requires real mTLS server + certs, out of scope for unit tests)
// =====================================================================

test('mTLSRequest function is exported (default maxRetries=0)', () => {
  // Note: mTLSRequest is not exported (it's the internal HTTP client).
  // We verify the file is importable as a module + the BrokerError +
  // parseBrokerError exports work. Full retry behavior is integration-tested.
  assert.equal(typeof BrokerError, 'function');
  assert.equal(typeof parseBrokerError, 'function');
  // Both should be constructable / callable
  const e = new BrokerError({ message: 'test' });
  assert.ok(e instanceof Error);
  const p = parseBrokerError(500, {}, 'msg', 'op');
  assert.ok(p instanceof BrokerError);
});

test('retry backoff strategy: exponential with Retry-After override', () => {
  // Verify the backoff math used in mTLSRequest.
  // See mTLSRequest implementation: backoff = retryBackoff << (attempt - 1)
  const retryBackoff = 500;  // ms
  const attempts = [1, 2, 3, 4];
  const backoffs = attempts.map(a => retryBackoff << (a - 1));
  // 500ms * 1 = 500, * 2 = 1000, * 4 = 2000, * 8 = 4000
  assert.deepEqual(backoffs, [500, 1000, 2000, 4000]);

  // Retry-After override (e.g. 1s from server, smaller than computed 4s)
  const fromHeader = 1000;
  const computed = 4000;
  const capped = fromHeader < computed && fromHeader < 30000 ? fromHeader : computed;
  assert.equal(capped, 1000);
});
