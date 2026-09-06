// V4.1.1 unit tests for BrokerError + parseBrokerError + mtlsRequest retry.
// Run: cd sdk/vscode && npm run build && node ./out/test/error.test.js
//
// Parity with Python SDK (test_exceptions.py 26 tests) + Go SDK (errors_test.go 19 tests)
// + CLI SDK (test-error.js 21 tests).

import * as assert from 'node:assert';
import * as https from 'node:https';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { BrokerClient, BrokerError, BrokerConnectionError, parseBrokerError, redact } from '../client';

let pass = 0, fail = 0;
function test(name: string, fn: () => void | Promise<void>): void {
  (async () => {
    try {
      await fn();
      pass++;
      console.log(`  PASS  ${name}`);
    } catch (e) {
      fail++;
      console.error(`  FAIL  ${name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  })();
}

// ============================================================
// BrokerError — field tests
// ============================================================
console.log('\n[BrokerError fields]');
test('basic construction: op + status + body + message', () => {
  const e = new BrokerError('test', 403, '{"error":"forbidden"}');
  assert.strictEqual(e.op, 'test');
  assert.strictEqual(e.status, 403);
  assert.ok(e.body.includes('forbidden'));
  assert.ok(e.message.includes('403'));
  assert.strictEqual(e.name, 'BrokerError');
});
test('V4.1.1: code field from options', () => {
  const e = new BrokerError('get_secret', 401, '', undefined, { code: 'auth_failed' });
  assert.strictEqual(e.code, 'auth_failed');
});
test('V4.1.1: requestId field from options', () => {
  const e = new BrokerError('get_secret', 500, '', undefined, { requestId: 'req-abc-123' });
  assert.strictEqual(e.requestId, 'req-abc-123');
});
test('V4.1.1: retryAfter field from options', () => {
  const e = new BrokerError('get_secret', 429, '', undefined, { retryAfter: 30 });
  assert.strictEqual(e.retryAfter, 30);
});
test('V4.1.1: defaults (no options) → empty code/requestId, 0 retryAfter', () => {
  const e = new BrokerError('op', 500, 'body');
  assert.strictEqual(e.code, '');
  assert.strictEqual(e.requestId, '');
  assert.strictEqual(e.retryAfter, 0);
});
test('V4.1.1: body is redacted in storage', () => {
  const e = new BrokerError('get', 500, 'ghp_xxxxABCDEFGHIJabcdefghij leaked');
  assert.ok(e.body.includes('REDACTED'));
  assert.ok(!e.body.includes('ghp_xxxxABCDEFGHIJabcdefghij'));
});

// ============================================================
// BrokerError — isRetryable getter
// ============================================================
console.log('\n[BrokerError.isRetryable]');
test('isRetryable: 429 → true (rate limit)', () => {
  const e = new BrokerError('op', 429, '');
  assert.strictEqual(e.isRetryable, true);
});
test('isRetryable: 500 → true', () => {
  const e = new BrokerError('op', 500, '');
  assert.strictEqual(e.isRetryable, true);
});
test('isRetryable: 502 → true (bad gateway)', () => {
  const e = new BrokerError('op', 502, '');
  assert.strictEqual(e.isRetryable, true);
});
test('isRetryable: 503 → true (unavailable)', () => {
  const e = new BrokerError('op', 503, '');
  assert.strictEqual(e.isRetryable, true);
});
test('isRetryable: 400 → false (bad request)', () => {
  const e = new BrokerError('op', 400, '');
  assert.strictEqual(e.isRetryable, false);
});
test('isRetryable: 401 → false (auth)', () => {
  const e = new BrokerError('op', 401, '');
  assert.strictEqual(e.isRetryable, false);
});
test('isRetryable: 403 → false (forbidden)', () => {
  const e = new BrokerError('op', 403, '');
  assert.strictEqual(e.isRetryable, false);
});
test('isRetryable: 404 → false (not found)', () => {
  const e = new BrokerError('op', 404, '');
  assert.strictEqual(e.isRetryable, false);
});

// ============================================================
// BrokerError — toString + toJSON
// ============================================================
console.log('\n[BrokerError formatting]');
test('toString: includes status + code + requestId + retryAfter', () => {
  const e = new BrokerError('get_secret', 429, '', undefined, {
    code: 'rate_limited', requestId: 'req-xyz', retryAfter: 60,
  });
  const s = e.toString();
  assert.ok(s.includes('status=429'));
  assert.ok(s.includes('code=rate_limited'));
  assert.ok(s.includes('request_id=req-xyz'));
  assert.ok(s.includes('retry_after=60s'));
});
test('toString: minimal fields when only status set', () => {
  const e = new BrokerError('op', 500, 'body');
  const s = e.toString();
  assert.ok(s.includes('status=500'));
  assert.ok(!s.includes('code='));
  assert.ok(!s.includes('request_id='));
});
test('toJSON: structured output, body omitted', () => {
  const e = new BrokerError('get_secret', 401, 'should-not-leak', undefined, {
    code: 'auth_failed', requestId: 'req-1',
  });
  const j = e.toJSON();
  assert.strictEqual(j.error_type, 'BrokerError');
  assert.strictEqual(j.op, 'get_secret');
  assert.strictEqual(j.status, 401);
  assert.strictEqual(j.code, 'auth_failed');
  assert.strictEqual(j.request_id, 'req-1');
  assert.strictEqual(j.is_retryable, false);
  assert.ok(!('body' in j), 'toJSON must NOT include body field');
});

// ============================================================
// parseBrokerError factory
// ============================================================
console.log('\n[parseBrokerError]');
test('parseBrokerError: object body with error.code + error.message', () => {
  const e = parseBrokerError(401, { 'x-request-id': 'req-1' }, {
    error: { code: 'auth_failed', message: 'bad creds' },
  }, 'login');
  assert.strictEqual(e.status, 401);
  assert.strictEqual(e.code, 'auth_failed');
  assert.strictEqual(e.requestId, 'req-1');
  assert.ok(e.message.includes('bad creds'));
  assert.strictEqual(e.op, 'login');
});
test('parseBrokerError: object body with string error', () => {
  const e = parseBrokerError(500, {}, { error: 'oops' }, 'op');
  assert.ok(e.message.includes('oops'));
});
test('parseBrokerError: top-level message field', () => {
  const e = parseBrokerError(400, {}, { message: 'bad input' }, 'op');
  assert.ok(e.message.includes('bad input'));
});
test('parseBrokerError: top-level code field', () => {
  const e = parseBrokerError(403, {}, { code: 'forbidden' }, 'op');
  assert.strictEqual(e.code, 'forbidden');
});
test('parseBrokerError: string body', () => {
  const e = parseBrokerError(500, {}, 'plain text error', 'op');
  assert.ok(e.message.includes('plain text error'));
});
test('parseBrokerError: null body', () => {
  const e = parseBrokerError(500, {}, null, 'op');
  assert.strictEqual(e.status, 500);
  assert.strictEqual(e.code, '');
});
test('parseBrokerError: empty body', () => {
  const e = parseBrokerError(404, {}, '', 'op');
  assert.strictEqual(e.status, 404);
  assert.ok(e.message.includes('HTTP 404'));
});
test('parseBrokerError: retry-after header parsed to seconds', () => {
  const e = parseBrokerError(429, { 'retry-after': '120' }, {}, 'op');
  assert.strictEqual(e.retryAfter, 120);
});
test('parseBrokerError: body is redacted', () => {
  const e = parseBrokerError(500, {}, { secret: 'ghp_xxxxABCDEFGHIJabcdefghij' }, 'op');
  assert.ok(e.body.includes('REDACTED'));
  assert.ok(!e.body.includes('ghp_xxxxABCDEFGHIJabcdefghij'));
});

// ============================================================
// BrokerConnectionError
// ============================================================
console.log('\n[BrokerConnectionError]');
test('BrokerConnectionError: wraps cause', () => {
  const cause = new Error('ECONNREFUSED');
  const e = new BrokerConnectionError('test_op', cause);
  assert.ok(e.message.includes('test_op'));
  assert.ok(e.message.includes('ECONNREFUSED'));
  assert.strictEqual(e.op, 'test_op');
  assert.strictEqual(e.cause, cause);
  assert.strictEqual(e.isRetryable, true);
});
test('BrokerConnectionError: stores requestId', () => {
  const cause = new Error('ETIMEDOUT');
  const e = new BrokerConnectionError('op', cause, 'req-123');
  assert.strictEqual(e.requestId, 'req-123');
});
test('BrokerConnectionError: toString includes requestId when set', () => {
  const cause = new Error('boom');
  const e = new BrokerConnectionError('op', cause, 'req-9');
  assert.ok(e.toString().includes('request_id=req-9'));
});
test('BrokerConnectionError: toJSON reports is_retryable: true', () => {
  const cause = new Error('ECONNRESET');
  const e = new BrokerConnectionError('op', cause);
  const j = e.toJSON();
  assert.strictEqual(j.is_retryable, true);
  assert.strictEqual(j.cause, 'ECONNRESET');
});

// ============================================================
// Integration: live retry via mock broker
// ============================================================
console.log('\n[mtlsRequest retry]');

// Build a flappy mock broker that fails N times then succeeds
async function startFlappyBroker(failuresBeforeSuccess: number, failStatus: number = 503): Promise<{ port: number; certPath: string; stop: () => void }> {
  let attempts = 0;
  const certs = generateSelfSigned();
  const server = https.createServer(
    { cert: certs.certPem, key: certs.keyPem },
    (req, res) => {
      attempts++;
      if (attempts <= failuresBeforeSuccess) {
        res.writeHead(failStatus, { 'content-type': 'application/json', 'x-request-id': 'req-fail' });
        res.end(JSON.stringify({ error: { code: 'unavailable', message: 'try again' } }));
      } else {
        res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': 'req-ok' });
        res.end(JSON.stringify({ ok: true, version: '4.1.1' }));
      }
    }
  );
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('server.address() returned no port'));
    });
  });
  return {
    port,
    certPath: certs.certPath,
    stop: () => { server.close(); },
  };
}

function generateSelfSigned() {
  // Try PATH first, then common fallbacks (Git for Windows, etc.)
  const candidates: string[] = [];
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['openssl'], { encoding: 'utf8' });
  if ((which.status ?? 0) === 0) {
    candidates.push('openssl');
  }
  if (process.platform === 'win32') {
    const fallbacks = [
      'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
      'C:\\Program Files (x86)\\Git\\mingw64\\bin\\openssl.exe',
      'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe',
    ];
    for (const fb of fallbacks) if (fs.existsSync(fb)) candidates.push(fb);
  }
  if (candidates.length === 0) throw new Error('openssl not on PATH and no fallback found');
  const opensslBin = candidates[0];

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-vscode-flap-'));
  const certPath = path.join(tmp, 'cert.pem');
  const keyPath = path.join(tmp, 'key.pem');
  spawnSync(opensslBin, [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1',
  ], { encoding: 'utf8' });
  return {
    certPem: fs.readFileSync(certPath, 'utf8'),
    keyPem: fs.readFileSync(keyPath, 'utf8'),
    certPath, keyPath,
  };
}

test('mtlsRequest: success on first try (no retry)', async () => {
  const m = await startFlappyBroker(0);
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '', clientKey: '', caCert: m.certPath,
      verifyTls: true, maxRetries: 3, retryBackoffMs: 10,
    });
    const h = await c.health();
    assert.strictEqual(h.ok, true);
    assert.strictEqual(h.version, '4.1.1');
  } finally { m.stop(); }
});

test('mtlsRequest: 503 → 200 (retries once, then succeeds)', async () => {
  const m = await startFlappyBroker(1, 503);
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '', clientKey: '', caCert: m.certPath,
      verifyTls: true, maxRetries: 3, retryBackoffMs: 10,
    });
    const h = await c.health();
    assert.strictEqual(h.ok, true);
  } finally { m.stop(); }
});

test('mtlsRequest: 500 → 500 → 200 (retries twice, then succeeds)', async () => {
  const m = await startFlappyBroker(2, 500);
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '', clientKey: '', caCert: m.certPath,
      verifyTls: true, maxRetries: 3, retryBackoffMs: 10,
    });
    const h = await c.health();
    assert.strictEqual(h.ok, true);
  } finally { m.stop(); }
});

test('mtlsRequest: 4 failures (max 3 retries) → final BrokerError', async () => {
  const m = await startFlappyBroker(99, 503);
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '', clientKey: '', caCert: m.certPath,
      verifyTls: true, maxRetries: 3, retryBackoffMs: 10,
    });
    let threw: BrokerError | null = null;
    try { await c.health(); } catch (e) { if (e instanceof BrokerError) threw = e; }
    assert.ok(threw, 'expected BrokerError after exhausting retries');
    assert.strictEqual(threw!.status, 503);
    assert.strictEqual(threw!.isRetryable, true);
  } finally { m.stop(); }
});

test('mtlsRequest: 4xx error is NOT retried (instant throw)', async () => {
  // Inline mock: returns 403 on /forbidden, 200 on /ok
  // (avoids mock_broker.ts module-level state that races with other tests)
  const certs = generateSelfSigned();
  const server = https.createServer(
    { cert: certs.certPem, key: certs.keyPem },
    (req, res) => {
      const url = req.url || '/';
      if (url.includes('/forbidden')) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 'forbidden', message: 'nope' } }));
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      }
    }
  );
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('no port'));
    });
  });
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${port}`,
      clientCert: '', clientKey: '', caCert: certs.certPath,
      verifyTls: true, maxRetries: 3, retryBackoffMs: 10,
    });
    let threw: BrokerError | null = null;
    try { await c.proxy('github', 'GET', '/forbidden'); }
    catch (e) { if (e instanceof BrokerError) threw = e; }
    assert.ok(threw, 'expected BrokerError on 403');
    assert.strictEqual(threw!.status, 403);
    assert.strictEqual(threw!.isRetryable, false);
    assert.strictEqual(threw!.code, 'forbidden');
  } finally { server.close(); }
});

test('mtlsRequest: maxRetries=0 disables retry', async () => {
  const m = await startFlappyBroker(99, 503);
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '', clientKey: '', caCert: m.certPath,
      verifyTls: true, maxRetries: 0, retryBackoffMs: 10,
    });
    let threw: BrokerError | null = null;
    try { await c.health(); } catch (e) { if (e instanceof BrokerError) threw = e; }
    assert.ok(threw);
    assert.strictEqual(threw!.status, 503);
  } finally { m.stop(); }
});

test('mtlsRequest: connection refused → BrokerConnectionError (no retry against dead port)', async () => {
  const c = new BrokerClient({
    endpoint: 'https://127.0.0.1:1', // port 1 = closed
    clientCert: '', clientKey: '', caCert: '',
    maxRetries: 1, retryBackoffMs: 10,
  });
  let threw: BrokerConnectionError | null = null;
  try { await c.health(); } catch (e) { if (e instanceof BrokerConnectionError) threw = e; }
  assert.ok(threw, 'expected BrokerConnectionError');
  assert.strictEqual(threw!.isRetryable, true);
});

test('mtlsRequest: honors Retry-After header on 429', async () => {
  // Mock broker returns 429 with retry-after: 1 (second)
  const certs = generateSelfSigned();
  let attempts = 0;
  const server = https.createServer(
    { cert: certs.certPem, key: certs.keyPem },
    (req, res) => {
      attempts++;
      if (attempts === 1) {
        res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '1' });
        res.end(JSON.stringify({ error: { code: 'rate_limited' } }));
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, version: '4.1.1' }));
      }
    }
  );
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') resolve(addr.port);
      else reject(new Error('server.address() returned no port'));
    });
  });
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${port}`,
      clientCert: '', clientKey: '', caCert: certs.certPath,
      verifyTls: true, maxRetries: 2, retryBackoffMs: 10,
    });
    const startTime = Date.now();
    const h = await c.health();
    const elapsed = Date.now() - startTime;
    assert.strictEqual(h.ok, true);
    // Should have waited at least ~1000ms (Retry-After=1s, not 10ms*2=20ms backoff)
    assert.ok(elapsed >= 900, `expected ~1s wait, got ${elapsed}ms`);
  } finally { server.close(); }
});

// ============================================================
setTimeout(() => {
  console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}, 5000);
