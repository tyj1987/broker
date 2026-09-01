// Unit tests for VS Code extension client.
// Run: cd sdk/vscode && npm run build && node ./out/test/run.js
import * as assert from 'node:assert';
import * as https from 'node:https';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { BrokerClient, redact, BrokerError, BrokerConnectionError } from '../client';

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
// Redact tests
// ============================================================
console.log('\n[redact]');
test('redacts GitHub PAT', () => {
  const s = 'Authorization: Bearer ghp_xxxxABCDEFGHIJabcdefghij';
  const out = redact(s);
  assert.ok(!out.includes('ghp_xxxxABCDEFGHIJ'));
  assert.ok(out.includes('REDACTED'));
});
test('redacts OpenAI sk-', () => {
  const s = 'openai key=sk-abcdefghijklmnopqrstuvwxyz';
  const out = redact(s);
  assert.ok(!out.includes('sk-abcdef'));
  assert.ok(out.includes('REDACTED'));
});
test('redacts AWS AKIA', () => {
  const s = 'access key AKIAIOSFODNN7EXAMPLE found';
  const out = redact(s);
  assert.ok(!out.includes('AKIAIOSFODNN7EXAMPLE'));
});
test('redacts JWT', () => {
  const s = 'token: eyJAbcdefghijklmnop.eyJqrstuvwxyzABCDEFG.eyJqrstuvwxyzABCDEFG';
  const out = redact(s);
  assert.ok(!out.includes('eyJAbcdefghijklmnop'));
});
test('preserves non-credential text', () => {
  const s = 'Hello world, this is a normal log line';
  assert.strictEqual(redact(s), s);
});
test('handles empty string', () => {
  assert.strictEqual(redact(''), '');
});

// ============================================================
// Client validation
// ============================================================
console.log('\n[client validation]');
test('rejects http endpoint', () => {
  let threw = false;
  try { new BrokerClient({ endpoint: 'http://insecure', clientCert: '', clientKey: '', caCert: '' }); }
  catch (e) { threw = /must be https/.test(String(e)); }
  assert.ok(threw);
});
test('rejects empty endpoint', () => {
  let threw = false;
  try { new BrokerClient({ endpoint: '', clientCert: '', clientKey: '', caCert: '' }); }
  catch (e) { threw = /endpoint required/.test(String(e)); }
  assert.ok(threw);
});

// ============================================================
// Error type
// ============================================================
console.log('\n[errors]');
test('BrokerError carries status and body', () => {
  const e = new BrokerError('test', 403, '{"error":"forbidden"}');
  assert.strictEqual(e.op, 'test');
  assert.strictEqual(e.status, 403);
  assert.ok(e.body.includes('forbidden'));
  assert.ok(e.message.includes('403'));
});
test('BrokerConnectionError wraps cause', () => {
  const cause = new Error('ECONNREFUSED');
  const e = new BrokerConnectionError('test_op', cause);
  assert.ok(e.message.includes('test_op'));
  assert.ok(e.message.includes('ECONNREFUSED'));
});

// ============================================================
// Integration (live HTTPS mock)
// ============================================================
console.log('\n[integration]');
test('mock broker: health + get + list', async () => {
  const { startMockBroker } = await import('./mock_broker');
  const m = startMockBroker();
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '',
      clientKey: '',
      caCert: m.certPath,
      verifyTls: true,
    });
    const h = await c.health();
    assert.strictEqual(h.ok, true);
    assert.ok(typeof h.version === 'string');
    const v = await c.getSecret('github.pat');
    assert.strictEqual(v, 'ghp_xxxxABCDEFGHIJabcdefghij');
    const items = await c.list();
    assert.ok(items.length > 0);
  } finally {
    m.stop();
  }
});

test('mock broker: 404 surfaces as BrokerError', async () => {
  const { startMockBroker } = await import('./mock_broker');
  const m = startMockBroker();
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '',
      clientKey: '',
      caCert: m.certPath,
      verifyTls: true,
    });
    let threw = false;
    try { await c.getSecret('does-not-exist'); }
    catch (e) {
      threw = e instanceof BrokerError && e.status === 404;
    }
    assert.ok(threw);
  } finally {
    m.stop();
  }
});

test('mock broker: 403 surfaces as BrokerError', async () => {
  const { startMockBroker } = await import('./mock_broker');
  const m = startMockBroker();
  try {
    const c = new BrokerClient({
      endpoint: `https://127.0.0.1:${m.port}`,
      clientCert: '',
      clientKey: '',
      caCert: m.certPath,
      verifyTls: true,
    });
    let threw = false;
    try { await c.proxy('github', 'GET', '/forbidden'); }
    catch (e) {
      threw = e instanceof BrokerError && e.status === 403;
    }
    assert.ok(threw);
  } finally {
    m.stop();
  }
});

test('connection error when broker unreachable', async () => {
  const c = new BrokerClient({
    endpoint: 'https://127.0.0.1:1',  // port 1 = closed
    clientCert: '', clientKey: '', caCert: '',
  });
  let threw = false;
  try { await c.health(); }
  catch (e) { threw = e instanceof BrokerConnectionError; }
  assert.ok(threw);
});

// ============================================================
setTimeout(() => {
  console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}, 500);
