#!/usr/bin/env node
// Example: V4.1.1 SDK error handling (Node CLI / mavis / AI agents).
//
// Run:
//   node examples/v4.1.1-error-handling.mjs
//
// Requires:
//   - broker running on https://127.0.0.1:8443
//   - pki setup: secrets/clients.json + pki/{ca.crt, clients/admin.{crt,key}}
//
// Note: This example is documentation / template code. It does not actually
// call a live broker — the broker is offline in dev. See README for setup.

import { BrokerClient, BrokerError, BrokerConnectionError, parseBrokerError } from '../secret-broker.js';

// === 1. Construct client with V4.1.1 retry config ===
const c = new BrokerClient({
  endpoint: 'https://127.0.0.1:8443',
  caCert: '../../pki/ca.crt',
  clientCert: '../../pki/clients/admin.crt',
  clientKey: '../../pki/clients/admin.key',
  // V4.1.1: built-in retry (defaults: maxRetries=2, retryBackoffMs=500)
  maxRetries: 3,        // retry up to 3 times (4 total attempts)
  retryBackoffMs: 1000, // start with 1s, doubled each retry (1s → 2s → 4s)
});

// === 2. Call surface and catch V4.1.1 errors ===
try {
  const secret = await c.getSecret('github.pat');
  console.log(`Got secret: ${secret.slice(0, 8)}...`);
} catch (e) {
  if (e instanceof BrokerError) {
    // V4.1.1: single BrokerError, regardless of HTTP status.
    // Check status / code / isRetryable to branch.
    console.log(`broker error: ${e}`);
    console.log(`  status     = ${e.status}`);
    console.log(`  code       = ${JSON.stringify(e.code)}`);
    console.log(`  request_id = ${JSON.stringify(e.requestId)}`);
    console.log(`  retry_after= ${e.retryAfter}s`);
    console.log(`  is_retryable = ${e.isRetryable}`);
    // V4.1.1: body auto-redacted on construction; safe to log
    console.log(`  body       = ${e.body}`);

    if (e.status === 401 || e.code === 'auth_failed') {
      console.log('  → auth failed, re-login required');
    } else if (e.status === 404 || e.code === 'not_found') {
      console.log('  → secret not found, check name');
    } else if (e.isRetryable) {
      // SDK already retried up to maxRetries; this is the final attempt
      console.log(`  → retryable, last attempt after ${e.retryAfter}s wait`);
    } else {
      console.log('  → permanent error, do not retry');
    }
  } else if (e instanceof BrokerConnectionError) {
    // V4.1.1: separate class for network-level failures (always retryable)
    console.log(`connection failed: ${e}`);
    console.log(`  op        = ${e.op}`);
    console.log(`  cause     = ${e.cause}`);
    console.log(`  request_id= ${e.requestId}`);
    // SDK already retried; surface for ops team.
  } else {
    throw e;
  }
}

// === 3. parseBrokerError factory (V4.1.1 new) ===
// Useful for middleware that needs to convert raw responses to typed errors
// without actually making a request.
const err = parseBrokerError(
  429,
  { 'x-request-id': 'req-abc-123', 'retry-after': '30' },
  { error: { code: 'rate_limited', message: 'slow down' } },
  'get_secret'
);

console.log(`\nfactory example: ${err}`);
console.log(`  status=${err.status} code=${JSON.stringify(err.code)} request_id=${JSON.stringify(err.requestId)} retry_after=${err.retryAfter}s is_retryable=${err.isRetryable}`);

// === 4. toString() + toJSON() (V4.1.1 new) ===
console.log(`toString: ${err.toString()}`);
const json = err.toJSON();
if ('body' in json) {
  throw new Error('toJSON() must omit body (may contain secrets)');
}
console.log(`toJSON: ${JSON.stringify(json, null, 2)}`);

// === 5. When NOT to use V4.1.1 retry (maxRetries=0) ===
// If you have your own retry logic, disable SDK retry to avoid double-retry.
const cNoRetry = new BrokerClient({
  endpoint: 'https://127.0.0.1:8443',
  caCert: '../../pki/ca.crt',
  maxRetries: 0, // SDK does not retry; your code handles it
});

// === 6. Migrating from V4.1.0 6-class model ===
// If you had:
//   if (e instanceof BrokerAuthError) { ... }
// V4.1.1 equivalent:
//   if (e instanceof BrokerError && e.status === 401) { ... }
//
// The old classes (BrokerAuthError, BrokerPermissionError, etc.) are
// still exported in V4.1.1 for one release, but emit DeprecationWarning
// on import. Plan to migrate to BrokerError + status/code checks before
// V4.2.0 (Q2 2027).
