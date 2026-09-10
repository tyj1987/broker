// broker-test/test-phase-d-trace-audit.js
import {
  parseTraceparent,
  continueOrCreateTrace,
  outboundTraceHeaders,
  resolveRequestId,
  newTraceId,
} from '../broker/lib/trace.js';
import {
  runWithRequestContext,
  getRequestId,
  getTraceparent,
  getRequestContext,
} from '../broker/lib/request-context.js';
import {
  shouldSampleAudit,
  withAuditSampling,
  pruneAuditFiles,
  auditPolicyFromEnv,
} from '../broker/lib/audit-policy.js';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BROKER_VERSION } from '../broker/version.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== version ===');
assert(typeof BROKER_VERSION === 'string' && /^\d+\.\d+\.\d+/.test(BROKER_VERSION), `version=${BROKER_VERSION}`);

console.log('=== parseTraceparent ===');
{
  const p = parseTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
  assert(p && p.traceId.startsWith('4bf92f35'), 'parse');
  assert(parseTraceparent('bad') === null, 'bad');
  assert(parseTraceparent('00-' + '0'.repeat(32) + '-00f067aa0ba902b7-01') === null, 'zero trace');
}

console.log('=== continueOrCreateTrace ===');
{
  const root = continueOrCreateTrace(undefined);
  assert(root.traceId.length === 32 && root.spanId.length === 16, 'root ids');
  assert(root.traceparent.startsWith('00-'), 'tp');
  const child = continueOrCreateTrace(root.traceparent);
  assert(child.traceId === root.traceId, 'same trace');
  assert(child.spanId !== root.spanId, 'new span');
  const out = outboundTraceHeaders({ ...child, requestId: 'abc' });
  assert(out.traceparent && out['x-request-id'] === 'abc', 'outbound');
}

console.log('=== resolveRequestId ===');
{
  assert(resolveRequestId({ 'x-request-id': 'r1' }) === 'r1', 'x-request-id');
  assert(resolveRequestId({}).length === 32, 'generated');
  const injected = 'Bearer ' + 'Z'.repeat(40);
  const replacement = resolveRequestId({ 'x-request-id': injected });
  assert(replacement !== injected && /^[a-f0-9]{32}$/.test(replacement), 'unsafe request id replaced');
  assert(resolveRequestId({ 'x-request-id': 'comma,value' }) !== 'comma', 'ambiguous request id replaced');
}

console.log('=== request context ALS ===');
{
  let seen;
  runWithRequestContext({ 'x-request-id': 'req-9', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' }, () => {
    seen = getRequestContext();
    assert(getRequestId() === 'req-9', 'req id');
    assert(getTraceparent().includes('4bf92f3577b34da6'), 'tp in ctx');
  });
  assert(seen.traceId === '4bf92f3577b34da6a3ce929d0e0e4736', 'ctx trace');
  assert(getRequestId() === undefined, 'cleared outside');
}

console.log('=== audit sampling ===');
{
  assert(shouldSampleAudit({ action: 'login' }, { sampleRate: 0 }) === true, 'always login');
  assert(shouldSampleAudit({ action: 'ping' }, { sampleRate: 0 }) === false, 'drop ping');
  assert(shouldSampleAudit({ action: 'ping', status: 'denied' }, { sampleRate: 0 }) === true, 'denied');
  let calls = 0;
  const wrapped = withAuditSampling((e) => { calls++; return e; }, { sampleRate: 0, alwaysActions: ['login'] });
  wrapped({ action: 'ping' });
  wrapped({ action: 'login' });
  assert(calls === 1, 'sampled wrap');
}

console.log('=== pruneAuditFiles ===');
{
  const dir = mkdtempSync(join(tmpdir(), 'broker-audit-test-'));
  writeFileSync(join(dir, 'audit-2020-01-01.jsonl'), '{}\n');
  writeFileSync(join(dir, 'audit-2099-01-01.jsonl'), '{}\n');
  const r = pruneAuditFiles(dir, 30);
  assert(r.deleted.includes('audit-2020-01-01.jsonl'), 'deleted old');
  assert(r.kept.includes('audit-2099-01-01.jsonl'), 'kept new');
  assert(!existsSync(join(dir, 'audit-2020-01-01.jsonl')), 'gone');
  rmSync(dir, { recursive: true, force: true });
}

console.log('=== policy from env ===');
{
  const p = auditPolicyFromEnv({ AUDIT_SAMPLE_RATE: '0.5', AUDIT_RETAIN_DAYS: '7' });
  assert(p.sampleRate === 0.5 && p.retainDays === 7, 'env policy');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
