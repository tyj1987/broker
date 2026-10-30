// broker-test/test-proxy-body.js — bounded upstream response buffering

import { Readable } from 'node:stream';
import {
  DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES,
  ABSOLUTE_MAX_UPSTREAM_RESPONSE_BYTES,
  maxUpstreamResponseBytes,
  readLimitedResponseBody,
} from '../broker/lib/proxy-body.js';

let pass = 0;
let fail = 0;

function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}

async function rejects(fn) {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

console.log('[limit configuration]');
ok('default = 16 MiB', maxUpstreamResponseBytes({}) === DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES);
ok(
  'valid override accepted',
  maxUpstreamResponseBytes({ BROKER_MAX_UPSTREAM_RESPONSE_BYTES: '1024' }) === 1024,
);
ok(
  'invalid override falls back',
  maxUpstreamResponseBytes({ BROKER_MAX_UPSTREAM_RESPONSE_BYTES: 'bad' }) ===
    DEFAULT_MAX_UPSTREAM_RESPONSE_BYTES,
);
ok(
  'override hard capped',
  maxUpstreamResponseBytes({ BROKER_MAX_UPSTREAM_RESPONSE_BYTES: String(999 * 1024 * 1024) }) ===
    ABSOLUTE_MAX_UPSTREAM_RESPONSE_BYTES,
);

console.log('\n[body buffering]');
{
  const stream = Readable.from([Buffer.from('hello'), Buffer.from(' world')]);
  stream.headers = {};
  const body = await readLimitedResponseBody(stream, 64);
  ok('small body preserved', body.toString() === 'hello world');
}
{
  const stream = Readable.from([Buffer.alloc(8), Buffer.alloc(8)]);
  stream.headers = {};
  ok('streaming overflow rejected', await rejects(() => readLimitedResponseBody(stream, 10)));
}
{
  const stream = Readable.from([]);
  stream.headers = { 'content-length': '1000' };
  ok(
    'advertised overflow rejected before buffering',
    await rejects(() => readLimitedResponseBody(stream, 10)),
  );
}
{
  const stream = Readable.from([Buffer.from('abc')]);
  stream.headers = { 'content-length': '3' };
  const body = await readLimitedResponseBody(stream, 3);
  ok('exact limit accepted', body.toString() === 'abc');
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
