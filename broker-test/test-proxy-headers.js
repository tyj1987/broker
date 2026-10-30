// broker-test/test-proxy-headers.js — credential-proxy header boundary tests

import {
  buildProxyRequestHeaders,
  sanitizeProxyResponseHeaders,
} from '../broker/lib/proxy-headers.js';

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

console.log('[request header sanitization]');
{
  const headers = buildProxyRequestHeaders({
    baseHeaders: {
      'User-Agent': 'secret-broker/test',
      traceparent: '00-good-trace-goodspan-01',
    },
    userHeaders: {
      authorization: 'Bearer attacker',
      TraceParent: '00-bad-trace-badspan-01',
      Host: 'attacker.example',
      'Content-Length': '999999',
      'Transfer-Encoding': 'chunked',
      Connection: 'upgrade',
      'X-Broker-Relay-Secret': 'attacker-secret',
      'X-Broker-Upstream-Authorization': 'Bearer attacker-2',
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    injectHeaders: {
      Authorization: 'Bearer broker-managed-secret',
    },
  });

  ok('broker Authorization wins', headers.Authorization === 'Bearer broker-managed-secret');
  ok('caller authorization variant removed', headers.authorization === undefined);
  ok(
    'broker traceparent wins case-insensitively',
    headers.traceparent === '00-good-trace-goodspan-01',
  );
  ok('caller TraceParent variant removed', headers.TraceParent === undefined);
  ok('Host removed', headers.Host === undefined && headers.host === undefined);
  ok('Content-Length removed', headers['Content-Length'] === undefined);
  ok('Transfer-Encoding removed', headers['Transfer-Encoding'] === undefined);
  ok('Connection removed', headers.Connection === undefined);
  ok('relay secret header removed', headers['X-Broker-Relay-Secret'] === undefined);
  ok(
    'relay auth duplicate header removed',
    headers['X-Broker-Upstream-Authorization'] === undefined,
  );
  ok('safe Content-Type preserved', headers['Content-Type'] === 'application/json');
  ok('safe Accept preserved', headers.Accept === 'application/json');
}

{
  const headers = buildProxyRequestHeaders({
    userHeaders: {
      'X-Custom': 'first',
      'x-custom': 'second',
    },
  });
  ok('case-insensitive duplicate collapses to last value', headers['x-custom'] === 'second');
  ok('old-casing duplicate removed', headers['X-Custom'] === undefined);
}

console.log('\n[response header sanitization]');
{
  const headers = sanitizeProxyResponseHeaders({
    'content-type': 'application/json',
    'content-encoding': 'gzip',
    'content-length': '123',
    'set-cookie': ['broker_session=evil; Path=/', 'other=1'],
    connection: 'keep-alive',
    'transfer-encoding': 'chunked',
    'x-upstream-id': 'abc',
  });

  ok('Content-Type preserved', headers['content-type'] === 'application/json');
  ok(
    'Content-Encoding preserved for raw https.request body',
    headers['content-encoding'] === 'gzip',
  );
  ok('Content-Length preserved for unchanged body', headers['content-length'] === '123');
  ok('Set-Cookie stripped from broker origin', headers['set-cookie'] === undefined);
  ok('Connection stripped', headers.connection === undefined);
  ok('Transfer-Encoding stripped', headers['transfer-encoding'] === undefined);
  ok('safe upstream metadata preserved', headers['x-upstream-id'] === 'abc');
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
