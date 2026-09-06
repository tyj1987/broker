import {
  buildPinnedUrl, sanitizeCallerHeaders, isForbiddenDestinationIp,
  assertSafeDestination, normalizeMethod, mergeOutboundHeaders,
} from '../broker/lib/outbound-policy.js';

let passed = 0;
function ok(name, condition) {
  if (!condition) throw new Error(`FAIL: ${name}`);
  passed++;
  console.log(`  PASS  ${name}`);
}
function rejects(name, fn) {
  let rejected = false;
  try { fn(); } catch { rejected = true; }
  ok(name, rejected);
}

ok('relative path remains pinned', buildPinnedUrl('https://api.github.com', '/user').origin === 'https://api.github.com');
rejects('absolute URL blocked', () => buildPinnedUrl('https://api.github.com', 'https://evil.example/steal'));
rejects('scheme-relative URL blocked', () => buildPinnedUrl('https://api.github.com', '//evil.example/steal'));
rejects('backslash path blocked', () => buildPinnedUrl('https://api.github.com', '/\\evil.example/steal'));
rejects('plaintext upstream blocked', () => buildPinnedUrl('http://api.example.com', '/'));
rejects('Authorization override blocked', () => sanitizeCallerHeaders({ Authorization: 'Bearer canary' }));
rejects('Host override blocked', () => sanitizeCallerHeaders({ Host: 'evil.example' }));
rejects('unlisted header blocked', () => sanitizeCallerHeaders({ 'X-Anything': 'x' }));
ok('Content-Type allowed', sanitizeCallerHeaders({ 'Content-Type': 'application/json' })['Content-Type'] === 'application/json');
rejects('header newline blocked', () => sanitizeCallerHeaders({ Accept: 'x\r\ny' }));
ok('method normalized', normalizeMethod('post') === 'POST');
rejects('invalid method blocked', () => normalizeMethod('GET\r\nX: y'));
for (const ip of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '::1', 'fd00::1']) {
  ok(`private destination blocked: ${ip}`, isForbiddenDestinationIp(ip));
}
ok('public destination allowed', !isForbiddenDestinationIp('8.8.8.8'));
rejects('IP literal hostname blocked', () => assertSafeDestination('8.8.8.8', '8.8.8.8'));
rejects('DNS private result blocked', () => assertSafeDestination('example.com', '127.0.0.1'));
ok('invalid resolved address blocked', isForbiddenDestinationIp('not-an-ip'));
ok('carrier-grade NAT blocked', isForbiddenDestinationIp('100.64.1.1'));
ok('benchmark network blocked', isForbiddenDestinationIp('198.18.1.1'));
ok('multicast blocked', isForbiddenDestinationIp('224.0.0.1'));
ok('IPv6 link-local blocked', isForbiddenDestinationIp('fe80::1'));
ok('IPv6 multicast blocked', isForbiddenDestinationIp('ff02::1'));
const queried = buildPinnedUrl('https://api.example.com/base/', '/', { a: 1, omitted: null, missing: undefined });
ok('query includes values and omits nullish entries', queried.search === '?a=1');
ok('empty caller headers accepted', Object.keys(sanitizeCallerHeaders()).length === 0);
ok('broker-owned auth header wins', mergeOutboundHeaders({}, { Authorization: 'caller' }, { Authorization: 'broker' }).Authorization === 'broker');

console.log(`\n${passed} passed, 0 failed`);
