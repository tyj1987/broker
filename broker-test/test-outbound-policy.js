import {
  OutboundPolicyError,
  assertPublicDestination,
  assertPublicResolvedAddress,
  buildPinnedUrl,
  parsePinnedUpstream,
  sanitizeCallerHeaders,
  validateMethod,
} from '../broker/lib/outbound-policy.js';

let passed = 0;
let failed = 0;
function ok(name, condition) {
  if (condition) { passed += 1; console.log(`  PASS  ${name}`); }
  else { failed += 1; console.error(`  FAIL  ${name}`); }
}
function denied(fn) {
  try { fn(); return false; } catch (error) { return error instanceof OutboundPolicyError; }
}

const safe = buildPinnedUrl('https://api.example.com/v1', '/models', { limit: 1 });
ok('pins scheme and host', safe.href === 'https://api.example.com/models?limit=1');
for (const path of [
  'https://evil.example/steal', '//evil.example/steal', '/\\evil.example/steal',
  '/%2e%2e/admin', '/%252e%252e/admin', '/ok#fragment', '/bad%0d%0aheader',
]) ok(`rejects unsafe path ${path}`, denied(() => buildPinnedUrl('https://api.example.com', path)));

for (const host of ['localhost', 'metadata.google.internal', '127.0.0.1', '169.254.169.254', '10.0.0.1', '::1']) {
  ok(`rejects destination ${host}`, denied(() => assertPublicDestination(host)));
}
ok('accepts named public destination', assertPublicDestination('api.github.com') === 'api.github.com');
ok('accepts public resolved address', assertPublicResolvedAddress('8.8.8.8') === '8.8.8.8');
ok('rejects DNS rebinding address', denied(() => assertPublicResolvedAddress('192.168.1.2')));
ok('rejects IPv4-mapped loopback', denied(() => assertPublicResolvedAddress('::ffff:127.0.0.1')));
ok('rejects NAT64-mapped loopback', denied(() => assertPublicResolvedAddress('64:ff9b::7f00:1')));
ok('accepts public IPv6 resolution', assertPublicResolvedAddress('2606:4700:4700::1111') === '2606:4700:4700::1111');
ok('rejects invalid resolved address', denied(() => assertPublicResolvedAddress('not-an-ip')));
for (const upstream of [
  'not a url', 'http://api.example.com', 'https://user@api.example.com',
  'https://api.example.com/?token=x', 'https://api.example.com/#fragment',
]) ok(`rejects unsafe upstream ${upstream}`, denied(() => parsePinnedUpstream(upstream)));
ok('normalizes trailing hostname dot', parsePinnedUpstream('https://api.example.com./v1').hostname === 'api.example.com.');
ok('rejects empty destination', denied(() => assertPublicDestination('')));
ok('rejects .local destination', denied(() => assertPublicDestination('printer.local')));
ok('rejects public IP literal destination', denied(() => assertPublicDestination('8.8.8.8')));
ok('rejects public IPv6 literal destination', denied(() => assertPublicDestination('[2606:4700:4700::1111]')));
ok('rejects invalid path encoding', denied(() => buildPinnedUrl('https://api.example.com', '/bad%zz')));
ok('rejects non-object query', denied(() => buildPinnedUrl('https://api.example.com', '/v1', [])));
const omitted = buildPinnedUrl('https://api.example.com', '/v1', { keep: 0, no: null, absent: undefined });
ok('omits null query values', omitted.search === '?keep=0');

const headers = sanitizeCallerHeaders({ Accept: 'application/json', 'X-Request-Mode': 'safe' }, ['x-request-mode']);
ok('normalizes allowlisted caller headers', headers.accept === 'application/json' && headers['x-request-mode'] === 'safe');
for (const name of ['Authorization', 'Cookie', 'Host', 'X-Forwarded-For', 'X-Broker-Relay-Secret']) {
  ok(`rejects protected header ${name}`, denied(() => sanitizeCallerHeaders({ [name]: 'attacker' })));
}
ok('rejects unlisted header', denied(() => sanitizeCallerHeaders({ 'X-Arbitrary': 'value' })));
ok('rejects header newline', denied(() => sanitizeCallerHeaders({ Accept: 'ok\r\nInjected: yes' })));
ok('allows missing headers', Object.keys(sanitizeCallerHeaders()).length === 0);
ok('rejects header arrays', denied(() => sanitizeCallerHeaders({ Accept: ['text/plain'] })));
ok('rejects non-object headers', denied(() => sanitizeCallerHeaders('accept: text/plain')));
ok('rejects sec headers', denied(() => sanitizeCallerHeaders({ 'Sec-Fetch-Site': 'same-origin' }, ['sec-fetch-site'])));
ok('rejects x-forwarded variants', denied(() => sanitizeCallerHeaders({ 'X-Forwarded-Custom': 'x' }, ['x-forwarded-custom'])));
ok('allows configured method', validateMethod('post', ['GET', 'POST']) === 'POST');
ok('allows default method', validateMethod() === 'GET');
ok('rejects unconfigured method', denied(() => validateMethod('DELETE', ['GET', 'POST'])));

console.log(`\n=== ${passed} pass / ${failed} fail ===`);
process.exit(failed === 0 ? 0 : 1);
