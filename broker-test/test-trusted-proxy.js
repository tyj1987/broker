import { isLoopbackAddress, isTrustedProxySocket, resolveSourceIp } from '../broker/lib/trusted-proxy.js';

let passed = 0;
function ok(name, value) { if (!value) throw new Error(`FAIL: ${name}`); passed++; console.log(`  PASS  ${name}`); }

ok('IPv4 loopback accepted', isLoopbackAddress('127.0.0.1'));
ok('IPv6 loopback accepted', isLoopbackAddress('::1'));
ok('mapped loopback accepted', isLoopbackAddress('::ffff:127.0.0.1'));
ok('non-loopback rejected', !isLoopbackAddress('10.0.0.5'));
const socket = { remoteAddress: '127.0.0.1', authorized: true, getPeerCertificate: () => ({ fingerprint256: 'AA:BB' }) };
ok('enrolled authorized proxy accepted', isTrustedProxySocket(socket, ['aa:bb']));
ok('wrong fingerprint rejected', !isTrustedProxySocket(socket, ['CC:DD']));
ok('unauthorized proxy rejected', !isTrustedProxySocket({ ...socket, authorized: false }, ['AA:BB']));
ok('remote proxy rejected', !isTrustedProxySocket({ ...socket, remoteAddress: '203.0.113.8' }, ['AA:BB']));
ok('missing certificate rejected', !isTrustedProxySocket({ ...socket, getPeerCertificate: () => ({}) }, ['AA:BB']));
ok('spoofed forwarding ignored for direct peer', resolveSourceIp({ socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-forwarded-for': '198.51.100.1' } }, false) === '203.0.113.9');
ok('trusted forwarding used', resolveSourceIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '198.51.100.1, 127.0.0.1' } }, true) === '198.51.100.1');
ok('trusted array forwarding used', resolveSourceIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': ['192.0.2.5'] } }, true) === '192.0.2.5');
ok('missing forwarding falls back to socket', resolveSourceIp({ socket: { remoteAddress: '127.0.0.1' }, headers: {} }, true) === '127.0.0.1');

console.log(`\n${passed} passed, 0 failed`);
