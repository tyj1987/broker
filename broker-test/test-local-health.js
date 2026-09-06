import { validateHealthSocketPath, isAllowedLocalHealthRequest } from '../broker/lib/local-health.js';

let passed = 0;
function ok(name, value) { if (!value) throw new Error(`FAIL: ${name}`); passed++; console.log(`  PASS  ${name}`); }
function rejects(name, fn) { let hit = false; try { fn(); } catch { hit = true; } ok(name, hit); }

ok('valid socket path', validateHealthSocketPath('/tmp/broker-health.sock') === '/tmp/broker-health.sock');
rejects('relative socket rejected', () => validateHealthSocketPath('broker.sock'));
rejects('path traversal rejected', () => validateHealthSocketPath('/tmp/../run/broker.sock'));
rejects('nested tmp path rejected', () => validateHealthSocketPath('/tmp/sub/broker.sock'));
rejects('non-socket suffix rejected', () => validateHealthSocketPath('/tmp/broker-health'));
ok('GET health allowed', isAllowedLocalHealthRequest('GET', '/health'));
ok('GET ready query allowed', isAllowedLocalHealthRequest('get', '/ready?full=1'));
ok('POST health rejected', !isAllowedLocalHealthRequest('POST', '/health'));
ok('unknown path rejected', !isAllowedLocalHealthRequest('GET', '/metrics'));
ok('encoded traversal rejected', !isAllowedLocalHealthRequest('GET', '/health%2f..%2fmetrics'));
ok('absolute attacker URL rejected by path allowlist', !isAllowedLocalHealthRequest('GET', 'http://evil.example/health'));
ok('scheme-relative URL rejected', !isAllowedLocalHealthRequest('GET', '//evil.example/health'));
ok('backslash path rejected', !isAllowedLocalHealthRequest('GET', '/health\\ignored'));
ok('missing method rejected', !isAllowedLocalHealthRequest('', '/health'));

console.log(`\n${passed} passed, 0 failed`);
