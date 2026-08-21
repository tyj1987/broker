// test-ip-allowlist.js — phase-A unit tests for IP / CIDR allowlist
import { isIpAllowed, matchIpRule, normalizeIp } from '../broker/lib/ip-allowlist.js';
import { isClientIpAllowed, generateApiKey } from '../broker/api-keys.js';

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    passed++;
    console.log(`  PASS  ${msg}`);
  } else {
    failed++;
    console.error(`  FAIL  ${msg}`);
  }
}

console.log('=== normalizeIp ===');
assert(normalizeIp('::ffff:10.0.0.1') === '10.0.0.1', 'strip ipv4-mapped');
assert(normalizeIp('  1.2.3.4  ') === '1.2.3.4', 'trim');
assert(normalizeIp('') === '', 'empty');

console.log('=== matchIpRule exact ===');
assert(matchIpRule('10.0.0.5', '10.0.0.5') === true, 'exact match');
assert(matchIpRule('10.0.0.5', '10.0.0.6') === false, 'exact miss');
assert(matchIpRule('10.0.0.5', '*') === true, 'star allow');
assert(matchIpRule('10.0.0.5', 'any') === true, 'any allow');

console.log('=== matchIpRule CIDR ===');
assert(matchIpRule('10.1.2.3', '10.0.0.0/8') === true, '10/8 hit');
assert(matchIpRule('11.1.2.3', '10.0.0.0/8') === false, '10/8 miss');
assert(matchIpRule('192.168.1.50', '192.168.1.0/24') === true, '24 hit');
assert(matchIpRule('192.168.2.50', '192.168.1.0/24') === false, '24 miss');
assert(matchIpRule('1.2.3.4', '0.0.0.0/0') === true, '0/0 all');

console.log('=== isIpAllowed ===');
assert(isIpAllowed(null, '1.2.3.4') === true, 'null whitelist = open');
assert(isIpAllowed([], '1.2.3.4') === true, 'empty whitelist = open');
assert(isIpAllowed(['10.0.0.0/8'], '10.9.9.9') === true, 'cidr allow');
assert(isIpAllowed(['10.0.0.0/8'], '11.0.0.1') === false, 'cidr deny');
assert(isIpAllowed(['1.2.3.4', '5.6.7.8'], '5.6.7.8') === true, 'list hit');
assert(isIpAllowed(['1.2.3.4'], '') === false, 'no ip with whitelist = deny');

console.log('=== isClientIpAllowed on key ===');
{
  const { key_obj } = generateApiKey('t', 'c', { ip_whitelist: ['203.0.113.0/24'] });
  assert(isClientIpAllowed(key_obj, '203.0.113.10') === true, 'key cidr allow');
  assert(isClientIpAllowed(key_obj, '198.51.100.1') === false, 'key cidr deny');
  const { key_obj: open } = generateApiKey('t2', 'c', {});
  assert(isClientIpAllowed(open, '198.51.100.1') === true, 'no whitelist = open');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
