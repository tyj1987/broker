import assert from 'node:assert/strict';
import {
  evaluatePolicyConditions,
  validatePolicyConditions,
} from '../broker/lib/policy-conditions.js';

const within = Date.parse('2026-09-09T12:00:00Z');
const policy = {
  source_cidrs: ['203.0.113.0/24', '2001:db8::/32'],
  not_before: '2026-09-09T00:00:00Z',
  not_after: '2026-09-10T00:00:00Z',
};

assert.equal(evaluatePolicyConditions(policy, '203.0.113.42', within).ok, true);
assert.equal(evaluatePolicyConditions(policy, '::ffff:203.0.113.42', within).ok, true);
assert.equal(evaluatePolicyConditions(policy, '2001:db8::42', within).ok, true);
assert.equal(evaluatePolicyConditions(policy, '198.51.100.2', within).reason, 'source_ip_denied');
assert.equal(evaluatePolicyConditions(policy, '', within).reason, 'source_ip_denied');
assert.equal(evaluatePolicyConditions(policy, '203.0.113.42', within - 86_400_000).reason, 'outside_time_window');
assert.equal(evaluatePolicyConditions(policy, '203.0.113.42', Date.parse(policy.not_after)).reason, 'outside_time_window');
assert.equal(evaluatePolicyConditions(policy, '203.0.113.42', Number.NaN).reason, 'invalid_policy_time');

for (const sourceCIDRs of [
  [],
  '203.0.113.0/24',
  [1],
  ['203.0.113.0'],
  ['bad/24'],
  ['203.0.113.0/x'],
  ['203.0.113.0/33'],
  ['2001:db8::/129'],
]) {
  assert.equal(validatePolicyConditions({ source_cidrs: sourceCIDRs }).reason, 'invalid_source_cidrs');
}
for (const invalidTime of [1, '2026-09-09', '2026-13-09T00:00:00Z']) {
  assert.equal(validatePolicyConditions({ not_before: invalidTime }).reason, 'invalid_policy_time');
}
assert.equal(validatePolicyConditions({
  not_before: '2026-09-10T00:00:00Z', not_after: '2026-09-09T00:00:00Z',
}).reason, 'invalid_policy_time_window');
assert.equal(evaluatePolicyConditions({ not_before: policy.not_before }, '', within).ok, true);
assert.equal(evaluatePolicyConditions({ not_after: policy.not_after }, '', within).ok, true);

console.log('policy conditions: IPv4/IPv6 CIDR and absolute time bounds fail closed');
