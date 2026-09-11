// broker-test/test-api-keys-rate.js — V4 任务 6: API Key 多维度限额
// Run: node broker-test/test-api-keys-rate.js
import {
  generateApiKey,
  generateMasterKey,
  createChildKey,
  findApiKey,
  isExpired,
  normalizeRateLimit,
  RATE_LIMIT_PRESETS,
} from '../broker/api-keys.js';
import { isClientIpAllowed } from '../broker/api-keys.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// === normalizeRateLimit ===
section('normalizeRateLimit');
ok('null = null (unlimited)', normalizeRateLimit(null) === null);
ok('undefined = null', normalizeRateLimit(undefined) === null);
ok('"unlimited" = open', JSON.stringify(normalizeRateLimit('unlimited')) === JSON.stringify({ minute: null, hour: null, day: null }));
ok('"100/hour" preset', JSON.stringify(normalizeRateLimit('100/hour')) === JSON.stringify({ minute: null, hour: 100, day: 1000 }));
ok('"1000/hour" preset', JSON.stringify(normalizeRateLimit('1000/hour')) === JSON.stringify({ minute: null, hour: 1000, day: 10000 }));
ok('"unknown" returns null', normalizeRateLimit('bogus-string') === null);
{
  const o = normalizeRateLimit({ minute: 50, hour: 1000, day: 20000 });
  ok('object shape preserved', o.minute === 50 && o.hour === 1000 && o.day === 20000);
}
{
  const o = normalizeRateLimit({ minute: 0, hour: 100 });
  ok('minute=0 is finite (0 not null)', o.minute === 0 && o.hour === 100);
}
{
  const o = normalizeRateLimit({});
  ok('empty object = all null', o.minute === null && o.hour === null && o.day === null);
}

// === RATE_LIMIT_PRESETS ===
section('presets');
ok('preset 100/hour present', !!RATE_LIMIT_PRESETS['100/hour']);
ok('preset 1000/hour present', !!RATE_LIMIT_PRESETS['1000/hour']);
ok('preset unlimited present', !!RATE_LIMIT_PRESETS['unlimited']);

section('expiry fail-closed');
const expiryKey = generateApiKey('expiry-check', 'client-1', { ttl_ms: 60_000 });
ok('valid key is accepted', findApiKey([expiryKey.key_obj], expiryKey.secret)?.id === expiryKey.id);
ok('valid key is not expired', isExpired(expiryKey.key_obj) === false);
ok('missing expiry is expired', isExpired({}) === true);
ok('malformed expiry is expired', isExpired({ expires_at: 'not-a-date' }) === true);
ok('malformed expiry cannot authenticate', findApiKey([
  { ...expiryKey.key_obj, expires_at: 'not-a-date' },
], expiryKey.secret) === null);

// === generateApiKey with new rate_limit shapes ===
section('generateApiKey with new fields');
{
  const { key_obj } = generateApiKey('test', 'client', {
    rate_limit: { minute: 10, hour: 100, day: 1000 },
    ip_whitelist: ['10.0.0.0/8', '192.168.0.0/16'],
    allowed_operations: ['aliyun:browser.otp.fill'],
    allowed_accounts: ['primary'],
    allowed_resources: ['account.aliyun.com'],
    allowed_environments: ['production'],
  });
  ok('rate_limit object stored', typeof key_obj.rate_limit === 'object');
  ok('rate_limit.minute = 10', key_obj.rate_limit.minute === 10);
  ok('rate_limit.hour = 100', key_obj.rate_limit.hour === 100);
  ok('rate_limit.day = 1000', key_obj.rate_limit.day === 1000);
  ok('ip_whitelist stored', Array.isArray(key_obj.ip_whitelist) && key_obj.ip_whitelist.length === 2);
  ok('allowed_operations stored', key_obj.allowed_operations[0] === 'aliyun:browser.otp.fill');
  ok('allowed_accounts stored', key_obj.allowed_accounts[0] === 'primary');
  ok('allowed_resources stored', key_obj.allowed_resources[0] === 'account.aliyun.com');
  ok('allowed_environments stored', key_obj.allowed_environments[0] === 'production');
  // v3 string backward compat
}
{
  const { key_obj } = generateApiKey('test', 'client', {
    rate_limit: '100/hour',
  });
  ok('v3 string accepted and stored', key_obj.rate_limit === '100/hour' || (typeof key_obj.rate_limit === 'object'));
}

// === IP whitelist with new key ===
section('IP whitelist');
{
  const { key_obj } = generateApiKey('t', 'c', { ip_whitelist: ['203.0.113.0/24'] });
  ok('203.0.113.10 allowed', isClientIpAllowed(key_obj, '203.0.113.10'));
  ok('198.51.100.1 denied', !isClientIpAllowed(key_obj, '198.51.100.1'));
}
{
  const { key_obj } = generateApiKey('t', 'c', { ip_whitelist: ['10.0.0.0/8', '192.168.1.0/24'] });
  ok('cidr 10/8 hit', isClientIpAllowed(key_obj, '10.99.99.99'));
  ok('cidr 192.168.1/24 hit', isClientIpAllowed(key_obj, '192.168.1.50'));
  ok('cidr miss', !isClientIpAllowed(key_obj, '172.16.0.1'));
}

// === master key still works ===
section('master key');
{
  const { key_obj } = generateMasterKey('m', 'client', {
    child_scopes: ['operations:execute'],
    allowed_services: ['aliyun'],
    allowed_operations: ['aliyun:browser.otp.fill'],
    allowed_accounts: ['primary'],
    allowed_resources: ['account.aliyun.com'],
    allowed_environments: ['production'],
  });
  ok('master is_master=true', key_obj.is_master === true);
  ok('master can_create_child=true', key_obj.can_create_child === true);
  const keys = [key_obj];
  const child = createChildKey(keys, key_obj, 'child', {
    scopes: ['operations:execute'], allowed_services: ['aliyun', 'github'],
    allowed_operations: ['aliyun:browser.otp.fill', 'github:repo.read'],
    allowed_accounts: ['primary', 'secondary'], allowed_resources: ['account.aliyun.com', 'other'],
    allowed_environments: ['production', 'staging'], ttl_seconds: 60 * 60 * 24 * 365,
    rate_limit: 'unlimited', ip_whitelist: ['203.0.113.0/24'],
  });
  ok('child created', child.ok === true);
  ok('child service cannot exceed parent', JSON.stringify(child.key_obj.allowed_services) === '["aliyun"]');
  ok('child operation cannot exceed parent', JSON.stringify(child.key_obj.allowed_operations) === '["aliyun:browser.otp.fill"]');
  ok('child account cannot exceed parent', JSON.stringify(child.key_obj.allowed_accounts) === '["primary"]');
  ok('child resource cannot exceed parent', JSON.stringify(child.key_obj.allowed_resources) === '["account.aliyun.com"]');
  ok('child environment cannot exceed parent', JSON.stringify(child.key_obj.allowed_environments) === '["production"]');
  ok('child cannot outlive parent', new Date(child.key_obj.expires_at) <= new Date(key_obj.expires_at));
  ok('child rate cannot exceed parent', child.key_obj.rate_limit.hour === 100);
}

{
  const { key_obj: master } = generateMasterKey('bounded', 'client', {
    ttl_ms: 1_500, child_scopes: ['audit:read'],
  });
  const child = createChildKey([], master, 'bounded-child', { scopes: ['audit:read'], ttl_seconds: 60 });
  ok('short parent uses exact absolute expiration', child.key_obj.expires_at === master.expires_at);
}

// === backward compat: ip_whitelist null = open ===
section('backward compat');
{
  const { key_obj } = generateApiKey('t', 'c', {});
  ok('no whitelist = open', isClientIpAllowed(key_obj, '8.8.8.8'));
  ok('default rate_limit = "100/hour"', key_obj.rate_limit === '100/hour' || (typeof key_obj.rate_limit === 'object'));
}

section('child constraints fail closed');
{
  const { key_obj } = generateMasterKey('unconstrained', 'client', { child_scopes: ['services:proxy'] });
  const denied = createChildKey([], key_obj, 'unsafe-child', { scopes: ['services:proxy'] });
  ok('unconstrained proxy child denied', denied.ok === false && denied.reason === 'service_constraints_required');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
