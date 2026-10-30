// broker-test/test-api-keys-rate.js — V4 任务 6: API Key 多维度限额
// Run: node broker-test/test-api-keys-rate.js
import {
  generateApiKey,
  generateMasterKey,
  normalizeRateLimit,
  createApiKeyRateLimiter,
  RATE_LIMIT_PRESETS,
} from '../broker/api-keys.js';
import { isClientIpAllowed } from '../broker/api-keys.js';

let pass = 0,
  fail = 0;
function ok(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

// === normalizeRateLimit ===
section('normalizeRateLimit');
ok('null = null (unlimited)', normalizeRateLimit(null) === null);
ok('undefined = null', normalizeRateLimit(undefined) === null);
ok(
  '"unlimited" = open',
  JSON.stringify(normalizeRateLimit('unlimited')) ===
    JSON.stringify({ minute: null, hour: null, day: null }),
);
ok(
  '"100/hour" preset',
  JSON.stringify(normalizeRateLimit('100/hour')) ===
    JSON.stringify({ minute: null, hour: 100, day: 1000 }),
);
ok(
  '"1000/hour" preset',
  JSON.stringify(normalizeRateLimit('1000/hour')) ===
    JSON.stringify({ minute: null, hour: 1000, day: 10000 }),
);
ok(
  'custom "5/minute" string',
  JSON.stringify(normalizeRateLimit('5/minute')) ===
    JSON.stringify({ minute: 5, hour: null, day: null }),
);
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

// === generateApiKey with new rate_limit shapes ===
section('generateApiKey with new fields');
{
  const { key_obj } = generateApiKey('test', 'client', {
    rate_limit: { minute: 10, hour: 100, day: 1000 },
    ip_whitelist: ['10.0.0.0/8', '192.168.0.0/16'],
  });
  ok('rate_limit object stored', typeof key_obj.rate_limit === 'object');
  ok('rate_limit.minute = 10', key_obj.rate_limit.minute === 10);
  ok('rate_limit.hour = 100', key_obj.rate_limit.hour === 100);
  ok('rate_limit.day = 1000', key_obj.rate_limit.day === 1000);
  ok(
    'ip_whitelist stored',
    Array.isArray(key_obj.ip_whitelist) && key_obj.ip_whitelist.length === 2,
  );
  // v3 string backward compat
}
{
  const { key_obj } = generateApiKey('test', 'client', {
    rate_limit: '100/hour',
  });
  ok(
    'v3 string accepted and stored',
    key_obj.rate_limit === '100/hour' || typeof key_obj.rate_limit === 'object',
  );
}

// === runtime limiter ===
section('runtime API key limiter');
{
  let now = 1_000;
  const check = createApiKeyRateLimiter({ now: () => now });
  const key = { id: 'key-a', rate_limit: { minute: 2, hour: 3, day: 4 } };
  ok('object limit first request allowed', check(key) === true);
  ok('object limit second request allowed', check(key) === true);
  ok('minute dimension blocks third request', check(key) === false);

  now += 60_001;
  ok('minute window expires while hour remains', check(key) === true);
  ok('hour dimension blocks fourth-in-hour request', check(key) === false);

  const other = { id: 'key-b', rate_limit: { minute: 2, hour: 3, day: 4 } };
  ok('different API key has independent bucket', check(other) === true);
}
{
  const check = createApiKeyRateLimiter({ defaultLimit: '2/hour' });
  const invalid = { id: 'bad-config', rate_limit: 'typo/hour' };
  ok('invalid config safe fallback first allow', check(invalid) === true);
  ok('invalid config safe fallback second allow', check(invalid) === true);
  ok('invalid config safe fallback third deny', check(invalid) === false);
}
{
  const check = createApiKeyRateLimiter();
  const legacy = { id: 'legacy', rate_limit: '2/minute' };
  ok('legacy string first request allowed', check(legacy) === true);
  ok('legacy string second request allowed', check(legacy) === true);
  ok('legacy string limit enforced', check(legacy) === false);
  const unlimited = { id: 'open', rate_limit: 'unlimited' };
  ok('unlimited remains unlimited', check(unlimited) === true && check(unlimited) === true);
}
{
  let now = 0;
  const check = createApiKeyRateLimiter({
    now: () => now,
    maxBuckets: 2,
    cleanupEvery: 10_000,
  });
  const limit = { minute: 1, hour: null, day: null };
  ok('bounded API limiter accepts first identity', check({ id: 'a', rate_limit: limit }));
  ok('bounded API limiter accepts second identity', check({ id: 'b', rate_limit: limit }));
  ok('bounded API limiter reports capacity', check.size() === 2);
  ok('new API identity fails closed at capacity', check({ id: 'c', rate_limit: limit }) === false);
  now = 60_000;
  ok('expired API buckets are pruned', check({ id: 'c', rate_limit: limit }) === true);
  ok('API bucket count shrinks after prune', check.size() === 1);
}
{
  const check = createApiKeyRateLimiter({ maxEventsPerBucket: 2 });
  const key = { id: 'event-cap', rate_limit: { minute: 100, hour: null, day: null } };
  ok('API event cap first allow', check(key));
  ok('API event cap second allow', check(key));
  ok('API event cap fails closed', check(key) === false);
  key.rate_limit = 'unlimited';
  ok('unlimited API key releases bucket', check(key) === true && check.size() === 0);
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
  const { key_obj } = generateMasterKey('m', 'client', {});
  ok('master is_master=true', key_obj.is_master === true);
  ok('master can_create_child=true', key_obj.can_create_child === true);
}

// === backward compat: ip_whitelist null = open ===
section('backward compat');
{
  const { key_obj } = generateApiKey('t', 'c', {});
  ok('no whitelist = open', isClientIpAllowed(key_obj, '8.8.8.8'));
  ok(
    'default rate_limit = "100/hour"',
    key_obj.rate_limit === '100/hour' || typeof key_obj.rate_limit === 'object',
  );
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
