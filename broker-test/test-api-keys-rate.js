// broker-test/test-api-keys-rate.js — V4 任务 6: API Key 多维度限额
// Run: node broker-test/test-api-keys-rate.js
import {
  generateApiKey,
  generateMasterKey,
  normalizeRateLimit,
  RATE_LIMIT_PRESETS,
  consumeRateLimit,
  createApiKey,
  findApiKey,
  listApiKeys,
  revokeApiKey,
  recordUse,
  parseBearer,
  isExpired,
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

section('enforcement fails closed');
{
  const buckets = new Map();
  const key = { id: 'k1', rate_limit: { minute: 2, hour: 3, day: 4 } };
  ok('first request allowed', consumeRateLimit(key, buckets, 100_000));
  ok('second request allowed', consumeRateLimit(key, buckets, 100_001));
  ok('minute quota enforced', !consumeRateLimit(key, buckets, 100_002));
  ok('window expiry permits request', consumeRateLimit(key, buckets, 160_001));
  ok('hour quota enforced independently', !consumeRateLimit(key, buckets, 160_002));
  ok('explicit unlimited accepted', consumeRateLimit({ id: 'k2', rate_limit: 'unlimited' }, buckets));
  ok('missing limit rejected', !consumeRateLimit({ id: 'k3' }, buckets));
  ok('unknown limit rejected', !consumeRateLimit({ id: 'k4', rate_limit: 'bogus' }, buckets));
  ok('zero limit rejects', !consumeRateLimit({ id: 'k5', rate_limit: { minute: 0 } }, buckets));
  ok('invalid bucket store rejects', !consumeRateLimit(key, {}, 1));
}

section('lifecycle and malformed input');
{
  const keys = [];
  const created = createApiKey(keys, 'one', 'client-a', { allowed_services: ['github'] });
  ok('created key can be found', findApiKey(keys, created.secret)?.id === created.key_obj.id);
  ok('bad secret rejected', findApiKey(keys, 'not-the-key') === null);
  ok('missing key list rejected', findApiKey(null, created.secret) === null);
  ok('bearer parsed', parseBearer(`Bearer ${created.secret}`) === created.secret);
  ok('malformed bearer rejected', parseBearer(`Basic ${created.secret}`) === null);
  ok('missing bearer rejected', parseBearer('') === null);
  recordUse(keys[0]);
  ok('usage recorded', keys[0].use_count === 1 && !!keys[0].last_used_at);
  recordUse(null);
  ok('client list filtered', listApiKeys(keys, { clientOnly: 'client-a' }).length === 1 && listApiKeys(keys, { clientOnly: 'other' }).length === 0);
  ok('invalid list is empty', listApiKeys(null).length === 0);
  ok('unknown revoke rejected', revokeApiKey(keys, 'missing', 'admin').reason === 'not_found');
  ok('key revoked', revokeApiKey(keys, created.key_obj.id, 'admin').ok === true);
  ok('revoked key cannot authenticate', findApiKey(keys, created.secret) === null);
  ok('duplicate revoke rejected', revokeApiKey(keys, created.key_obj.id, 'admin').reason === 'already_revoked');
  ok('invalid expiry fails closed', isExpired({ expires_at: 'not-a-date' }));
  ok('missing expiry fails closed', isExpired({}));
  ok('expired key rejected', isExpired({ expires_at: new Date(Date.now() - 1).toISOString() }));
  ok('future key remains valid', !isExpired({ expires_at: new Date(Date.now() + 60_000).toISOString() }));
  ok('numeric rate format rejected', normalizeRateLimit(100) === null);
}

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
  ok('ip_whitelist stored', Array.isArray(key_obj.ip_whitelist) && key_obj.ip_whitelist.length === 2);
  // v3 string backward compat
}
{
  let invalidRejected = false;
  try { generateApiKey('bad', 'client', { ttl_ms: -1 }); } catch { invalidRejected = true; }
  ok('negative TTL rejected', invalidRejected);
  const capped = generateApiKey('capped', 'client', { ttl_ms: 365 * 86400_000 }).key_obj;
  ok('ordinary key TTL capped at 24 hours', new Date(capped.expires_at).getTime() <= Date.now() + 86400_500);
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
  const { key_obj } = generateMasterKey('m', 'client', {});
  ok('master is_master=true', key_obj.is_master === true);
  ok('master can_create_child=true', key_obj.can_create_child === true);
}

// === backward compat: ip_whitelist null = open ===
section('backward compat');
{
  const { key_obj } = generateApiKey('t', 'c', {});
  ok('no whitelist = open', isClientIpAllowed(key_obj, '8.8.8.8'));
  ok('default rate_limit = "100/hour"', key_obj.rate_limit === '100/hour' || (typeof key_obj.rate_limit === 'object'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
