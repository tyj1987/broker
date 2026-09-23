// Exercise the actual compatibility request handler with synthetic boundaries.
// No listening socket, real configuration, credentials or provider is used.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { join } from 'node:path';
import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';
import { isCompatibilityKeyRouteAllowed } from '../broker/lib/compatibility-key-policy.js';
import { createApiKeyQuota } from '../broker/lib/api-key-quota.js';
import { proxyResponseHeaders } from '../broker/lib/proxy-response.js';
import { securityHeaders } from '../broker/lib/security-headers.js';
import { canResolveSecret, canProxyService, canCreateChild, generateMasterKey, createApiKey, publicView } from '../broker/api-keys.js';
import { createReadApiRoutes } from '../broker/routes/read-api.js';
import { canProxy, isServiceAllowed } from '../broker/can-proxy.js';
import { verifyPassword as totpVerifyPassword } from '../broker/totp.js';
const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
function section(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a && source.indexOf(start, a + 1) === -1, 'ambiguous or missing production section');
  return source.slice(a, b);
}
let passed = 0, failed = 0;
async function check(name, test) {
  try { await test(); passed++; console.log('PASS ' + name); }
  catch (error) { failed++; console.error('FAIL ' + name + ': ' + error.message); }
}
function harness({ key = null, withTotp = false, mfaValid = false, v2 = false } = {}) {
  let writes = 0, upstreamCalls = 0, certificateCalls = 0;
  const client = { role: 'admin', password: 'synthetic-password', ...(withTotp ? { totp_secret: 'SYNTHETIC' } : {}) };
  const ctx = { cn: 'owner', fp: 'synthetic-fp', clientName: 'owner', client, certSubject: { CN: 'owner' }, via: key ? 'api_key' : 'mtls', ...(key ? { apiKey: key } : {}) };
  const config = { clients: { owner: client }, api_keys: [], services: { visible: { type: 'bearer', upstream: 'https://upstream.example.test', token_secret: 'VISIBLE' }, hidden: { type: 'bearer' } } };
  const cache = new Map();
  const sandbox = {
    URL, Buffer, join, __dirname: '/synthetic', createHash, cryptoTimingSafeEqual, totpVerifyPassword,
    CONFIG: config, SECRET_CACHE: cache, BROKER_VERSION: 'synthetic',
    runWithRequestContext: (_h, fn) => fn(), setResponseTraceHeaders: () => {},
    rejectIfShuttingDown: () => false, getIdentity: () => ctx,
    isDirectLocalRequest: () => false, handleHealth: () => false, handleStatic: () => false, handleMetrics: () => false,
    v2Routes: async (_req, res) => { if (!v2) return false; res.writeHead(200, {}); res.end('{}'); return true; },
    send: (res, status, body) => { res.writeHead(status, {}); res.end(JSON.stringify(body)); },
    jsonError: (res, status, error) => { res.writeHead(status, {}); res.end(JSON.stringify({ error })); },
    readBody: async req => req.body,
    audit: () => {}, rateLimit: () => true, inc: () => {}, observeMs: () => {},
    isCompatibilityKeyRouteAllowed, canResolveSecret, canProxyService, canCreateChild, canProxy, isServiceAllowed,
    proxyResponseHeaders, securityHeaders,
    createApiKeyFn: createApiKey, generateMasterKey, publicViewFn: publicView, verifyMfaCode: () => ({ ok: mfaValid }),
    persistConfig: async () => { writes++; },
    checkSecretForService: () => ({ allowed: true, status: 'ok' }), healthcheckGetSecretStatus: () => null,
    callUpstream: async () => { upstreamCalls++; return { status: 200, latency: 1, body: Buffer.from('<html>fixture</html>'),
      headers: { 'content-type': 'text/html', 'set-cookie': 'fixture=bad', connection: 'x-hop', 'x-hop': 'private', 'content-security-policy': "default-src * 'unsafe-inline'" } }; },
    issueClientCert: async () => { certificateCalls++; throw new Error('synthetic issuer must not be reached'); },
  };
  sandbox.readApiRoutes = () => createReadApiRoutes({ config, SECRET_CACHE: cache, audit: () => {}, canResolve: () => true,
    isServiceAllowed, healthcheckGetSecretStatus: () => null });
  vm.createContext(sandbox);
  vm.runInContext(section('// timing-safe string compare', 'function rateLimit(ctx)') + '\n' + section('async function handle(req, res)', '// ============================================================\n// Identity:'), sandbox);
  return {
    config,
    async request(method, path, body) {
      const res = { statusCode: 0, headers: {}, body: null,
        setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
        writeHead(status, headers) { this.statusCode = status; Object.assign(this.headers, Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))); },
        end(body) { try { this.body = JSON.parse(String(body)); } catch { this.body = String(body); } },
      };
      await sandbox.handle({ method, url: path, headers: { host: 'broker.example.test' }, socket: { remoteAddress: '127.0.0.1' }, body }, res);
      return res;
    },
    counts: () => ({ writes, upstreamCalls, certificateCalls }),
  };
}
const delegated = { id: 'synthetic-key', client: 'owner', scopes: ['services:proxy', 'secrets:resolve'], allowed_services: ['visible'], allowed_secrets: ['VISIBLE'] };
for (const [method, path] of [
  ['GET', '/api/v1/admin/clients'], ['GET', '/api/v1/api-keys'], ['GET', '/api/v1/api-keys/master'],
  ['GET', '/api/v1/me'], ['GET', '/api/v1/audit'], ['GET', '/api/v1/admin/audit/verify'],
  ['GET', '/api/v1/health'], ['POST', '/api/v1/login'], ['POST', '/api/v1/me/change-password'],
  ['POST', '/api/v1/me/rotate-cert'], ['POST', '/api/v1/api-keys/master'], ['POST', '/api/v1/reload'],
  ['POST', '/api/v1/ssh/exec'],
]) await check('actual handler denies delegated owner privileges: ' + method + ' ' + path, async () => {
  const h = harness({ key: delegated }); const r = await h.request(method, path, {});
  assert.equal(r.statusCode, 403); assert.deepEqual(h.counts(), { writes: 0, upstreamCalls: 0, certificateCalls: 0 });
});
await check('delegated identity inspection remains available', async () => {
  const r = await harness({ key: delegated }).request('GET', '/api/v1/identity'); assert.equal(r.statusCode, 200);
});
await check('typed v2 route is handled before compatibility-only gating', async () => {
  const r = await harness({ key: delegated, v2: true }).request('POST', '/api/v2/operations', {}); assert.equal(r.statusCode, 200);
});
await check('actual proxy handler intersects the delegated service allowlist', async () => {
  const h = harness({ key: delegated }); const r = await h.request('POST', '/api/v1/proxy/hidden', { method: 'GET', path: '/' });
  assert.equal(r.statusCode, 403); assert.equal(h.counts().upstreamCalls, 0);
});
await check('proxy without the delegated scope is denied before provider execution', async () => {
  const h = harness({ key: { ...delegated, scopes: ['secrets:resolve'] } });
  assert.equal((await h.request('POST', '/api/v1/proxy/visible', {})).statusCode, 403); assert.equal(h.counts().upstreamCalls, 0);
});
for (const path of ['/api/v1/api-keys', '/api/v1/api-keys/master', '/api/v1/me/rotate-cert']) {
  await check('enabled MFA cannot downgrade step-up to password: ' + path, async () => {
    const h = harness({ withTotp: true }); const r = await h.request('POST', path, { name: 'fixture', verify: 'synthetic-password' });
    assert.equal(r.statusCode, 401); assert.equal(h.counts().writes, 0); assert.equal(h.counts().certificateCalls, 0);
  });
}
await check('valid configured TOTP still authorizes master creation', async () => {
  const h = harness({ withTotp: true, mfaValid: true }); const r = await h.request('POST', '/api/v1/api-keys/master', { name: 'fixture', verify: '123456' });
  assert.equal(r.statusCode, 200); assert.equal(h.counts().writes, 1);
});
await check('password step-up is preserved only when no TOTP is enrolled', async () => {
  const h = harness(); assert.equal((await h.request('POST', '/api/v1/api-keys/master', { name: 'fixture', verify: 'synthetic-password' })).statusCode, 200);
});
await check('production rate-limit wrapper accepts bounded multidimensional quotas', () => {
  const sandbox = vm.createContext({ createApiKeyQuota });
  vm.runInContext(section('// v3.0 M2: API Key 限速', '// ============================================================'), sandbox);
  const key = { id: 'synthetic-rate', rate_limit: { minute: 2, hour: 5, day: 10 } };
  assert.deepEqual([sandbox.rateLimitApiKey(key), sandbox.rateLimitApiKey(key), sandbox.rateLimitApiKey(key)], [true, true, false]);
});
await check('quota window expiry and active-bucket capacity cannot reset a limit', () => {
  let now = 0; const check = createApiKeyQuota({ now: () => now, maxBuckets: 1 });
  const one = { id: 'one', rate_limit: { minute: 1 } }, two = { id: 'two', rate_limit: { minute: 1 } };
  assert.equal(check(one), true); assert.equal(check(two), false); assert.equal(check(one), false);
  now = 60_000; assert.equal(check(two), true);
});
await check('invalid quotas fail closed while supported legacy quotas remain valid', () => {
  const check = createApiKeyQuota();
  for (const rate_limit of ['invalid', { hour: -1 }, { minute: 1.5 }, { bogus: 1 }, ['100/hour'], { day: 0 }]) assert.equal(check({ id: 'invalid', rate_limit }), false);
  assert.equal(check({ id: 'legacy', rate_limit: '7/minute' }), true);
  assert.equal(check({ id: 'unlimited', rate_limit: 'unlimited' }), true);
});
await check('actual proxy response strips cookies and connection-nominated headers without changing the body', async () => {
  const h = harness({ key: delegated });
  const r = await h.request('POST', '/api/v1/proxy/visible', { method: 'GET', path: '/' });
  assert.equal(r.statusCode, 200); assert.equal(h.counts().upstreamCalls, 1);
  assert.equal(r.body, '<html>fixture</html>');
  for (const name of ['set-cookie', 'connection', 'x-hop']) assert.equal(Object.hasOwn(r.headers, name), false);
  assert.ok(r.headers['content-security-policy'].startsWith('sandbox;'));
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
});
await check('proxy response header normalization keeps body framing and trusted security metadata', () => {
  const h = proxyResponseHeaders({ Connection: 'X-Hop, x-next', 'X-Hop': 'private', 'X-NeXt': 'private',
    'SeT-CoOkIe': ['a=b'], 'Content-Encoding': 'gzip', 'Content-Length': '12', 'X-Safe': ['a', 'b'],
    'Bad Name': 'invalid', 'X-Bad-Value': 'a\r\nb', 'X-Null': null, '': 'invalid',
    'Content-Security-Policy': 'default-src *', 'X-Frame-Options': 'ALLOWALL' },
    { 'X-Broker-Version': 'synthetic', 'Content-Security-Policy': 'unsafe-override' });
  assert.equal(Object.getPrototypeOf(h), null);
  assert.equal(h['content-encoding'], 'gzip'); assert.equal(h['content-length'], '12'); assert.equal(h['x-safe'], 'a, b');
  assert.equal(h['x-broker-version'], 'synthetic'); assert.ok(h['content-security-policy'].startsWith('sandbox;'));
  assert.equal(h['x-frame-options'], 'DENY');
  for (const name of ['connection', 'x-hop', 'x-next', 'set-cookie', 'bad name', 'x-bad-value', 'x-null', '']) assert.equal(Object.hasOwn(h, name), false);
  assert.equal(proxyResponseHeaders()['cache-control'], 'no-store');
  assert.equal(proxyResponseHeaders(null)['referrer-policy'], 'no-referrer');
});
await check('compatibility key policy enforces each supported operation and rejects unknown routes', () => {
  assert.equal(isCompatibilityKeyRouteAllowed(null, 'GET', '/api/v1/me'), true);
  assert.equal(isCompatibilityKeyRouteAllowed({}, 'GET', '/api/v1/identity'), false);
  for (const [method, path, scope] of [['GET', '/api/v1/services', 'services:proxy'],
    ['GET', '/api/v1/secrets', 'secrets:resolve'], ['POST', '/api/v1/secrets/resolve', 'secrets:resolve']]) {
    assert.equal(isCompatibilityKeyRouteAllowed({ scopes: [scope] }, method, path), true);
    assert.equal(isCompatibilityKeyRouteAllowed({ scopes: [] }, method, path), false);
  }
  const master = generateMasterKey('synthetic', 'owner').key_obj;
  assert.equal(isCompatibilityKeyRouteAllowed(master, 'POST', '/api/v1/api-keys/issue-child'), true);
  master.revoked_at = new Date().toISOString();
  assert.equal(isCompatibilityKeyRouteAllowed(master, 'POST', '/api/v1/api-keys/issue-child'), false);
  assert.equal(isCompatibilityKeyRouteAllowed({ scopes: ['services:proxy'] }, 'POST', '/api/v1/proxy/visible/extra'), false);
});
console.log(`compatibility-runtime: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
