// Mainline convergence regressions. All identities, credentials and persistence
// are synthetic. Extracted server functions run without starting server.js.
import assert from 'node:assert/strict';
import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import { generateMasterKey, createChildKey, findApiKey, isExpired, canResolveSecret } from '../broker/api-keys.js';
import { createIdentityResolver } from '../broker/lib/mtls.js';
import { createReadApiRoutes } from '../broker/routes/read-api.js';
import { hashPassword, verifyPassword as totpVerifyPassword } from '../broker/totp.js';

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log('PASS ' + name); }
  catch (error) { failed++; console.error('FAIL ' + name + ': ' + error.message); }
}
function delegation() {
  const parent = generateMasterKey('parent', 'owner', {
    child_scopes: ['services:proxy', 'operations:execute'], allowed_services: ['example'],
    allowed_operations: ['example:read'], allowed_accounts: ['account'],
    allowed_resources: ['resource'], allowed_environments: ['test'],
  }).key_obj;
  const keys = [parent];
  const issued = createChildKey(keys, parent, 'child', { ttl_seconds: 60 });
  assert.equal(issued.ok, true);
  return { parent, keys, issued, child: keys[1] };
}
await check('child authenticates under its current live parent', () => {
  const { keys, issued, child } = delegation(); assert.equal(findApiKey(keys, issued.secret), child);
});
for (const [name, mutate] of [
  ['revoked parent', p => { p.revoked_at = new Date().toISOString(); }],
  ['expired parent', p => { p.expires_at = new Date(0).toISOString(); }],
  ['malformed parent expiry', p => { p.expires_at = 'not-a-date'; }],
  ['changed parent owner', p => { p.client = 'other-owner'; }],
  ['parent no longer a master', p => { p.is_master = false; }],
  ['parent issuance permission removed', p => { p.can_create_child = false; }],
  ['parent issuance scope removed', p => { p.scopes = []; }],
]) await check(name + ' denies already-issued child', () => {
  const { parent, keys, issued } = delegation(); mutate(parent); assert.equal(findApiKey(keys, issued.secret), null);
});
await check('missing parent denies an existing child', () => {
  const { child, issued } = delegation(); assert.equal(findApiKey([child], issued.secret), null);
});
await check('ambiguous duplicate parent identifier fails closed', () => {
  const { parent, keys, issued } = delegation(); keys.push({ ...parent }); assert.equal(findApiKey(keys, issued.secret), null);
});
for (const value of [undefined, null, '', 'invalid-date', new Date(0).toISOString()]) {
  await check('invalid or absent expiry is not an immortal key: ' + String(value), () => {
    assert.equal(isExpired({ expires_at: value }), true);
    const { keys, child, issued } = delegation(); child.expires_at = value; assert.equal(findApiKey(keys, issued.secret), null);
  });
}
await check('expiry equality is rejected with a fixed clock', () => {
  const OriginalDate = globalThis.Date; const epoch = OriginalDate.now();
  class FixedDate extends OriginalDate { constructor(...args) { super(...(args.length ? args : [epoch])); } static now() { return epoch; } }
  try { globalThis.Date = FixedDate; assert.equal(isExpired({ expires_at: new OriginalDate(epoch).toISOString() }), true); }
  finally { globalThis.Date = OriginalDate; }
});
await check('mainline operation delegation fields and exact TTL stay intact', () => {
  const { child, parent } = delegation();
  for (const field of ['allowed_services', 'allowed_operations', 'allowed_accounts', 'allowed_resources', 'allowed_environments']) assert.deepEqual(child[field], parent[field]);
  assert.ok(Date.parse(child.expires_at) <= Date.parse(parent.expires_at));
});

function sessionFixture() {
  const current = { clients: { owner: { role: 'admin', allowed_resolve: ['VISIBLE'] } }, api_keys: [] };
  const session = { cn: 'owner@web', clientName: 'owner', client: current.clients.owner, authFactors: ['webauthn'] };
  const resolver = createIdentityResolver({ config: () => current, getSession: () => session,
    parseBearer: () => null, findApiKey: () => null, isClientIpAllowed: () => true,
    rateLimitApiKey: () => true, recordUse: () => {}, recordClientSeen: () => {}, audit: () => {} });
  const request = () => ({ headers: {}, socket: { remoteAddress: '198.51.100.2' } });
  return { current, resolver, request };
}
await check('session resolves the current role after a configuration replacement', () => {
  const { current, resolver, request } = sessionFixture(); current.clients.owner = { role: 'reader', allowed_resolve: [] };
  const identity = resolver.getIdentity(request()); assert.equal(identity.client, current.clients.owner); assert.equal(identity.client.role, 'reader');
  assert.deepEqual(identity.authFactors, ['webauthn']);
});
await check('deleted session owner cannot retain an old authenticated identity', () => {
  const { current, resolver, request } = sessionFixture(); delete current.clients.owner; assert.equal(resolver.getIdentity(request()), null);
});

function response() {
  return { statusCode: 0, headers: {}, body: undefined,
    writeHead(status, headers) { this.statusCode = status; this.headers = headers; },
    end(body) { this.body = JSON.parse(body); } };
}
const syntheticConfig = { services: {
  visible: { type: 'bearer', upstream: 'https://visible.example.test', token_secret: 'VISIBLE', description: 'visible' },
  hidden: { type: 'bearer', upstream: 'https://hidden.example.test', token_secret: 'HIDDEN' },
} };
const metadata = new Map(['VISIBLE', 'HIDDEN'].map(name => [name, { name, type: 'custom', description: name, updated_by: 'operator' }]));
const routeDeps = (overrides = {}) => ({ config: syntheticConfig, SECRET_CACHE: metadata, audit: () => {},
  canResolve: (_ctx, name) => name === 'VISIBLE', isServiceAllowed: (_ctx, name) => name === 'visible',
  checkPathAllowed: () => true, getSecret: () => null, healthcheckGetSecretStatus: () => ({ detail: 'private account metadata' }), ...overrides });
const user = { cn: 'owner', clientName: 'owner', client: { role: 'developer', allowed_resolve: ['.*'] } };
async function query(path, ctx = user, overrides = {}) {
  const res = response(); const api = createReadApiRoutes(routeDeps(overrides));
  const handled = await api.dispatch({ headers: {}, socket: {} }, res, { method: 'GET', pathname: path }, ctx);
  return { res, handled };
}
await check('non-admin service inventory excludes unauthorized names and private metadata', async () => {
  const { res } = await query('/api/v1/services'); assert.deepEqual(res.body.services.map(s => s.name), ['visible']);
  for (const name of ['upstream', 'token_secret', 'secret_health']) assert.equal(Object.hasOwn(res.body.services[0], name), false);
});
await check('admin-owned delegated key still receives only delegated service metadata', async () => {
  const ctx = { ...user, client: { role: 'admin' }, apiKey: { scopes: ['services:proxy'], allowed_services: ['visible'] } };
  const { res } = await query('/api/v1/services', ctx, { isServiceAllowed: () => true });
  assert.deepEqual(res.body.services.map(s => s.name), ['visible']); assert.equal(Object.hasOwn(res.body.services[0], 'upstream'), false);
});
await check('secret inventory uses the same authorization predicate as resolution', async () => {
  const { res } = await query('/api/v1/secrets'); assert.deepEqual(res.body.secrets.map(s => s.name), ['VISIBLE']);
});
await check('delegated secret inventory intersects key constraints even for admin owners', async () => {
  const ctx = { ...user, client: { role: 'admin' }, apiKey: { scopes: ['secrets:resolve'], allowed_secrets: ['VISIBLE'] } };
  const { res } = await query('/api/v1/secrets', ctx, { canResolve: () => true });
  assert.deepEqual(res.body.secrets.map(s => s.name), ['VISIBLE']); assert.equal(Object.hasOwn(res.body.secrets[0], 'updated_by'), false);
});
await check('missing delegated scope reveals no secret inventory', async () => {
  const ctx = { ...user, client: { role: 'admin' }, apiKey: { scopes: ['services:proxy'], allowed_secrets: ['VISIBLE'] } };
  const { res } = await query('/api/v1/secrets', ctx, { canResolve: () => true }); assert.deepEqual(res.body.secrets, []);
});
await check('audit verification dispatch is not swallowed by an unrelated async handler', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'broker-r5-read-api-'));
  try { const { res, handled } = await query('/api/v1/admin/audit/verify', { ...user, client: { role: 'admin' } }, { auditDir: dir });
    assert.equal(handled, true); assert.equal(res.statusCode, 200); assert.equal(res.body.ok, true); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});
await check('unavailable audit verifier returns a generic unavailable response', async () => {
  const { res } = await query('/api/v1/admin/audit/verify', { ...user, client: { role: 'admin' } });
  assert.equal(res.statusCode, 503); assert.equal(res.body.error, 'Audit verification is unavailable');
});

const source = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
function section(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a && source.indexOf(start, a + 1) === -1, 'production section must be unique: ' + start);
  return source.slice(a, b);
}
const passwords = vm.createContext({ createHash, cryptoTimingSafeEqual, totpVerifyPassword });
vm.runInContext(section('// timing-safe string compare', 'function rateLimit(ctx)'), passwords);
await check('legacy password verification returns a synchronous rejecting boolean', () => {
  assert.equal(passwords.verifyClientPassword('incorrect', 'synthetic-legacy-password'), false);
});
await check('legacy and scrypt valid passwords remain supported', () => {
  assert.equal(passwords.verifyClientPassword('synthetic-password', 'synthetic-password'), true);
  assert.equal(passwords.verifyClientPassword('synthetic-password', hashPassword('synthetic-password')), true);
});
await check('malformed password input fails closed', () => {
  assert.equal(passwords.verifyClientPassword({}, 'synthetic-password'), false);
  assert.equal(passwords.verifyClientPassword('synthetic-password', {}), false);
});
const acl = vm.createContext({ canResolveSecret, checkPathAllowed: (_rules, name) => name === 'VISIBLE' });
vm.runInContext(section('function canResolve(ctx, secretName)', '// ============================================================'), acl);
await check('actual server secret authorization intersects an admin-owned API key', () => {
  const ctx = { client: { role: 'admin' }, apiKey: { scopes: ['secrets:resolve'], allowed_secrets: ['VISIBLE'] } };
  assert.equal(acl.canResolve(ctx, 'HIDDEN'), false); assert.equal(acl.canResolve(ctx, 'VISIBLE'), true);
});
await check('actual server denies a key without resolve scope', () => {
  assert.equal(acl.canResolve({ client: { role: 'admin' }, apiKey: { scopes: ['services:proxy'] } }, 'VISIBLE'), false);
});
await check('an absent or empty owner resolve ACL denies secret access', () => {
  for (const allowed_resolve of [undefined, [], '.*']) assert.equal(acl.canResolve({ client: { role: 'developer', allowed_resolve } }, 'VISIBLE'), false);
});
await check('an explicit owner wildcard retains intended secret access', () => {
  assert.equal(acl.canResolve({ client: { role: 'developer', allowed_resolve: ['*'] } }, 'VISIBLE'), true);
});
await check('cached production read routes bind the latest configuration and cache', () => {
  const f = vm.createContext({ CONFIG: { services: { old: {} } }, SECRET_CACHE: new Map(),
    createReadApiRoutes: deps => deps, audit: () => {}, canResolve: () => {}, checkPathAllowed: () => {},
    getSecret: () => {}, isServiceAllowed: () => {}, healthcheckGetSecretStatus: () => {},
    process: { env: {} }, __dirname: '/synthetic', resolvePath: () => '/synthetic/audit' });
  vm.runInContext(section('let _readApi = null;', 'async function prepareConfig()'), f);
  const routes = f.readApiRoutes();
  const nextConfig = { services: { current: {} } }, nextCache = new Map([['VISIBLE', {}]]);
  f.CONFIG = nextConfig; f.SECRET_CACHE = nextCache;
  assert.equal(routes.config, nextConfig); assert.equal(routes.SECRET_CACHE, nextCache);
});
console.log(`release-convergence: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
