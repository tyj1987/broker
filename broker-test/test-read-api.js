// broker-test/test-read-api.js — V4.1.1 tests for broker/routes/read-api.js
//
// Tests the extracted read-only API routes (identity, services, secrets, secrets/resolve)
// using fake req/res and an in-memory config + secret cache.

import { createReadApiRoutes } from '../broker/routes/read-api.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- helpers ----------

const auditEvents = [];
function audit(e) { auditEvents.push(e); }

function fakeRes() {
  const r = { statusCode: 0, headers: {}, body: null };
  r.writeHead = (s, h) => { r.statusCode = s; r.headers = h; return r; };
  r.end = (b) => {
    if (b !== undefined) {
      // Try to parse JSON like a real client would
      try { r.body = JSON.parse(b); } catch { r.body = b; }
    }
    return r;
  };
  return r;
}

function req({ method = 'GET', body = null } = {}) {
  const r = { method, headers: {}, socket: { remoteAddress: '127.0.0.1' } };
  if (body) {
    // mock IncomingMessage stream
    const buf = Buffer.from(JSON.stringify(body));
    r.headers['content-length'] = String(buf.length);
    r.on = (event, fn) => {
      if (event === 'data') setImmediate(() => fn(buf));
      if (event === 'end') setImmediate(() => fn());
      if (event === 'error') {} // ignore
      return r;
    };
  } else {
    r.on = (event, fn) => {
      if (event === 'end') setImmediate(() => fn());
      return r;
    };
  }
  return r;
}

const SECRET_CACHE = new Map([
  ['GITHUB_PAT', {
    name: 'GITHUB_PAT',
    type: 'github_pat',
    description: 'GitHub token',
    created_at: '2026-01-01',
    updated_at: '2026-02-01',
    last_rotated_at: '2026-02-01',
    rotation_policy_days: 90,
    updated_by: 'admin',
  }],
  ['ALIYUN_KEY', {
    name: 'ALIYUN_KEY',
    type: 'aliyun_ak',
    description: 'Aliyun',
    created_at: '2026-01-01',
    updated_at: '2026-01-15',
    last_rotated_at: '2026-01-15',
    rotation_policy_days: 180,
    updated_by: 'admin',
  }],
]);

function makeDeps(overrides = {}) {
  return {
    config: overrides.config || {
      services: {
        github: { type: 'github_token', upstream: 'https://api.github.com', token_secret: 'GITHUB_PAT', dashboard_actions: [] },
      },
    },
    SECRET_CACHE: overrides.SECRET_CACHE || SECRET_CACHE,
    audit: overrides.audit || audit,
    canResolve: overrides.canResolve || (() => true),
    checkPathAllowed: overrides.checkPathAllowed || (() => true),
    getSecret: overrides.getSecret || ((name) => {
      const meta = SECRET_CACHE.get(name);
      if (!meta) return null;
      return {
        name: meta.name,
        type: meta.type,
        value: 'SECRET_VALUE',
        fields: { token: 'SECRET_VALUE' },
      };
    }),
    isServiceAllowed: overrides.isServiceAllowed || (() => true),
    healthcheckGetSecretStatus: overrides.healthcheckGetSecretStatus || (() => null),
  };
}

// ---------- tests ----------

section('1. Identity endpoint');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = {
    cn: 'client.alice',
    fp: 'AB:CD',
    client: { role: 'developer' },
    clientName: 'client.alice',
    certSubject: { CN: 'client.alice' },
    via: 'mtls',
    authFactors: ['webauthn', 'webauthn'],
  };
  const res = fakeRes();
  const handled = await r.dispatch(req({ method: 'GET' }), res, { method: 'GET', pathname: '/api/v1/identity' }, ctx);
  ok('handled', handled === true);
  ok('status 200', res.statusCode === 200);
  ok('body.cn matches', res.body?.cn === 'client.alice');
  ok('body.fingerprint_sha256 matches', res.body?.fingerprint_sha256 === 'AB:CD');
  ok('body.role matches', res.body?.role === 'developer');
  ok('body.via matches', res.body?.via === 'mtls');
  ok('body auth factors are deduplicated', res.body?.auth_factors?.join(',') === 'webauthn');
}

section('2. Services endpoint (admin sees all + secret_health)');

{
  const deps = makeDeps({
    healthcheckGetSecretStatus: (n) => n === 'GITHUB_PAT' ? { status: 'ok', detail: 'user=tyj' } : null,
  });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'admin' }, cn: 'admin', fp: 'X' };
  const res = fakeRes();
  await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/services' }, ctx);
  ok('status 200', res.statusCode === 200);
  ok('returns services array', Array.isArray(res.body?.services));
  ok('one service', res.body?.services.length === 1);
  const svc = res.body.services[0];
  ok('service.name = github', svc.name === 'github');
  ok('service.allowed = true', svc.allowed === true);
  ok('service.secret_health populated', svc.secret_health?.status === 'ok');
  ok('audit logged', auditEvents.some(e => e.action === 'list_services'));
}

section('3. Services endpoint (non-admin + service not allowed)');

{
  const deps = makeDeps({ isServiceAllowed: () => false });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'Y' };
  const res = fakeRes();
  await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/services' }, ctx);
  ok('allowed=false for non-admin', res.body.services[0].allowed === false);
  ok('still returns service metadata', res.body.services[0].type === 'github_token');
}

section('4. Secrets endpoint (admin sees full metadata)');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'admin', allowed_resolve: [] }, cn: 'a', fp: 'Z' };
  const res = fakeRes();
  await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/secrets' }, ctx);
  ok('returns both secrets', res.body?.secrets?.length === 2);
  const gh = res.body.secrets.find(s => s.name === 'GITHUB_PAT');
  ok('admin sees updated_by', gh?.updated_by === 'admin');
  ok('admin sees rotation_policy_days', gh?.rotation_policy_days === 90);
}

section('5. Secrets endpoint (non-admin with allow_all wildcard)');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer', allowed_resolve: ['*'] }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/secrets' }, ctx);
  ok('sees both via wildcard', res.body?.secrets?.length === 2);
  const gh = res.body.secrets.find(s => s.name === 'GITHUB_PAT');
  ok('non-admin does NOT see updated_by', gh?.updated_by === undefined);
  ok('non-admin DOES see last_rotated_at (M5.9)', gh?.last_rotated_at !== undefined);
}

section('6. Secrets endpoint (non-admin with restricted allow)');

{
  const deps = makeDeps({ checkPathAllowed: (allow, name) => name === 'GITHUB_PAT' });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer', allowed_resolve: ['GITHUB_*'] }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/secrets' }, ctx);
  ok('only sees allowed secret', res.body?.secrets?.length === 1);
  ok('GITHUB_PAT visible', res.body.secrets[0].name === 'GITHUB_PAT');
}

section('7. Secrets resolve (allowed)');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req({ method: 'POST', body: { name: 'GITHUB_PAT' } }),
                    res, { method: 'POST', pathname: '/api/v1/secrets/resolve' }, ctx);
  ok('status 200', res.statusCode === 200);
  ok('returns fields', res.body?.fields?.token === 'SECRET_VALUE');
  ok('audit logged ok', auditEvents.some(e => e.action === 'resolve' && e.status === 'ok'));
}

section('8. Secrets resolve (denied by canResolve)');

{
  const deps = makeDeps({ canResolve: () => false });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req({ method: 'POST', body: { name: 'GITHUB_PAT' } }),
                    res, { method: 'POST', pathname: '/api/v1/secrets/resolve' }, ctx);
  ok('status 403', res.statusCode === 403);
  ok('error message present', /Not allowed/.test(res.body?.error || ''));
}

section('9. Secrets resolve (missing name)');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req({ method: 'POST', body: {} }),
                    res, { method: 'POST', pathname: '/api/v1/secrets/resolve' }, ctx);
  ok('status 400', res.statusCode === 400);
}

section('10. Secrets resolve (secret not loaded)');

{
  const deps = makeDeps({ getSecret: () => null });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req({ method: 'POST', body: { name: 'GITHUB_PAT' } }),
                    res, { method: 'POST', pathname: '/api/v1/secrets/resolve' }, ctx);
  ok('status 404', res.statusCode === 404);
}

section('11. Secrets resolve (specific field)');

{
  const deps = makeDeps({
    getSecret: () => ({ type: 'github_pat', value: '', fields: { token: 'synthetic-token-value', name: 'my-token' } }),
  });
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  await r.dispatch(req({ method: 'POST', body: { name: 'GITHUB_PAT', field: 'token' } }),
                    res, { method: 'POST', pathname: '/api/v1/secrets/resolve' }, ctx);
  ok('status 200', res.statusCode === 200);
  ok('returns requested field', res.body?.value === 'synthetic-token-value');
  ok('returns field name', res.body?.field === 'token');
}

section('12. Fall-through (unhandled path returns false)');

{
  const deps = makeDeps();
  const r = createReadApiRoutes(deps);
  const ctx = { client: { role: 'developer' }, cn: 'u', fp: 'W' };
  const res = fakeRes();
  const handled = await r.dispatch(req(), res, { method: 'GET', pathname: '/api/v1/nonexistent' }, ctx);
  ok('not handled', handled === false);
  ok('no response sent (statusCode 0)', res.statusCode === 0);
}

section('13. Security: API-key secret capability bounds listing and resolve');

{
  const keyCtx = {
    via: 'api_key',
    apiKey: { scopes: ['secrets:resolve'], allowed_secrets: ['GITHUB_PAT'] },
    client: { role: 'admin', allowed_resolve: ['*'] },
    cn: 'apikey:test', fp: 'K',
  };
  const deps = makeDeps({
    canResolve: (ctx, name) => ctx.via === 'api_key'
      ? ctx.apiKey?.scopes?.includes('secrets:resolve') && ctx.apiKey.allowed_secrets?.includes(name)
      : true,
  });
  const r = createReadApiRoutes(deps);
  const listRes = fakeRes();
  await r.dispatch(req(), listRes, { method: 'GET', pathname: '/api/v1/secrets' }, keyCtx);
  ok('API-key listing only exposes allowed secret', listRes.body?.secrets?.length === 1 && listRes.body.secrets[0].name === 'GITHUB_PAT');
  const deniedRes = fakeRes();
  await r.dispatch(req({ method: 'POST', body: { name: 'ALIYUN_KEY' } }), deniedRes,
    { method: 'POST', pathname: '/api/v1/secrets/resolve' }, keyCtx);
  ok('API-key resolve outside allowlist denied', deniedRes.statusCode === 403);
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
