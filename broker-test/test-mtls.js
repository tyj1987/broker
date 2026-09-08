// broker-test/test-mtls.js — V4.1.1 tests for broker/lib/mtls.js (extracted identity resolver)
//
// Coverage:
//   1. Returns null with no auth
//   2. API Key path: valid Bearer → returns api_key context
//   3. API Key path: invalid Bearer → null
//   4. API Key path: rate-limited → null (audit emitted)
//   5. API Key path: IP not allowed → null (audit emitted)
//   6. API Key path: owner client missing → null
//   7. Session path: valid session → returns session context
//   8. Session path: no session → falls through to mTLS
//   9. mTLS-header path: SUCCESS verify → returns mtls-header context
//  10. mTLS-header path: verify != SUCCESS → null
//  11. mTLS path: matching fingerprint → returns mtls context
//  12. mTLS path: no matching fingerprint → null
//  13. Priority: API key beats session beats mTLS
//  14. Error in X509Certificate parsing → null (graceful)

import { createIdentityResolver } from '../broker/lib/mtls.js';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- helpers ----------

const FP = 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';
const FP_LOWER = FP.toLowerCase();

function makeConfig() {
  return {
    clients: {
      'client.alice': {
        role: 'developer',
        cert_fingerprint_sha256: FP,
        allowed_resolve: ['GITHUB_PAT'],
        allowed_proxy: ['github'],
        rate_limit: '100/hour',
      },
      'client.bob': {
        role: 'admin',
        cert_fingerprint_sha256: 'FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF',
        rate_limit: 'unlimited',
      },
    },
    api_keys: {
      'mb_test_aaaa': {
        id: 'mb_test_aaaa',
        client: 'client.alice',
        scopes: ['secrets:resolve', 'services:proxy'],
        expires_at: Date.now() + 1e9,
      },
    },
  };
}

function makeDeps(overrides = {}) {
  const auditEvents = [];
  return {
    config: overrides.config || makeConfig(),
    getSession: overrides.getSession || (() => null),
    parseBearer: overrides.parseBearer || ((h) => h?.startsWith('Bearer ') ? h.slice(7) : null),
    findApiKey: overrides.findApiKey || ((keys, token) => keys?.[token] || null),
    isClientIpAllowed: overrides.isClientIpAllowed || (() => true),
    rateLimitApiKey: overrides.rateLimitApiKey || (() => true),
    recordUse: overrides.recordUse || (() => {}),
    recordClientSeen: overrides.recordClientSeen || (() => {}),
    audit: overrides.audit || ((e) => auditEvents.push(e)),
    auditEvents,
  };
}

function req(overrides = {}) {
  return {
    headers: overrides.headers || {},
    socket: overrides.socket || { remoteAddress: '203.0.113.5' },
    ...overrides,
  };
}

// ---------- tests ----------

section('1. No auth → null');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req());
  ok('returns null', id === null);
}

section('2. API Key Bearer (valid)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns context', id !== null);
  ok('via = api_key', id?.via === 'api_key');
  ok('cn starts with apikey:', String(id?.cn).startsWith('apikey:'));
  ok('clientName = client.alice', id?.clientName === 'client.alice');
}

section('3. API Key Bearer (invalid token)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_invalid' } }));
  ok('returns null', id === null);
}

section('4. API Key Bearer (rate limited)');

{
  const deps = makeDeps({ rateLimitApiKey: () => false });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns null', id === null);
  ok('audit emitted for rate-limit', deps.auditEvents.some(e => e.reason === 'api_key_rate_limit'));
}

section('5. API Key Bearer (IP not allowed)');

{
  const deps = makeDeps({ isClientIpAllowed: () => false });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns null', id === null);
  ok('audit emitted for ip denied', deps.auditEvents.some(e => e.reason === 'api_key_ip_denied'));
}

section('6. API Key Bearer (owner client missing)');

{
  const cfg = makeConfig();
  cfg.api_keys['mb_test_aaaa'].client = 'client.nonexistent';
  const deps = makeDeps({ config: cfg });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns null', id === null);
}

section('7. Session (valid)');

{
  const deps = makeDeps({
    getSession: () => ({
      cn: 'client.alice',
      fp: FP_LOWER,
      client: { role: 'developer', cert_fingerprint_sha256: FP },
      clientName: 'client.alice',
      cert: { subject: { CN: 'client.alice' } },
    }),
  });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req());
  ok('returns context', id !== null);
  ok('via = session', id?.via === 'session');
  ok('cn = client.alice', id?.cn === 'client.alice');
}

section('8. No session → falls through (returns null when nothing else)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ socket: { remoteAddress: '203.0.113.5' } }));
  ok('returns null', id === null);
}

section('9. mTLS-header (nginx forwarded, SUCCESS)');

{
  // Fake x509 with self-signed cert PEM
  const tmp = mkdtempSync(join(tmpdir(), 'mtls-'));
  try {
    const key = join(tmp, 'k.key');
    const csr = join(tmp, 'k.csr');
    const crt = join(tmp, 'k.crt');
    // Make CA + sign a client cert
    const caKey = join(tmp, 'ca.key');
    const caCrt = join(tmp, 'ca.crt');
    execFileSync('openssl', ['genrsa', '-out', caKey, '2048']);
    execFileSync('openssl', ['req', '-x509', '-new', '-nodes', '-key', caKey, '-days', '1', '-subj', '/CN=ca', '-out', caCrt]);
    execFileSync('openssl', ['genrsa', '-out', key, '2048']);
    execFileSync('openssl', ['req', '-new', '-key', key, '-subj', '/CN=client.alice', '-out', csr]);
    execFileSync('openssl', ['x509', '-req', '-in', csr, '-CA', caCrt, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-out', crt]);
    const pem = readFileSync(crt, 'utf8');
    const fpLine = execFileSync('openssl', ['x509', '-in', crt, '-noout', '-fingerprint', '-sha256'], { encoding: 'utf8' });
    const realFp = fpLine.split('=')[1].trim();
    const cfg = makeConfig();
    cfg.clients['client.alice'].cert_fingerprint_sha256 = realFp;
    const deps = makeDeps({ config: cfg });
    const r = createIdentityResolver(deps);
    const id = r.getIdentity(req({
      headers: {
        'x-ssl-client-verify': 'SUCCESS',
        'x-ssl-client-cert': encodeURIComponent(pem),
      },
      socket: { remoteAddress: '127.0.0.1' },
    }));
    ok('returns context', id !== null);
    ok('via = mtls-header', id?.via === 'mtls-header');
    ok('cn = client.alice', id?.cn === 'client.alice');
    ok('fp matches', id?.fp === realFp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

section('10. mTLS-header (verify != SUCCESS)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    headers: {
      'x-ssl-client-verify': 'FAILED:expired',
      'x-ssl-client-cert': 'whatever',
    },
    socket: { remoteAddress: '127.0.0.1' },
  }));
  ok('returns null', id === null);
}

section('11. Direct mTLS (peer cert, matching fingerprint)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    socket: {
      remoteAddress: '203.0.113.5',
      getPeerCertificate: () => ({
        subject: { CN: 'client.alice' },
        fingerprint256: FP_LOWER,
      }),
    },
  }));
  ok('returns context', id !== null);
  ok('via = mtls', id?.via === 'mtls');
  ok('cn = client.alice', id?.cn === 'client.alice');
}

section('12. Direct mTLS (no matching fingerprint)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    socket: {
      remoteAddress: '203.0.113.5',
      getPeerCertificate: () => ({
        subject: { CN: 'client.unknown' },
        fingerprint256: '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
      }),
    },
  }));
  ok('returns null', id === null);
}

section('13. Priority: API key > session > mTLS');

{
  const deps = makeDeps({
    getSession: () => ({
      cn: 'client.alice',
      fp: FP_LOWER,
      client: { role: 'developer', cert_fingerprint_sha256: FP },
      clientName: 'client.alice',
      cert: { subject: { CN: 'client.alice' } },
    }),
  });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('API key wins over session', id?.via === 'api_key');
}

section('14. Garbage X-SSL-Client-Cert → null (graceful)');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    headers: {
      'x-ssl-client-verify': 'SUCCESS',
      'x-ssl-client-cert': encodeURIComponent('NOT A PEM CERT'),
    },
    socket: { remoteAddress: '127.0.0.1' },
  }));
  ok('returns null on bad cert', id === null);
}

section('15. getApiKeyIdentity standalone');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const ctx = r.getApiKeyIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns ctx', ctx !== null);
  ok('via = api_key', ctx?.via === 'api_key');
  ok('apiKey.id matches', ctx?.apiKey?.id === 'mb_test_aaaa');
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
