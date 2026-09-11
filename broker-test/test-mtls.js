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
//  13. API key narrows, but cannot replace, a stronger identity
//  14. Error in X509Certificate parsing → null (graceful)

import { createIdentityResolver } from '../broker/lib/mtls.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- helpers ----------

const FP = 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';
const FP_LOWER = FP.toLowerCase();
const PROXY_FP = '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00';

function makeConfig() {
  return {
    trusted_proxy_fingerprints: [PROXY_FP],
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
    requireNodeCrypto: overrides.requireNodeCrypto,
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

section('8b. Session is rebound to current client config');

{
  const cfg = makeConfig();
  const deps = makeDeps({
    config: cfg,
    getSession: () => ({
      cn: 'client.alice', fp: FP_LOWER, clientName: 'client.alice',
      client: { role: 'admin', allowed_proxy: ['*'] },
      cert: { subject: { CN: 'client.alice' } },
    }),
  });
  cfg.clients['client.alice'].role = 'readonly';
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req());
  ok('session uses current role instead of cached role', id?.client?.role === 'readonly');
  ok('session keeps current policy object', id?.client === cfg.clients['client.alice']);
}

section('8c. Session is revoked when its client or certificate is revoked');

{
  const cfg = makeConfig();
  const session = {
    cn: 'client.alice', fp: FP_LOWER, clientName: 'client.alice',
    client: cfg.clients['client.alice'], cert: { subject: { CN: 'client.alice' } },
  };
  const deps = makeDeps({ config: cfg, getSession: () => session });
  const r = createIdentityResolver(deps);
  delete cfg.clients['client.alice'];
  ok('deleted client invalidates session', r.getIdentity(req()) === null);

  const cfg2 = makeConfig();
  const deps2 = makeDeps({ config: cfg2, getSession: () => session });
  const r2 = createIdentityResolver(deps2);
  cfg2.clients['client.alice'].cert_fingerprint_sha256 = PROXY_FP;
  ok('rotated certificate invalidates certificate-bound session', r2.getIdentity(req()) === null);
  ok('revocation is audited', deps2.auditEvents.some(e => e.reason === 'session_certificate_revoked'));
}

section('9. mTLS-header (nginx forwarded, SUCCESS)');

{
  class FakeX509Certificate {
    constructor(pem) {
      if (pem !== 'FAKE CLIENT CERTIFICATE') throw new Error('invalid certificate');
      this.fingerprint256 = FP;
      this.subject = 'CN=client.alice';
    }
  }
  const deps = makeDeps({ requireNodeCrypto: { X509Certificate: FakeX509Certificate } });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    headers: {
      'x-ssl-client-verify': 'SUCCESS',
      'x-ssl-client-cert': encodeURIComponent('FAKE CLIENT CERTIFICATE'),
    },
    socket: {
      remoteAddress: '127.0.0.1',
      authorized: true,
      getPeerCertificate: () => ({ fingerprint256: PROXY_FP }),
    },
  }));
  ok('returns context', id !== null);
  ok('via = mtls-header', id?.via === 'mtls-header');
  ok('cn = client.alice', id?.cn === 'client.alice');
  ok('fp matches', id?.fp === FP);
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
      authorized: true,
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
      authorized: true,
      getPeerCertificate: () => ({
        subject: { CN: 'client.unknown' },
        fingerprint256: '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
      }),
    },
  }));
  ok('returns null', id === null);
}

section('13. API key is intersected with the session identity');

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
  ok('session remains the principal', id?.via === 'session');
  ok('API key restrictions are attached', id?.apiKey?.id === 'mb_test_aaaa');
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
    socket: {
      remoteAddress: '127.0.0.1',
      authorized: true,
      getPeerCertificate: () => ({ fingerprint256: PROXY_FP }),
    },
  }));
  ok('returns null on bad cert', id === null);
}

section('15. Forwarded identity requires an authorized trusted proxy');

{
  class FakeX509Certificate {
    constructor() {
      this.fingerprint256 = FP;
      this.subject = 'CN=client.alice';
    }
  }
  const deps = makeDeps({ requireNodeCrypto: { X509Certificate: FakeX509Certificate } });
  const r = createIdentityResolver(deps);
  const headers = {
    'x-ssl-client-verify': 'SUCCESS',
    'x-ssl-client-cert': encodeURIComponent('FAKE CLIENT CERTIFICATE'),
  };
  const unauthorized = r.getIdentity(req({
    headers,
    socket: {
      remoteAddress: '127.0.0.1',
      authorized: false,
      getPeerCertificate: () => ({ fingerprint256: PROXY_FP }),
    },
  }));
  const untrusted = r.getIdentity(req({
    headers,
    socket: {
      remoteAddress: '127.0.0.1',
      authorized: true,
      getPeerCertificate: () => ({ fingerprint256: FP }),
    },
  }));
  ok('rejects unauthorized proxy TLS', unauthorized === null);
  ok('rejects untrusted proxy fingerprint', untrusted === null);
}

section('16. Direct mTLS requires an authorized certificate chain');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    socket: {
      remoteAddress: '203.0.113.5',
      authorized: false,
      getPeerCertificate: () => ({ subject: { CN: 'client.alice' }, fingerprint256: FP }),
    },
  }));
  ok('rejects unauthorized direct mTLS', id === null);
}

section('17. getApiKeyIdentity standalone');

{
  const deps = makeDeps();
  const r = createIdentityResolver(deps);
  const ctx = r.getApiKeyIdentity(req({ headers: { authorization: 'Bearer mb_test_aaaa' } }));
  ok('returns ctx', ctx !== null);
  ok('via = api_key', ctx?.via === 'api_key');
  ok('apiKey.id matches', ctx?.apiKey?.id === 'mb_test_aaaa');
}

section('18. A bearer key cannot replace a different certificate identity');

{
  const cfg = makeConfig();
  cfg.api_keys.mb_bob = { id: 'mb_bob', client: 'client.bob', scopes: ['operations:execute'] };
  const deps = makeDeps({ config: cfg });
  const r = createIdentityResolver(deps);
  const id = r.getIdentity(req({
    headers: { authorization: 'Bearer mb_bob' },
    socket: {
      remoteAddress: '203.0.113.5',
      authorized: true,
      getPeerCertificate: () => ({ subject: { CN: 'client.alice' }, fingerprint256: FP }),
    },
  }));
  ok('cross-subject binding denied', id === null);
  ok('binding denial audited', deps.auditEvents.some(e => e.reason === 'identity_binding_mismatch'));
}

section('19. Trusted proxy X-Forwarded-For is used only as a single value');

{
  let observedIp = '';
  const deps = makeDeps({ isClientIpAllowed: (_key, ip) => { observedIp = ip; return true; } });
  const r = createIdentityResolver(deps);
  r.getIdentity(req({
    headers: {
      authorization: 'Bearer mb_test_aaaa',
      'x-ssl-client-verify': 'NONE',
      'x-forwarded-for': '198.51.100.7',
    },
    socket: {
      remoteAddress: '127.0.0.1', authorized: true,
      getPeerCertificate: () => ({ fingerprint256: PROXY_FP }),
    },
  }));
  ok('uses sanitized forwarded client IP', observedIp === '198.51.100.7');
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
