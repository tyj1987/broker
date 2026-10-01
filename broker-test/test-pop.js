// Generated-key and generated-certificate tests for the deployed v1 wire contract.
// Forwarded socket metadata is injected; this is not a live TLS handshake test.
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, constants, X509Certificate, createPrivateKey, createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildCanonicalMessage, parsePoPHeader, createReplayCache, defaultReplayCache,
  verifyPoP, normalizeRequirePop, enforcePop, isReadOnlyAllowlisted } from '../broker/lib/pop.js';
import { createIdentityResolver } from '../broker/lib/mtls.js';

let passed = 0, failed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log('PASS ' + name); }
  catch (error) { failed++; console.error('FAIL ' + name + ': ' + error.message); }
}
const now = Math.floor(Date.now() / 1000);
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const pss = generateKeyPairSync('rsa-pss', { modulusLength: 2048, hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 });
function proof(pair = rsa, method = 'POST', path = '/api/v2/operations?q=1', ts = now) {
  const key = pair.privateKey.asymmetricKeyType === 'rsa-pss'
    ? { key: pair.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 } : pair.privateKey;
  const bytes = sign('sha256', Buffer.from(buildCanonicalMessage({ method, pathAndQuery: path, ts })), key);
  return `v1:${ts}:${bytes.toString('base64')}`;
}
function attempt(overrides = {}) {
  return verifyPoP({ headerValue: proof(), publicKey: rsa.publicKey, fingerprint: 'synthetic-fingerprint',
    method: 'POST', pathAndQuery: '/api/v2/operations?q=1', nowSeconds: now,
    cache: createReplayCache({ now: () => now }), ...overrides });
}
check('v1 message bytes are compatible with the existing clients', () => {
  assert.equal(buildCanonicalMessage({ method: 'post', pathAndQuery: '/a?q=1', ts: now }), `v1\nPOST\n/a?q=1\n${now}`);
  assert.equal(parsePoPHeader(proof()).ts, now);
});
for (const [name, pair] of [['RSA', rsa], ['ECDSA', ec], ['RSA-PSS', pss]]) {
  check(name + ' real signature verifies and cannot be replayed', () => {
    const cache = createReplayCache({ now: () => now });
    const opts = { publicKey: pair.publicKey, headerValue: proof(pair), cache };
    assert.equal(attempt(opts), true); assert.equal(attempt(opts), false);
  });
}
check('different valid randomized signatures cannot bypass message replay binding', () => {
  const a = proof(ec), b = proof(ec); assert.notEqual(a, b);
  const cache = createReplayCache({ now: () => now });
  assert.equal(attempt({ publicKey: ec.publicKey, headerValue: a, cache }), true);
  assert.equal(attempt({ publicKey: ec.publicKey, headerValue: b, cache }), false);
});
check('method, query, path and verification key are signature-bound', () => {
  for (const overrides of [{ method: 'GET' }, { pathAndQuery: '/api/v2/operations?q=2' },
    { pathAndQuery: '/different' }, { publicKey: ec.publicKey }]) assert.equal(attempt(overrides), false);
});
check('timestamp boundaries reject expired or too-far-future proofs', () => {
  for (const delta of [-301, 301]) assert.equal(attempt({ headerValue: proof(rsa, 'POST', '/api/v2/operations?q=1', now + delta) }), false);
  for (const delta of [-300, 300]) assert.equal(attempt({ headerValue: proof(rsa, 'POST', '/api/v2/operations?q=1', now + delta) }), true);
});
check('malformed headers and noncanonical encodings fail closed', () => {
  for (const value of [null, {}, [], '', 'v2:1:AAAA', 'v1:0:AAAA', 'v1:01:AAAA', 'v1:1:AB==', 'v1:1:!',
    'v1:1234567890123:AAAA', 'v1:1:', 'v1:1:AAA', 'x'.repeat(8193)]) assert.equal(parsePoPHeader(value), null);
});
check('malformed verifier inputs never grant a proof', () => {
  for (const overrides of [{ publicKey: null }, { publicKey: {} }, { fingerprint: '' }, { fingerprint: {} },
    { nowSeconds: NaN }, { windowSeconds: 0 }, { windowSeconds: 301 }, { cache: null },
    { pathAndQuery: 'https://foreign.invalid/' }, { method: null },
    { publicKey: { get asymmetricKeyType() { throw new Error('synthetic'); } } }]) assert.equal(attempt(overrides), false);
});
check('invalid canonical bindings are rejected before signing', () => {
  for (const overrides of [{ method: 'GET\nPOST' }, { method: 12 }, { pathAndQuery: '/a#fragment' },
    { pathAndQuery: '/a\0' }, { pathAndQuery: 'a' }, { pathAndQuery: '/' + 'a'.repeat(16384) }, { ts: 0 }]) {
    assert.throws(() => buildCanonicalMessage({ method: 'GET', pathAndQuery: '/', ts: now, ...overrides }));
  }
});
check('per-key capacity refuses new proof instead of forgetting an accepted proof', () => {
  const cache = createReplayCache({ maxPerKey: 1, now: () => now });
  const header = proof(); assert.equal(attempt({ headerValue: header, cache }), true);
  assert.equal(attempt({ headerValue: proof(rsa, 'GET', '/different'), method: 'GET', pathAndQuery: '/different', cache }), false);
  assert.equal(attempt({ headerValue: header, cache }), false); assert.equal(cache.proofCount, 1);
});
check('global capacity never evicts valid anti-replay state', () => {
  const cache = createReplayCache({ maxEntries: 1, now: () => now });
  assert.equal(attempt({ cache }), true);
  assert.equal(attempt({ fingerprint: 'other-identity', cache }), false);
  assert.equal(attempt({ cache }), false); assert.equal(cache.proofCount, 1);
});
check('replay retention includes the last valid timestamp second', () => {
  let clock = now; const cache = createReplayCache({ now: () => clock });
  const digest = createHash('sha256').update('synthetic').digest();
  assert.equal(cache.remember('aa:bb', now, digest), true);
  assert.equal(cache.check('AABB', now, digest), true);
  clock += 300; cache.pruneAt(clock); assert.equal(cache.proofCount, 1);
  clock++; cache.pruneAt(clock); assert.equal(cache.proofCount, 0); assert.equal(cache.size, 0);
  cache.pruneAt(NaN); assert.equal(cache.remember('new', clock, digest), true);
  cache.clear(); assert.equal(cache.size, 0); assert.equal(cache.proofCount, 0);
});
check('invalid replay-cache settings and records are not accepted', () => {
  for (const opts of [{ maxEntries: 0 }, { maxPerKey: -1 }, { windowSeconds: NaN }, { now: 1 }]) assert.throws(() => createReplayCache(opts));
  const cache = createReplayCache({ now: () => now }); const digest = Buffer.alloc(32);
  for (const [fp, timestamp, bytes] of [['', now, digest], ['x'.repeat(257), now, digest], ['f', 0, digest],
    ['f', now + 301, digest], ['f', now, 'bad'], ['f', now, Buffer.alloc(31)]]) assert.equal(cache.remember(fp, timestamp, bytes), false);
  assert.equal(cache.check('f', now, null), false);
  assert.equal(cache.remember('f', now, digest), true); assert.equal(cache.remember('f', now, digest), false);
  assert.equal(createReplayCache({ now: () => NaN }).remember('f', now, digest), false);
});
check('unknown PoP modes are invalid instead of becoming off', () => {
  for (const value of ['privleged', 'enabled', {}, 1, true, ' ']) assert.equal(normalizeRequirePop(value), 'invalid');
  for (const value of [null, undefined, '', 'off', ' OFF ']) assert.equal(normalizeRequirePop(value), 'off');
  assert.equal(normalizeRequirePop(' PRIVILEGED '), 'privileged'); assert.equal(normalizeRequirePop('all'), 'all');
});
check('the staged policy preserves explicit allowlist and direct TLS semantics', () => {
  const identity = { via: 'mtls-forwarded-rfc9440', edgeForwarded: true, popVerified: false };
  assert.equal(enforcePop({ identity, method: 'POST', pathname: '/mutation', requirePop: 'off' }), null);
  for (const path of ['/', '/health', '/api/v1/identity', '/api/v1/services']) {
    assert.equal(isReadOnlyAllowlisted('GET', path), true);
    assert.equal(enforcePop({ identity, method: 'GET', pathname: path, requirePop: 'privileged' }), null);
    assert.ok(enforcePop({ identity, method: 'GET', pathname: path, requirePop: 'all' }));
  }
  for (const path of ['/api/v1/me', '/api/v1/secrets', '/api/v2/operations']) assert.ok(enforcePop({ identity, method: 'GET', pathname: path, requirePop: 'privileged' }));
  assert.equal(isReadOnlyAllowlisted('POST', '/health'), false);
  assert.ok(enforcePop({ identity: { ...identity, popVerified: true }, method: 'POST', pathname: '/', requirePop: 'typo' }));
  assert.equal(enforcePop({ identity: { ...identity, popVerified: true }, method: 'POST', pathname: '/', requirePop: 'all' }), null);
  for (const ctx of [null, { via: 'mtls' }, { via: 'session' }, { via: 'api_key' }, { via: 'mtls-header', edgeForwarded: false }]) {
    assert.equal(enforcePop({ identity: ctx, method: 'POST', pathname: '/mutation', requirePop: 'all' }), null);
  }
});
check('default replay cache supports an actual current-time proof', () => {
  defaultReplayCache.clear(); const ts = Math.floor(Date.now() / 1000);
  const values = { headerValue: proof(rsa, 'GET', '/default', ts), publicKey: rsa.publicKey,
    fingerprint: 'default-fixture', method: 'GET', pathAndQuery: '/default' };
  assert.equal(verifyPoP(values), true); assert.equal(verifyPoP(values), false); defaultReplayCache.clear();
});

const dir = mkdtempSync(join(tmpdir(), 'broker-pop-certificate-'));
const openssl = process.platform === 'win32' && existsSync('C:/Program Files/Git/usr/bin/openssl.exe')
  ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl';
try {
  const keyPath = join(dir, 'client.key'), certPath = join(dir, 'client.crt');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '2', '-subj', '/CN=synthetic-pop-client', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'extendedKeyUsage=clientAuth', '-addext', 'keyUsage=critical,digitalSignature'], { stdio: ['ignore', 'pipe', 'pipe'] });
  chmodSync(keyPath, 0o600);
  const cert = new X509Certificate(readFileSync(certPath));
  const privateKey = createPrivateKey(readFileSync(keyPath));
  const header = ':' + cert.raw.toString('base64') + ':';
  function fixture({ headerName = 'client-cert', clientExists = true, certOverride = null } = {}) {
    const config = { clients: clientExists ? { 'client.fixture': { role: 'developer', cert_fingerprint_sha256: '11'.repeat(32) } } : {}, trusted_proxy_fingerprints: ['SYNTHETIC-PROXY'] };
    const audits = [];
    const deps = { config: () => config, getSession: () => null, parseBearer: () => null,
      findApiKey: () => null, isClientIpAllowed: () => true, rateLimitApiKey: () => true,
      recordUse: () => {}, recordClientSeen: () => {}, audit: e => audits.push(e),
      popCache: createReplayCache({ now: () => now }),
      forwardedMtls: { sourceIp: '203.0.113.7', fingerprintSha256: cert.fingerprint256,
        clientName: 'client.fixture', headerName,
        ...(headerName === 'x-broker-cf-client-cert' ? { ownerFingerprintSha256: '11'.repeat(32) } : {}) },
    };
    if (certOverride) deps.requireNodeCrypto = { X509Certificate: class {
      constructor(der) {
        const original = new X509Certificate(der);
        return { raw: original.raw, ca: original.ca, validFrom: original.validFrom,
          validTo: original.validTo, keyUsage: original.keyUsage, subject: original.subject,
          fingerprint256: original.fingerprint256, publicKey: original.publicKey, ...certOverride };
      }
    } };
    const resolver = createIdentityResolver(deps);
    const url = '/api/v2/operations?fixture=1';
    const request = () => ({ method: 'POST', url, headers: { 'x-forwarded-for': '203.0.113.7',
      'x-ssl-client-verify': 'NONE', [headerName]: header,
      'x-broker-pop': proof({ privateKey }, 'POST', url) },
      socket: { remoteAddress: '127.0.0.1', authorized: true,
        getPeerCertificate: () => ({ fingerprint256: 'SYNTHETIC-PROXY' }) } });
    return { resolver, request, config, audits, deps };
  }
  for (const headerName of ['client-cert', 'x-broker-cf-client-cert']) check('configured ' + headerName + ' verifies the real leaf and signature', () => {
    const f = fixture({ headerName }); const identity = f.resolver.getIdentity(f.request());
    assert.equal(identity.clientName, 'client.fixture'); assert.equal(identity.edgeForwarded, true); assert.equal(identity.popVerified, true);
    assert.equal(identity.via, 'mtls-forwarded-rfc9440');
    const replay = f.resolver.getIdentity(f.request()); assert.equal(replay.popVerified, false);
    assert.ok(enforcePop({ identity: replay, method: 'POST', pathname: '/api/v2/operations', requirePop: 'all' }));
  });
  check('possession proof is tied to actual method and raw query', () => {
    for (const mutate of [r => { r.method = 'GET'; }, r => { r.url += '&changed=1'; }]) {
      const f = fixture(); const req = f.request(); mutate(req); assert.equal(f.resolver.getIdentity(req).popVerified, false);
    }
    const f = fixture(); const req = f.request(); req.url = 'https://broker.example.test' + req.url;
    assert.equal(f.resolver.getIdentity(req).popVerified, true);
  });
  check('ambiguous headers and untrusted forwarding connections do not fall back', () => {
    for (const mutate of [r => { r.headers['x-broker-cf-client-cert'] = header; },
      r => { r.headers['x-forwarded-for'] = '203.0.113.8'; }, r => { r.socket.authorized = false; },
      r => { r.headers['x-ssl-client-verify'] = 'SUCCESS'; }, r => { delete r.headers['x-ssl-client-verify']; }]) {
      const f = fixture(); const req = f.request(); mutate(req); assert.equal(f.resolver.getIdentity(req), null);
    }
  });
  check('mapped certificate still requires a current live client', () => {
    const f = fixture(); delete f.config.clients['client.fixture']; assert.equal(f.resolver.getIdentity(f.request()), null);
  });
  check('malformed, expired, non-client and CA certificate shapes fail closed', () => {
    for (const certOverride of [{ validTo: '2000-01-01T00:00:00Z' }, { validFrom: '2999-01-01T00:00:00Z' },
      { ca: true }, { keyUsage: [] }, { raw: Buffer.from('different-der') }]) {
      const f = fixture({ certOverride }); assert.equal(f.resolver.getIdentity(f.request()), null);
      assert.ok(f.audits.some(e => e.reason === 'forwarded_mtls_certificate_invalid'));
    }
  });
  check('deployment-compatible owner certificate rotation or revocation invalidates forwarding', () => {
    for (const fingerprint of [undefined, '22'.repeat(32)]) {
      const f = fixture({ headerName: 'x-broker-cf-client-cert' });
      f.config.clients['client.fixture'].cert_fingerprint_sha256 = fingerprint;
      assert.equal(f.resolver.getIdentity(f.request()), null);
      assert.ok(f.audits.some(e => e.reason === 'forwarded_mtls_owner_binding_changed'));
    }
  });
  check('unknown forwarding header and partial configuration are rejected at startup', () => {
    const f = fixture(); assert.throws(() => createIdentityResolver({ ...f.deps, forwardedMtls: { ...f.deps.forwardedMtls, headerName: 'x-untrusted' } }));
    assert.throws(() => createIdentityResolver({ ...f.deps, forwardedMtls: { headerName: 'x-broker-cf-client-cert' } }));
    assert.throws(() => createIdentityResolver({ ...f.deps, forwardedMtls: { ...f.deps.forwardedMtls, ownerFingerprintSha256: 'invalid' } }));
    assert.throws(() => createIdentityResolver({ ...f.deps, forwardedMtls: { ...f.deps.forwardedMtls, headerName: 'x-broker-cf-client-cert' } }));
  });
} finally { rmSync(dir, { recursive: true, force: true }); }
console.log(`PoP convergence: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
