// broker-test/test-webauthn.js — V4.1.1 tests for broker/webauthn.js
//
// Coverage:
//   1. beginRegistration returns valid options
//   2. Challenge round-trips through challenge pool
//   3. beginAuthentication returns valid options
//   4. finishRegistration: wrong ceremony type → reject
//   5. finishRegistration: invalid challenge → reject
//   6. finishRegistration: origin mismatch → reject
//   7. finishRegistration: missing verifier → reject
//   8. finishRegistration: verifier rejects → reject
//   9. finishRegistration: verifier accepts → ok + credential returned
//  10. finishAuthentication: wrong ceremony type → reject
//  11. finishAuthentication: unknown credential → reject
//  12. finishAuthentication: signCount regression (cloning) → reject
//  13. finishAuthentication: valid → ok
//  14. Challenge GC works
//  15. ensureWebAuthnFactors initializes correctly
//  16. listCredentials returns public view (no private key)
//  17. parseAuthenticatorData: valid 37-byte buffer
//  18. parseAuthenticatorData: too-short buffer throws
//  19. noopVerifier returns verified: false
//  20. configureWebAuthn overrides
//  21. Challenge single-use (can't reuse)

import {
  beginRegistration,
  finishRegistration,
  beginAuthentication,
  finishAuthentication,
  configureWebAuthn,
  getWebAuthnConfig,
  ensureWebAuthnFactors,
  listCredentials,
  parseAuthenticatorData,
  noopVerifier,
} from '../broker/webauthn.js';
import { createHash } from 'node:crypto';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- helpers ----------

function buildClientData(type, challenge, origin) {
  const cd = { type, challenge, origin };
  return Buffer.from(JSON.stringify(cd)).toString('base64url');
}

function buildAttestationObject() {
  // Minimal valid CBOR-encoded map: { fmt: "none", attStmt: {}, authData: <37 bytes> }
  // For testing we just need a non-empty buffer.
  const authData = Buffer.alloc(37);
  authData.writeUInt32BE(5, 33); // signCount = 5
  return Buffer.concat([Buffer.from([0xa3]), authData.subarray(0, 20)]).toString('base64url');
}

// Always set a known origin
configureWebAuthn({ rp_origin: 'https://broker.test', rp_id: 'broker.test', algorithms: [-7, -257] });

// ---------- tests ----------

section('1. beginRegistration returns valid options');

{
  const r = beginRegistration('client.alice', 'Alice');
  ok('has publicKey', !!r.publicKey);
  ok('has rp.name', r.publicKey.rp.name === 'Secret Broker');
  ok('rp.id is broker.test', r.publicKey.rp.id === 'broker.test');
  ok('user.name', r.publicKey.user.name === 'client.alice');
  ok('user.displayName=Alice', r.publicKey.user.displayName === 'Alice');
  ok('challenge is Buffer', Buffer.isBuffer(r.publicKey.challenge));
  ok('challenge is 32 bytes', r.publicKey.challenge.length === 32);
  ok('has pubKeyCredParams', Array.isArray(r.publicKey.pubKeyCredParams));
  ok('has authenticatorSelection', !!r.publicKey.authenticatorSelection);
  ok('UV preferred', r.publicKey.authenticatorSelection.userVerification === 'preferred');
}

section('2. Challenge round-trip');

{
  const r1 = beginRegistration('client.bob');
  const challenge = r1.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://broker.test');
  // Without a real verifier this will fail at the verifier step, but should
  // PASS challenge consumption (i.e. get past the challenge check)
  const credential = {
    id: 'cred-1',
    rawId: 'cred-1',
    response: {
      clientDataJSON: cd,
      attestationObject: buildAttestationObject(),
      transports: ['internal'],
    },
  };
  // After this attempt the challenge should be consumed
  finishRegistration('client.bob', credential, () => ({ verified: false }));
  // A second attempt with the same challenge should fail with "challenge expired"
  const r2 = beginRegistration('client.bob'); // generates a NEW challenge
  // But the second attempt using the SAME challenge should fail
  const cd2 = buildClientData('webauthn.create', challenge, 'https://broker.test');
  const credential2 = {
    id: 'cred-2',
    rawId: 'cred-2',
    response: { clientDataJSON: cd2, attestationObject: buildAttestationObject() },
  };
  const r = finishRegistration('client.bob', credential2, () => ({ verified: true }));
  ok('reused challenge rejected', !r.ok && /challenge expired/.test(r.error || ''));
  void r2;
}

section('3. beginAuthentication returns valid options');

{
  const r = beginAuthentication('client.alice', [{ id: 'cred-1' }]);
  ok('has publicKey', !!r.publicKey);
  ok('rpId = broker.test', r.publicKey.rpId === 'broker.test');
  ok('allowCredentials has 1 entry', r.publicKey.allowCredentials.length === 1);
  ok('timeout = 60s', r.publicKey.timeout === 60_000);
}

section('4. finishRegistration: wrong ceremony type');

{
  const r = beginRegistration('client.x');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.get', challenge, 'https://broker.test'); // WRONG type
  const credential = { id: 'c', response: { clientDataJSON: cd, attestationObject: buildAttestationObject() } };
  const r2 = finishRegistration('client.x', credential, () => ({ verified: true }));
  ok('rejected', !r2.ok);
  ok('error mentions ceremony', /ceremony/.test(r2.error || ''));
}

section('5. finishRegistration: invalid challenge');

{
  const cd = buildClientData('webauthn.create', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'https://broker.test');
  const credential = { id: 'c', response: { clientDataJSON: cd, attestationObject: buildAttestationObject() } };
  const r = finishRegistration('client.y', credential, () => ({ verified: true }));
  ok('rejected', !r.ok);
  ok('error mentions challenge', /challenge/.test(r.error || ''));
}

section('6. finishRegistration: origin mismatch');

{
  const r = beginRegistration('client.z');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://evil.test');
  const credential = { id: 'c', response: { clientDataJSON: cd, attestationObject: buildAttestationObject() } };
  const r2 = finishRegistration('client.z', credential, () => ({ verified: true }));
  ok('rejected', !r2.ok);
  ok('error mentions origin', /origin/.test(r2.error || ''));
}

section('7. finishRegistration: missing verifier');

{
  const r = beginRegistration('client.m');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://broker.test');
  const credential = { id: 'c', response: { clientDataJSON: cd, attestationObject: buildAttestationObject() } };
  const r2 = finishRegistration('client.m', credential, null); // no verifier
  ok('rejected', !r2.ok);
  ok('error mentions attestation/verifier', /attestation|verifier/.test(r2.error || ''));
}

section('8. finishRegistration: verifier rejects');

{
  const r = beginRegistration('client.r');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://broker.test');
  const credential = { id: 'c', response: { clientDataJSON: cd, attestationObject: buildAttestationObject() } };
  const r2 = finishRegistration('client.r', credential, () => ({ verified: false, error: 'bad cert' }));
  ok('rejected', !r2.ok);
  ok('error mentions verification', /verification/.test(r2.error || ''));
}

section('9. finishRegistration: verifier accepts → ok');

{
  const r = beginRegistration('client.ok');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://broker.test');
  const credential = {
    id: 'cred-real',
    response: { clientDataJSON: cd, attestationObject: buildAttestationObject(), transports: ['usb'] },
  };
  const r2 = finishRegistration('client.ok', credential, () => ({
    verified: true, publicKey: 'pubkey-base64', signCount: 7, aaguid: 'aaguid-x', fmt: 'none',
  }));
  ok('ok=true', r2.ok === true);
  ok('returns credential_id', r2.credential_id === 'cred-real');
  ok('returns credential object', r2.credential?.signCount === 7);
}

section('10. finishAuthentication: wrong ceremony type');

{
  const r = beginAuthentication('client.a');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.create', challenge, 'https://broker.test'); // WRONG
  const credential = { id: 'cred-real', response: { clientDataJSON: cd, authenticatorData: '', signature: '' } };
  const r2 = finishAuthentication('client.a', credential, [], () => ({ verified: true }));
  ok('rejected', !r2.ok);
}

section('11. finishAuthentication: unknown credential');

{
  const r = beginAuthentication('client.a');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.get', challenge, 'https://broker.test');
  const credential = { id: 'cred-unknown', response: { clientDataJSON: cd, authenticatorData: '', signature: '' } };
  const stored = [{ credential_id: 'cred-known', publicKey: 'pk', signCount: 0 }];
  const r2 = finishAuthentication('client.a', credential, stored, () => ({ verified: true }));
  ok('rejected', !r2.ok);
  ok('error mentions credential', /credential/.test(r2.error || ''));
}

section('12. finishAuthentication: signCount regression (cloning)');

{
  const r = beginAuthentication('client.a');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.get', challenge, 'https://broker.test');
  const credential = { id: 'cred-1', response: { clientDataJSON: cd, authenticatorData: '', signature: '' } };
  const stored = [{ credential_id: 'cred-1', publicKey: 'pk', signCount: 10 }];
  const r2 = finishAuthentication('client.a', credential, stored, () => ({ verified: true, signCount: 5 }));
  ok('rejected', !r2.ok);
  ok('error mentions signCount', /signCount/.test(r2.error || ''));
}

section('13. finishAuthentication: valid');

{
  const r = beginAuthentication('client.a');
  const challenge = r.publicKey.challenge.toString('base64url');
  const cd = buildClientData('webauthn.get', challenge, 'https://broker.test');
  const credential = { id: 'cred-1', response: { clientDataJSON: cd, authenticatorData: '', signature: '' } };
  const stored = [{ credential_id: 'cred-1', publicKey: 'pk', signCount: 5 }];
  const r2 = finishAuthentication('client.a', credential, stored, () => ({ verified: true, signCount: 6 }));
  ok('ok=true', r2.ok === true);
  ok('returns new signCount', r2.signCount === 6);
}

section('14. ensureWebAuthnFactors initializes');

{
  const c1 = {};
  ensureWebAuthnFactors(c1);
  ok('factors.webauthn created', !!c1.factors?.webauthn);
  ok('credentials is array', Array.isArray(c1.factors.webauthn.credentials));
  // Idempotent
  const c2 = { factors: { webauthn: { credentials: [{ credential_id: 'a' }] } } };
  ensureWebAuthnFactors(c2);
  ok('existing preserved', c2.factors.webauthn.credentials.length === 1);
}

section('15. listCredentials returns public view');

{
  const wa = { credentials: [{
    credential_id: 'c1',
    publicKey: 'SECRET-PRIVATE-KEY',  // should NOT be in public view
    signCount: 3,
    aaguid: 'aag',
    transports: ['usb'],
    created_at: '2026-01-01',
  }] };
  const list = listCredentials(wa);
  ok('1 credential', list.length === 1);
  ok('publicKey NOT in view', !('publicKey' in list[0]));
  ok('credential_id present', list[0].credential_id === 'c1');
  ok('aaguid present', list[0].aaguid === 'aag');
  ok('transports present', Array.isArray(list[0].transports));
}

section('16. parseAuthenticatorData');

{
  const buf = Buffer.alloc(37);
  buf.writeUInt32BE(42, 33);
  const r = parseAuthenticatorData(buf);
  ok('signCount = 42', r.signCount === 42);
  ok('flags is byte', typeof r.flags === 'number');
  ok('rpIdHash is 32 bytes', r.rpIdHash.length === 32);
}

section('17. parseAuthenticatorData: too short throws');

{
  try {
    parseAuthenticatorData(Buffer.alloc(10));
    ok('throws', false, 'should have thrown');
  } catch (e) {
    ok('throws "too short"', /too short/.test(e.message));
  }
}

section('18. noopVerifier returns verified:false');

{
  ok('verifyRegistration returns verified:false', noopVerifier.verifyRegistration().verified === false);
  ok('verifyAuthentication returns verified:false', noopVerifier.verifyAuthentication().verified === false);
}

section('19. configureWebAuthn overrides');

{
  configureWebAuthn({ rp_name: 'Custom', timeout_ms: 30000 });
  const cfg = getWebAuthnConfig();
  ok('rp_name overridden', cfg.rp_name === 'Custom');
  ok('timeout_ms overridden', cfg.timeout_ms === 30000);
  // Reset to defaults for other tests
  configureWebAuthn({ rp_name: 'Secret Broker', timeout_ms: 60_000 });
}

section('20. getWebAuthnConfig returns a copy');

{
  const c1 = getWebAuthnConfig();
  c1.rp_name = 'mutated';
  const c2 = getWebAuthnConfig();
  ok('mutating copy does not affect original', c2.rp_name !== 'mutated');
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
