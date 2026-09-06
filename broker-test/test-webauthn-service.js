import { createWebAuthnService } from '../broker/lib/webauthn-service.js';

let passed = 0;
let failed = 0;
function ok(name, value) {
  if (value) { passed++; console.log('  PASS ', name); }
  else { failed++; console.error('  FAIL ', name); }
}

let now = 1_700_000_000_000;
let persists = 0;
const config = {
  webauthn: { rp_id: 'broker.example', origin: 'https://broker.example' },
  clients: { admin: { role: 'admin', factors: { webauthn: { credentials: [] } } } },
};
const library = {
  generateRegistrationOptions: async () => ({ challenge: 'reg-challenge' }),
  verifyRegistrationResponse: async () => ({
    verified: true,
    registrationInfo: {
      userVerified: true,
      fmt: 'packed',
      aaguid: 'hardware-key',
      credentialDeviceType: 'singleDevice',
      credentialBackedUp: false,
      credential: { id: 'cred-1', publicKey: new Uint8Array([1, 2, 3]), counter: 1 },
    },
  }),
  generateAuthenticationOptions: async () => ({ challenge: 'auth-challenge' }),
  verifyAuthenticationResponse: async () => ({
    verified: true,
    authenticationInfo: {
      userVerified: true,
      newCounter: 2,
      credentialDeviceType: 'singleDevice',
      credentialBackedUp: false,
    },
  }),
};
const svc = createWebAuthnService({ config, library, now: () => now, persistConfig: async () => { persists++; } });

const reg = await svc.beginRegistration('admin');
ok('registration challenge returned', reg.challenge === 'reg-challenge');
const credential = await svc.finishRegistration('admin', { id: 'cred-1', response: { transports: ['usb'] } });
ok('hardware credential stored', credential.credential_id === 'cred-1');
ok('private key material not exposed', !JSON.stringify(credential).includes('public_key'));
ok('registration persisted', persists === 1);

const auth = await svc.beginAuthentication('admin');
ok('authentication challenge returned', auth.challenge === 'auth-challenge');
const verified = await svc.finishAuthentication('admin', { id: 'cred-1', response: {} });
ok('authentication verified', verified.verified === true);
ok('counter persisted', config.clients.admin.factors.webauthn.credentials[0].counter === 2 && persists === 2);

let replayRejected = false;
try { await svc.finishAuthentication('admin', { id: 'cred-1', response: {} }); } catch { replayRejected = true; }
ok('challenge replay rejected', replayRejected);

const syncedLibrary = { ...library, verifyRegistrationResponse: async () => ({
  verified: true,
  registrationInfo: {
    userVerified: true, fmt: 'packed', aaguid: 'sync', credentialDeviceType: 'multiDevice', credentialBackedUp: true,
    credential: { id: 'cred-sync', publicKey: new Uint8Array([4]), counter: 0 },
  },
}) };
const synced = createWebAuthnService({ config, library: syncedLibrary, now: () => now, persistConfig: async () => {} });
await synced.beginRegistration('admin');
let syncRejected = false;
try { await synced.finishRegistration('admin', { id: 'cred-sync', response: {} }); } catch { syncRejected = true; }
ok('synced passkey rejected in strict hardware flow', syncRejected);

const expiring = createWebAuthnService({ config, library, now: () => now, challengeTtlMs: 10, persistConfig: async () => {} });
await expiring.beginAuthentication('admin');
now += 11;
let expiredRejected = false;
try { await expiring.finishAuthentication('admin', { id: 'cred-1', response: {} }); } catch { expiredRejected = true; }
ok('expired challenge rejected', expiredRejected);

await (async () => {
  await (async () => {
    let threw = false;
    try { createWebAuthnService({ config: {}, persistConfig: async () => {} }); } catch { threw = true; }
    ok('missing clients config rejected', threw);
  })();
  await (async () => {
    let threw = false;
    try { createWebAuthnService({ config: { clients: {} } }); } catch { threw = true; }
    ok('missing persistence callback rejected', threw);
  })();

  const emptyConfig = { webauthn: { rp_id: 'broker.example', origin: 'https://broker.example' }, clients: { empty: {} } };
  const emptySvc = createWebAuthnService({ config: emptyConfig, library, persistConfig: async () => {} });
  await rejectsAsync('unknown client rejected', () => emptySvc.beginAuthentication('missing'));
  await rejectsAsync('authentication without credential rejected', () => emptySvc.beginAuthentication('empty'));

  const rollbackConfig = { webauthn: { rp_id: 'broker.example', origin: 'https://broker.example' }, clients: { user: {} } };
  const rollbackSvc = createWebAuthnService({ config: rollbackConfig, library, persistConfig: async () => { throw new Error('disk failed'); } });
  await rollbackSvc.beginRegistration('user');
  await rejectsAsync('registration persistence failure reported', () => rollbackSvc.finishRegistration('user', { id: 'cred-1', response: {} }));
  ok('registration persistence rollback', rollbackSvc.listCredentials('user').length === 0);

  const unsafeLibrary = { ...library, verifyRegistrationResponse: async () => ({ verified: false }) };
  const unsafeSvc = createWebAuthnService({ config: rollbackConfig, library: unsafeLibrary, persistConfig: async () => {} });
  await unsafeSvc.beginRegistration('user');
  await rejectsAsync('unverified registration rejected', () => unsafeSvc.finishRegistration('user', { id: 'x', response: {} }));

  const noAttestationLibrary = { ...library, verifyRegistrationResponse: async () => ({
    verified: true,
    registrationInfo: { userVerified: true, fmt: 'none', credentialDeviceType: 'singleDevice', credentialBackedUp: false, credential: { id: 'x', publicKey: new Uint8Array([1]), counter: 0 } },
  }) };
  const noAttestationSvc = createWebAuthnService({ config: rollbackConfig, library: noAttestationLibrary, persistConfig: async () => {} });
  await noAttestationSvc.beginRegistration('user');
  await rejectsAsync('missing attestation rejected', () => noAttestationSvc.finishRegistration('user', { id: 'x', response: {} }));

  const counterConfig = { webauthn: { rp_id: 'broker.example', origin: 'https://broker.example' }, clients: { user: { factors: { webauthn: { credentials: [{ credential_id: 'counter', public_key: 'AQ', counter: 5, transports: [] }] } } } } };
  const counterLibrary = { ...library, generateAuthenticationOptions: async () => ({ challenge: 'counter-c' }), verifyAuthenticationResponse: async () => ({ verified: true, authenticationInfo: { userVerified: true, newCounter: 4, credentialDeviceType: 'singleDevice', credentialBackedUp: false } }) };
  const counterSvc = createWebAuthnService({ config: counterConfig, library: counterLibrary, persistConfig: async () => {} });
  await counterSvc.beginAuthentication('user');
  await rejectsAsync('counter rollback rejected', () => counterSvc.finishAuthentication('user', { id: 'counter', response: {} }));
})();

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

async function rejectsAsync(name, fn) {
  try { await fn(); ok(name, false); } catch { ok(name, true); }
}
