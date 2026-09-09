import assert from 'node:assert/strict';
import { WebAuthnService } from '../broker/lib/webauthn-service.js';

let persisted = 0;
let registrationNumber = 0;
const config = {
  webauthn: { rp_id: 'broker.test', rp_origin: 'https://broker.test', rp_name: 'Broker test' },
  clients: {
    alice: {
      role: 'admin', security_profile: 'strict', webauthn_bootstrap: true,
      factors: { webauthn: { credentials: [] } },
    },
  },
};
const implementation = {
  generateRegistrationOptions: async () => ({ challenge: `register-${++registrationNumber}`, user: { id: 'user' } }),
  verifyRegistrationResponse: async ({ response }) => ({
    verified: true,
    registrationInfo: {
      credential: {
        id: response.id,
        publicKey: Uint8Array.from([1, 2, 3]),
        counter: 0,
      },
      credentialDeviceType: response.device_type || 'singleDevice',
      credentialBackedUp: response.backed_up || false,
      aaguid: '00000000-0000-0000-0000-000000000001',
      fmt: 'packed',
    },
  }),
  generateAuthenticationOptions: async () => ({ challenge: 'authenticate-1' }),
  verifyAuthenticationResponse: async () => ({ verified: true, authenticationInfo: { newCounter: 1 } }),
};
const service = new WebAuthnService({
  getConfig: () => config,
  persist: async () => { persisted += 1; },
  now: () => 1_800_000_000_000,
  implementation,
});

const bootstrapIdentity = { name: 'alice', context: { via: 'mtls', authFactors: [] } };
const first = await service.beginRegistration(bootstrapIdentity, { label: 'Primary security key' });
const firstResult = await service.finishRegistration(bootstrapIdentity, {
  flow_id: first.flow_id,
  response: { id: 'key-1', response: { transports: ['usb', 'nfc'] } },
});
assert.equal(firstResult.strict_ready, false);
assert.equal(config.clients.alice.factors.webauthn.credentials.length, 1);
assert.equal(config.clients.alice.factors.webauthn.credentials[0].public_key, 'AQID');

await assert.rejects(
  service.finishRegistration(bootstrapIdentity, { flow_id: first.flow_id, response: { id: 'replay' } }),
  (error) => error.code === 'invalid_flow',
);

const steppedUpIdentity = { name: 'alice', context: { via: 'session', authFactors: ['webauthn'] } };
const second = await service.beginRegistration(steppedUpIdentity, { label: 'Backup security key' });
let registrationAuditCommitted = false;
const secondResult = await service.finishRegistrationAndAudit(steppedUpIdentity, {
  flow_id: second.flow_id,
  response: { id: 'key-2', response: { transports: ['usb'] } },
}, ({ credential_id: credentialId }) => {
  assert.equal(credentialId, 'key-2');
  registrationAuditCommitted = true;
});
assert.equal(registrationAuditCommitted, true);
assert.equal(secondResult.strict_ready, true);

const unauditedRegistration = await service.beginRegistration(steppedUpIdentity, { label: 'Unaudited key' });
await assert.rejects(
  service.finishRegistrationAndAudit(steppedUpIdentity, {
    flow_id: unauditedRegistration.flow_id,
    response: { id: 'unaudited-key', response: { transports: ['usb'] } },
  }, () => { throw new Error('audit unavailable'); }),
  /audit unavailable/,
);
assert.equal(config.clients.alice.factors.webauthn.credentials.length, 2);

const authentication = await service.beginAuthentication({ client: 'alice' });
const authenticated = await service.finishAuthentication({
  flow_id: authentication.flow_id,
  response: { id: 'key-1', response: {} },
});
assert.equal(authenticated.clientName, 'alice');
assert.equal(authenticated.strictReady, true);
assert.equal(config.clients.alice.factors.webauthn.credentials[0].counter, 1);

const rollbackAuthentication = await service.beginAuthentication({ client: 'alice' });
assert.throws(
  () => service.rollbackFlowCreation(rollbackAuthentication.flow_id, 'registration', 'alice'),
  (error) => error.code === 'invalid_flow',
);
assert.throws(
  () => service.rollbackFlowCreation(rollbackAuthentication.flow_id, 'authentication', 'other-client'),
  (error) => error.code === 'invalid_flow',
);
service.rollbackFlowCreation(rollbackAuthentication.flow_id, 'authentication', 'alice');
await assert.rejects(
  service.finishAuthentication({
    flow_id: rollbackAuthentication.flow_id,
    response: { id: 'key-1', response: {} },
  }),
  (error) => error.code === 'invalid_flow',
);

const rollbackRegistration = await service.beginRegistration(steppedUpIdentity, { label: 'Unused key' });
service.rollbackFlowCreation(rollbackRegistration.flow_id, 'registration', 'alice');
await assert.rejects(
  service.finishRegistration(steppedUpIdentity, {
    flow_id: rollbackRegistration.flow_id,
    response: { id: 'unused-key', response: {} },
  }),
  (error) => error.code === 'invalid_flow',
);

const synced = await service.beginRegistration(steppedUpIdentity, { label: 'Synced passkey' });
await assert.rejects(
  service.finishRegistration(steppedUpIdentity, {
    flow_id: synced.flow_id,
    response: { id: 'synced', device_type: 'multiDevice', backed_up: true, response: {} },
  }),
  (error) => error.code === 'hardware_key_required',
);
assert.equal(config.clients.alice.factors.webauthn.credentials.length, 2);
assert.equal(persisted, 3);

for (let i = 0; i < 5; i += 1) await service.beginAuthentication({ client: 'alice' });
await assert.rejects(
  service.beginAuthentication({ client: 'alice' }),
  (error) => error.code === 'capacity',
);

console.log('webauthn service: strict hardware, replay, capacity, persistence, and counter checks passed');
