import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function credentialsFor(client) {
  client.factors ||= {};
  client.factors.webauthn ||= { credentials: [] };
  client.factors.webauthn.credentials ||= [];
  return client.factors.webauthn.credentials;
}

function publicCredential(c) {
  return {
    credential_id: c.credential_id,
    transports: c.transports || [],
    aaguid: c.aaguid || null,
    sign_count: c.counter || 0,
    device_type: c.device_type,
    created_at: c.created_at,
  };
}

export function createWebAuthnService({
  config,
  persistConfig,
  audit = () => {},
  now = () => Date.now(),
  challengeTtlMs = DEFAULT_TTL_MS,
  library = {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
  },
} = {}) {
  if (!config?.clients) throw new Error('WebAuthn requires config.clients');
  if (typeof persistConfig !== 'function') throw new Error('WebAuthn requires persistConfig');
  const challenges = new Map();

  function client(name) {
    const value = config.clients[name];
    if (!value) throw new Error('client not found');
    return value;
  }

  function saveChallenge(kind, clientName, challenge) {
    challenges.set(`${kind}:${clientName}`, { challenge, expiresAt: now() + challengeTtlMs });
  }

  function consumeChallenge(kind, clientName) {
    const key = `${kind}:${clientName}`;
    const record = challenges.get(key);
    challenges.delete(key);
    if (!record || record.expiresAt < now()) throw new Error('challenge expired or missing');
    return record.challenge;
  }

  function rp() {
    const cfg = config.webauthn || {};
    if (!cfg.rp_id || !cfg.origin) throw new Error('webauthn.rp_id and webauthn.origin are required');
    return { rpID: cfg.rp_id, origin: cfg.origin, rpName: cfg.rp_name || 'Secret Broker' };
  }

  async function beginRegistration(clientName, displayName) {
    const c = client(clientName);
    const current = credentialsFor(c);
    const { rpID, rpName } = rp();
    const options = await library.generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(clientName, 'utf8'),
      userName: clientName,
      userDisplayName: displayName || clientName,
      attestationType: 'direct',
      preferredAuthenticatorType: 'securityKey',
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials: current.map((item) => ({ id: item.credential_id, transports: item.transports || [] })),
    });
    saveChallenge('register', clientName, options.challenge);
    audit({ action: 'webauthn_register_begin', client: clientName, status: 'ok' });
    return options;
  }

  async function finishRegistration(clientName, response) {
    const c = client(clientName);
    const expectedChallenge = consumeChallenge('register', clientName);
    const { rpID, origin } = rp();
    const verification = await library.verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    });
    const info = verification.registrationInfo;
    if (!verification.verified || !info?.userVerified) throw new Error('WebAuthn registration verification failed');
    if (info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp) {
      throw new Error('strict profile requires a non-synced hardware authenticator');
    }
    if (!info.fmt || info.fmt === 'none') throw new Error('attestation statement is required');
    const list = credentialsFor(c);
    const id = info.credential.id;
    if (list.some((item) => item.credential_id === id)) throw new Error('credential already registered');
    for (const [otherName, otherClient] of Object.entries(config.clients)) {
      if (otherName !== clientName && credentialsFor(otherClient).some((item) => item.credential_id === id)) {
        throw new Error('credential is already bound to another identity');
      }
    }
    const stored = {
      credential_id: id,
      public_key: Buffer.from(info.credential.publicKey).toString('base64url'),
      counter: info.credential.counter || 0,
      transports: response.response?.transports || [],
      aaguid: info.aaguid || null,
      fmt: info.fmt,
      device_type: info.credentialDeviceType,
      backed_up: false,
      created_at: new Date(now()).toISOString(),
    };
    list.push(stored);
    try {
      await persistConfig();
    } catch (error) {
      list.pop();
      throw error;
    }
    audit({ action: 'webauthn_register_finish', client: clientName, status: 'ok', credential_id: id });
    return publicCredential(stored);
  }

  async function beginAuthentication(clientName) {
    const list = credentialsFor(client(clientName));
    if (!list.length) throw new Error('no registered WebAuthn credential');
    const { rpID } = rp();
    const options = await library.generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      allowCredentials: list.map((item) => ({ id: item.credential_id, transports: item.transports || [] })),
    });
    saveChallenge('authenticate', clientName, options.challenge);
    audit({ action: 'webauthn_auth_begin', client: clientName, status: 'ok' });
    return options;
  }

  async function finishAuthentication(clientName, response) {
    const list = credentialsFor(client(clientName));
    const stored = list.find((item) => item.credential_id === response.id);
    if (!stored) throw new Error('credential not registered');
    const expectedChallenge = consumeChallenge('authenticate', clientName);
    const { rpID, origin } = rp();
    const verification = await library.verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: stored.credential_id,
        publicKey: new Uint8Array(Buffer.from(stored.public_key, 'base64url')),
        counter: stored.counter || 0,
        transports: stored.transports || [],
      },
    });
    const info = verification.authenticationInfo;
    if (!verification.verified || !info?.userVerified) throw new Error('WebAuthn authentication verification failed');
    if (info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp) {
      throw new Error('strict profile requires a non-synced hardware authenticator');
    }
    const previous = stored.counter || 0;
    if (info.newCounter > 0 && previous > 0 && info.newCounter <= previous) {
      throw new Error('authenticator counter rollback detected');
    }
    stored.counter = info.newCounter;
    try {
      await persistConfig();
    } catch (error) {
      stored.counter = previous;
      throw error;
    }
    audit({ action: 'webauthn_auth_finish', client: clientName, status: 'ok', credential_id: stored.credential_id });
    return { verified: true, credential_id: stored.credential_id };
  }

  return {
    beginAuthentication,
    beginRegistration,
    finishAuthentication,
    finishRegistration,
    listCredentials: (clientName) => credentialsFor(client(clientName)).map(publicCredential),
  };
}
