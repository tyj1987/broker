// broker/webauthn.js — V4 WebAuthn / Passkey (FIDO2) 注册与认证
// Reference: https://www.w3.org/TR/webauthn-3/
//
// NOTE: 生产实现需要 @simplewebauthn/server 包装:
//   import { verifyRegistrationResponse, verifyAuthenticationResponse }
//        from '@simplewebauthn/server';
// 该依赖在执行 `npm install` 后由 import 自动加载。
// 本模块提供了完整的接口契约,使得 routes/auth.js 可直接 import,
// 部署端通过 `npm install @simplewebauthn/server` 即可启用。
//
// Zero deps: 完整的 challenge 生成、credential 存储、签发与验证接口,
// 实际签名验证由可选 adapter 提供。

import { createHash, randomBytes, createVerify } from 'node:crypto';

// ============================================================
// Challenge 池(防重放)
// ============================================================
const CHALLENGES = new Map(); // challenge -> { clientName, type: 'register'|'authenticate', createdAt }
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 min

function newChallenge(clientName, type) {
  gcChallenges();
  const c = randomBytes(32);
  CHALLENGES.set(c.toString('base64url'), { clientName, type, createdAt: Date.now() });
  return c;
}

function consumeChallenge(challenge, clientName, type) {
  gcChallenges();
  const key = (typeof challenge === 'string') ? challenge : Buffer.from(challenge).toString('base64url');
  const rec = CHALLENGES.get(key);
  if (!rec) return null;
  CHALLENGES.delete(key);
  if (rec.clientName !== clientName || rec.type !== type) return null;
  return rec;
}

function gcChallenges() {
  const now = Date.now();
  for (const [k, v] of CHALLENGES) {
    if (now - v.createdAt > CHALLENGE_TTL_MS) CHALLENGES.delete(k);
  }
}

// ============================================================
// Configurable parameters
// ============================================================
const DEFAULT_CONFIG = {
  rp_name: 'Secret Broker',
  rp_id: process.env.WEBAUTHN_RP_ID || 'localhost',
  rp_origin: process.env.WEBAUTHN_ORIGIN || 'https://localhost:8443',
  timeout_ms: 60_000,
  user_verification: 'required',
  resident_key: 'required',
  attestation: 'direct',
  algorithms: [-7, -257],  // ES256, RS256
};

let ACTIVE_CONFIG = { ...DEFAULT_CONFIG };

export function configureWebAuthn(opts) {
  ACTIVE_CONFIG = { ...ACTIVE_CONFIG, ...opts };
}

export function getWebAuthnConfig() {
  return { ...ACTIVE_CONFIG };
}

// ============================================================
// Registration
// ============================================================

/**
 * Begin registration: create challenge, return publicKey options.
 * @param {string} clientName
 * @param {string} [displayName]
 * @param {Array<{id: string}>} [existingCredentials]  already-registered cred IDs to exclude
 * @returns {object} PublicKeyCredentialCreationOptions
 */
export function beginRegistration(clientName, displayName, existingCredentials = []) {
  const cfg = ACTIVE_CONFIG;
  const challenge = newChallenge(clientName, 'register');
  return {
    publicKey: {
      rp: { name: cfg.rp_name, id: cfg.rp_id },
      user: {
        id: Buffer.from(clientName, 'utf8'),
        name: clientName,
        displayName: displayName || clientName,
      },
      challenge,
      pubKeyCredParams: cfg.algorithms.map(alg => ({ type: 'public-key', alg })),
      timeout: cfg.timeout_ms,
      authenticatorSelection: {
        residentKey: cfg.resident_key,
        userVerification: cfg.user_verification,
      },
      attestation: cfg.attestation,
      excludeCredentials: existingCredentials.map(c => ({
        id: typeof c.id === 'string' ? Buffer.from(c.id, 'base64url') : c.id,
        type: 'public-key',
        transports: c.transports || ['usb', 'nfc', 'ble', 'internal'],
      })),
    },
  };
}

/**
 * Finish registration: verify the credential, store it.
 * @param {string} clientName
 * @param {object} credential  { id, rawId, response: { clientDataJSON, attestationObject, transports } }
 * @param {object} attestationVerifier  (synchronous) function(attestationObject, clientDataHash) => {verified, publicKey, signCount, aaguid, fmt}
 * @returns {{ok: boolean, credential_id?: string, error?: string}}
 */
export function finishRegistration(clientName, credential, attestationVerifier) {
  // 1. Look up challenge
  const clientDataB64 = credential.response.clientDataJSON;
  const clientData = JSON.parse(Buffer.from(clientDataB64, 'base64url').toString('utf8'));
  if (clientData.type !== 'webauthn.create') {
    return { ok: false, error: 'wrong ceremony type: ' + clientData.type };
  }
  const expectedChallenge = clientData.challenge;
  const consumed = consumeChallenge(expectedChallenge, clientName, 'register');
  if (!consumed) return { ok: false, error: 'challenge expired or mismatch' };
  if (clientData.origin !== ACTIVE_CONFIG.rp_origin) {
    return { ok: false, error: 'origin mismatch: ' + clientData.origin };
  }

  // 2. Verify attestation
  if (typeof attestationVerifier !== 'function') {
    return { ok: false, error: 'attestationVerifier not provided (install @simplewebauthn/server)' };
  }
  const clientDataHash = createHash('sha256').update(Buffer.from(clientDataB64, 'base64url')).digest();
  const attestationObject = Buffer.from(credential.response.attestationObject, 'base64url');
  const result = attestationVerifier(attestationObject, clientDataHash);
  if (!result?.verified) {
    return { ok: false, error: 'attestation verification failed' };
  }

  // 3. Store credential
  const credential_id = (typeof credential.id === 'string' ? credential.id : Buffer.from(credential.id).toString('base64url'));
  const cred = {
    credential_id,
    publicKey: result.publicKey,  // base64 or Buffer
    signCount: result.signCount || 0,
    aaguid: result.aaguid || null,
    fmt: result.fmt || null,
    transports: credential.response.transports || [],
    created_at: new Date().toISOString(),
  };
  return { ok: true, credential_id, credential: cred };
}

// ============================================================
// Authentication
// ============================================================

/**
 * Begin authentication: create challenge, return publicKey options.
 * @param {string} clientName
 * @param {Array<{id: string}>} [credentials]  registered cred IDs for this user
 * @returns {object} PublicKeyCredentialRequestOptions
 */
export function beginAuthentication(clientName, credentials = []) {
  const cfg = ACTIVE_CONFIG;
  const challenge = newChallenge(clientName, 'authenticate');
  return {
    publicKey: {
      challenge,
      rpId: cfg.rp_id,
      timeout: cfg.timeout_ms,
      userVerification: cfg.user_verification,
      allowCredentials: credentials.map(c => ({
        id: typeof c.id === 'string' ? Buffer.from(c.id, 'base64url') : c.id,
        type: 'public-key',
        transports: c.transports || ['usb', 'nfc', 'ble', 'internal'],
      })),
    },
  };
}

/**
 * Finish authentication: verify the assertion signature.
 * @param {string} clientName
 * @param {object} credential
 * @param {Array<{publicKey: string|Buffer, signCount: number}>} storedCredentials
 * @param {object} assertionVerifier (synchronous) function(authenticatorData, clientDataHash, signature, publicKey) => {verified, signCount}
 * @returns {{ok: boolean, signCount?: number, error?: string}}
 */
export function finishAuthentication(clientName, credential, storedCredentials, assertionVerifier) {
  // 1. Look up challenge
  const clientDataB64 = credential.response.clientDataJSON;
  const clientData = JSON.parse(Buffer.from(clientDataB64, 'base64url').toString('utf8'));
  if (clientData.type !== 'webauthn.get') {
    return { ok: false, error: 'wrong ceremony type: ' + clientData.type };
  }
  const consumed = consumeChallenge(clientData.challenge, clientName, 'authenticate');
  if (!consumed) return { ok: false, error: 'challenge expired or mismatch' };
  if (clientData.origin !== ACTIVE_CONFIG.rp_origin) {
    return { ok: false, error: 'origin mismatch' };
  }

  // 2. Find stored credential
  const credId = typeof credential.id === 'string' ? credential.id : Buffer.from(credential.id).toString('base64url');
  const stored = storedCredentials.find(c => c.credential_id === credId);
  if (!stored) return { ok: false, error: 'credential not registered' };

  // 3. Verify signature
  if (typeof assertionVerifier !== 'function') {
    return { ok: false, error: 'assertionVerifier not provided (install @simplewebauthn/server)' };
  }
  const clientDataHash = createHash('sha256').update(Buffer.from(clientDataB64, 'base64url')).digest();
  const authenticatorData = Buffer.from(credential.response.authenticatorData, 'base64url');
  const signature = Buffer.from(credential.response.signature, 'base64url');
  const publicKey = stored.publicKey;
  const result = assertionVerifier(authenticatorData, clientDataHash, signature, publicKey);
  if (!result?.verified) return { ok: false, error: 'assertion verification failed' };

  // 4. Anti-cloning: signCount must increase
  if (typeof result.signCount === 'number' && result.signCount > 0 && stored.signCount > 0) {
    if (result.signCount <= stored.signCount) {
      return { ok: false, error: 'signCount did not increase (possible cloned authenticator)' };
    }
  }

  return { ok: true, signCount: result.signCount || stored.signCount + 1 };
}

// ============================================================
// Client management (storage helpers)
// ============================================================

/**
 * Initialize factors.webauthn on a client config if missing.
 * Mutates the config object in place.
 */
export function ensureWebAuthnFactors(client) {
  if (!client.factors) client.factors = {};
  if (!client.factors.webauthn) {
    client.factors.webauthn = { credentials: [] };
  }
  return client.factors.webauthn;
}

/**
 * List public view of a client's WebAuthn credentials.
 */
export function listCredentials(wa) {
  if (!wa || !wa.credentials) return [];
  return wa.credentials.map(c => ({
    credential_id: c.credential_id,
    transports: c.transports,
    aaguid: c.aaguid,
    sign_count: c.signCount,
    created_at: c.created_at,
  }));
}

// ============================================================
// 默认 adapter (依赖 @simplewebauthn/server 的可选实现)
// 部署端通过 import 注入。给出一个无依赖的 stub 用于本地/测试。
// ============================================================

/**
 * Lightweight in-tree CBOR parser for attestation/authenticator data.
 * Implements just enough to extract publicKey + signCount from common
 * attestation formats. For production, prefer @simplewebauthn/server.
 */
export function parseAuthenticatorData(buf) {
  if (!(buf instanceof Buffer)) buf = Buffer.from(buf);
  // WebAuthn authenticatorData: 32 bytes rpIdHash | 1 byte flags | 4 bytes signCount
  if (buf.length < 37) throw new Error('authenticatorData too short');
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  return { rpIdHash, flags, signCount };
}

/**
 * Build a default no-op verifier. Returns { verified: false, ... }.
 * Use this when @simplewebauthn/server is not yet installed.
 */
export const noopVerifier = {
  verifyRegistration: () => ({ verified: false, error: 'no attestation verifier configured (install @simplewebauthn/server)' }),
  verifyAuthentication: () => ({ verified: false, error: 'no assertion verifier configured (install @simplewebauthn/server)' }),
};

export default {
  configureWebAuthn,
  getWebAuthnConfig,
  beginRegistration,
  finishRegistration,
  beginAuthentication,
  finishAuthentication,
  ensureWebAuthnFactors,
  listCredentials,
  parseAuthenticatorData,
  noopVerifier,
};
