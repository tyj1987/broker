import { createHash, randomUUID } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { V2Error } from './operations-v2.js';

const FLOW_TTL_MS = 5 * 60_000;
const MAX_FLOWS = 1_000;
const MAX_FLOWS_PER_CLIENT = 5;

function credentials(client) {
  return client?.factors?.webauthn?.credentials || [];
}

function webAuthnConfig(config) {
  const value = config?.webauthn || {};
  const rpID = String(value.rp_id || 'broker.52trz.com').toLowerCase();
  const origin = String(value.rp_origin || `https://${rpID}`);
  let parsed;
  try { parsed = new URL(origin); } catch { throw new V2Error('webauthn_unavailable', 'WebAuthn configuration is invalid', 503); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new V2Error('webauthn_unavailable', 'WebAuthn configuration is invalid', 503);
  }
  if (parsed.hostname !== rpID && !parsed.hostname.endsWith(`.${rpID}`)) {
    throw new V2Error('webauthn_unavailable', 'WebAuthn RP ID does not match its origin', 503);
  }
  return { rpID, origin, rpName: String(value.rp_name || 'Secret Broker') };
}

function publicCredential(item) {
  return {
    id: item.id,
    label: item.label,
    transports: item.transports || [],
    device_type: item.device_type,
    backed_up: item.backed_up,
    aaguid: item.aaguid,
    attestation_format: item.attestation_format,
    created_at: item.created_at,
    last_used_at: item.last_used_at || null,
  };
}

export class WebAuthnService {
  constructor({ getConfig, persist, now = () => Date.now(), implementation = {} }) {
    this.getConfig = getConfig;
    this.persist = persist;
    this.now = now;
    this.impl = {
      generateAuthenticationOptions,
      generateRegistrationOptions,
      verifyAuthenticationResponse,
      verifyRegistrationResponse,
      ...implementation,
    };
    this.flows = new Map();
  }

  strictReady(client) {
    return credentials(client).filter((item) => item.device_type === 'singleDevice' && item.backed_up === false).length >= 2;
  }

  list(client) {
    return credentials(client).map(publicCredential);
  }

  async beginAuthentication(input) {
    const clientName = String(input?.client || '');
    const config = this.getConfig();
    const client = config?.clients?.[clientName];
    const stored = credentials(client);
    if (!client || stored.length === 0) throw new V2Error('authentication_denied', 'Authentication could not be started', 401);
    const rp = webAuthnConfig(config);
    const options = await this.impl.generateAuthenticationOptions({
      rpID: rp.rpID,
      allowCredentials: stored.map((item) => ({ id: item.id, transports: item.transports || [] })),
      userVerification: 'required',
      timeout: FLOW_TTL_MS,
    });
    const flowId = this.storeFlow({ kind: 'authentication', clientName, challenge: options.challenge });
    return { flow_id: flowId, options };
  }

  async finishAuthentication(input) {
    const flow = this.takeFlow(input?.flow_id, 'authentication');
    const config = this.getConfig();
    const client = config?.clients?.[flow.clientName];
    const item = credentials(client).find((credential) => credential.id === input?.response?.id);
    if (!client || !item) throw new V2Error('authentication_denied', 'WebAuthn assertion was rejected', 401);
    const rp = webAuthnConfig(config);
    let verification;
    try {
      verification = await this.impl.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: flow.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        credential: {
          id: item.id,
          publicKey: Buffer.from(item.public_key, 'base64url'),
          counter: Number(item.counter || 0),
          transports: item.transports || [],
        },
        requireUserVerification: true,
      });
    } catch {
      throw new V2Error('authentication_denied', 'WebAuthn assertion was rejected', 401);
    }
    if (!verification?.verified || !verification.authenticationInfo) {
      throw new V2Error('authentication_denied', 'WebAuthn assertion was rejected', 401);
    }
    const before = { counter: item.counter, last_used_at: item.last_used_at };
    item.counter = verification.authenticationInfo.newCounter;
    item.last_used_at = new Date(this.now()).toISOString();
    try { await this.persist(); } catch {
      Object.assign(item, before);
      throw new V2Error('persistence_failed', 'Authentication state could not be saved', 503);
    }
    return {
      clientName: flow.clientName,
      client,
      credential: publicCredential(item),
      strictReady: this.strictReady(client),
    };
  }

  async beginRegistration(identity, input) {
    const config = this.getConfig();
    const client = config?.clients?.[identity?.name];
    if (!client) throw new V2Error('forbidden', 'Registration is not allowed', 403);
    const stored = credentials(client);
    const bootstrapping = stored.length === 0;
    const hasWebAuthnStepUp = identity.context?.authFactors?.includes('webauthn') === true;
    if (bootstrapping) {
      if (!['mtls', 'mtls-header'].includes(identity.context?.via) || client.webauthn_bootstrap !== true) {
        throw new V2Error('step_up_required', 'Initial registration requires mTLS and an explicit bootstrap window', 403);
      }
    } else if (!hasWebAuthnStepUp) {
      throw new V2Error('step_up_required', 'An existing security key must authorize registration', 403);
    }
    if (stored.length >= 8) throw new V2Error('capacity', 'Credential limit reached', 409);
    const rp = webAuthnConfig(config);
    const strict = client.security_profile === 'strict';
    const options = await this.impl.generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: identity.name,
      userDisplayName: String(input?.label || identity.name),
      userID: createHash('sha256').update(identity.name).digest(),
      attestationType: strict ? 'direct' : 'none',
      excludeCredentials: stored.map((item) => ({ id: item.id, transports: item.transports || [] })),
      authenticatorSelection: {
        authenticatorAttachment: strict ? 'cross-platform' : undefined,
        residentKey: strict ? 'discouraged' : 'preferred',
        userVerification: 'required',
      },
      preferredAuthenticatorType: strict ? 'securityKey' : undefined,
      timeout: FLOW_TTL_MS,
    });
    const flowId = this.storeFlow({
      kind: 'registration', clientName: identity.name, challenge: options.challenge,
      label: String(input?.label || 'Security key').slice(0, 80), strict,
    });
    return { flow_id: flowId, options };
  }

  async finishRegistration(identity, input) {
    return this.finishRegistrationInternal(identity, input, null);
  }

  async finishRegistrationAndAudit(identity, input, commitAudit) {
    if (typeof commitAudit !== 'function') {
      throw new V2Error('audit_unavailable', 'mandatory audit storage is unavailable', 503);
    }
    return this.finishRegistrationInternal(identity, input, commitAudit);
  }

  async finishRegistrationInternal(identity, input, commitAudit) {
    const flow = this.takeFlow(input?.flow_id, 'registration');
    if (flow.clientName !== identity?.name) throw new V2Error('forbidden', 'Registration identity changed', 403);
    const config = this.getConfig();
    const client = config?.clients?.[flow.clientName];
    if (!client) throw new V2Error('forbidden', 'Registration is not allowed', 403);
    const rp = webAuthnConfig(config);
    let verification;
    try {
      verification = await this.impl.verifyRegistrationResponse({
        response: input?.response,
        expectedChallenge: flow.challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: true,
      });
    } catch {
      throw new V2Error('registration_denied', 'WebAuthn credential was rejected', 400);
    }
    const info = verification?.registrationInfo;
    if (!verification?.verified || !info?.credential) {
      throw new V2Error('registration_denied', 'WebAuthn credential was rejected', 400);
    }
    if (flow.strict && (info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp !== false)) {
      throw new V2Error('hardware_key_required', 'Strict profile requires a non-synced hardware-bound credential', 403);
    }
    const list = credentials(client);
    if (list.some((item) => item.id === info.credential.id)) throw new V2Error('duplicate_credential', 'Credential is already registered', 409);
    if (!client.factors) client.factors = {};
    if (!client.factors.webauthn) client.factors.webauthn = { credentials: [] };
    const item = {
      id: info.credential.id,
      label: flow.label,
      public_key: Buffer.from(info.credential.publicKey).toString('base64url'),
      counter: info.credential.counter,
      transports: input?.response?.response?.transports || [],
      device_type: info.credentialDeviceType,
      backed_up: info.credentialBackedUp,
      aaguid: info.aaguid,
      attestation_format: info.fmt,
      created_at: new Date(this.now()).toISOString(),
    };
    if (commitAudit) commitAudit({ credential_id: item.id });
    client.factors.webauthn.credentials.push(item);
    try { await this.persist(); } catch {
      client.factors.webauthn.credentials = client.factors.webauthn.credentials.filter((value) => value !== item);
      throw new V2Error('persistence_failed', 'Credential could not be saved', 503);
    }
    return { credential: publicCredential(item), strict_ready: this.strictReady(client) };
  }

  storeFlow(value) {
    this.prune();
    if (this.flows.size >= MAX_FLOWS) throw new V2Error('capacity', 'Authentication flow capacity reached', 503);
    const clientFlows = [...this.flows.values()].filter((flow) => flow.clientName === value.clientName).length;
    if (clientFlows >= MAX_FLOWS_PER_CLIENT) {
      throw new V2Error('capacity', 'Authentication flow capacity reached', 503);
    }
    const id = randomUUID();
    this.flows.set(id, { ...value, expiresAt: this.now() + FLOW_TTL_MS });
    return id;
  }

  rollbackFlowCreation(id, kind, clientName) {
    const flow = this.flows.get(id);
    if (!flow || flow.kind !== kind || flow.clientName !== clientName) {
      throw new V2Error('invalid_flow', 'Authentication flow is invalid or expired', 401);
    }
    this.flows.delete(id);
  }

  takeFlow(id, kind) {
    this.prune();
    const flow = this.flows.get(id);
    if (!flow || flow.kind !== kind || flow.expiresAt <= this.now()) {
      throw new V2Error('invalid_flow', 'Authentication flow is invalid or expired', 401);
    }
    this.flows.delete(id);
    return flow;
  }

  prune() {
    const now = this.now();
    for (const [id, flow] of this.flows) if (flow.expiresAt <= now) this.flows.delete(id);
  }
}
