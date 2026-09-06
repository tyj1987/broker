import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const APPROVAL_TTL_MS = 10 * 60 * 1000;
const REAUTH_TTL_MS = 5 * 60 * 1000;

function token() {
  return randomBytes(32).toString('base64url');
}

export function payloadDigest(payload) {
  const canonicalize = (value) => {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
    }
    return value;
  };
  const canonical = JSON.stringify(canonicalize(payload));
  return createHash('sha256').update(canonical).digest('hex');
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

export function createSensitiveApprovalStore({ now = () => Date.now(), audit = () => {} } = {}) {
  const reauth = new Map();
  const approvals = new Map();

  function issueReauth({ clientName, sessionId, method, credentialId }) {
    if (!clientName || !sessionId || method !== 'webauthn' || !credentialId) {
      throw new Error('verified WebAuthn context is required');
    }
    const value = token();
    reauth.set(value, {
      clientName, sessionId, method, credentialId,
      expiresAt: now() + REAUTH_TTL_MS,
      used: false,
    });
    audit({ action: 'reauth_grant_issued', client: clientName, status: 'ok', method });
    return { grant: value, expires_in: REAUTH_TTL_MS / 1000 };
  }

  function verifyReauth(grant, { clientName, sessionId }, consume = false) {
    const record = reauth.get(grant);
    if (!record || record.used || record.expiresAt < now()) return false;
    if (!safeEqual(record.clientName, clientName) || !safeEqual(record.sessionId, sessionId)) return false;
    if (consume) {
      record.used = true;
      reauth.delete(grant);
    }
    return record;
  }

  function requestApproval({ requester, action, resource, payload, reauthGrant, sessionId }) {
    const verifiedReauth = verifyReauth(reauthGrant, { clientName: requester, sessionId }, true);
    if (!verifiedReauth) {
      throw new Error('valid reauthentication grant required');
    }
    if (!action || !resource) throw new Error('action and resource are required');
    const id = token();
    const record = {
      id,
      requester,
      action,
      resource,
      payload_digest: payloadDigest(payload),
      created_at: new Date(now()).toISOString(),
      expiresAt: now() + APPROVAL_TTL_MS,
      approvers: [],
      requesterCredentialId: verifiedReauth.credentialId,
      consumed: false,
    };
    approvals.set(id, record);
    audit({ action: 'approval_requested', client: requester, operation: action, resource, approval_id: id, status: 'pending' });
    return { approval_id: id, expires_in: APPROVAL_TTL_MS / 1000, payload_digest: record.payload_digest };
  }

  function approve({ approvalId, approver, role, reauthGrant, sessionId }) {
    const record = approvals.get(approvalId);
    if (!record || record.consumed || record.expiresAt < now()) throw new Error('approval not found or expired');
    if (role !== 'admin') throw new Error('admin role required');
    if (record.requester === approver) throw new Error('requester cannot approve own operation');
    if (record.approvers.includes(approver)) throw new Error('duplicate approver');
    const verifiedReauth = verifyReauth(reauthGrant, { clientName: approver, sessionId }, true);
    if (!verifiedReauth) {
      throw new Error('valid reauthentication grant required');
    }
    if (safeEqual(record.requesterCredentialId, verifiedReauth.credentialId)) {
      throw new Error('a distinct hardware authenticator is required');
    }
    record.approvers.push(approver);
    audit({ action: 'approval_granted', client: approver, approval_id: approvalId, operation: record.action, status: 'ok' });
    return { approval_id: approvalId, approvals: record.approvers.length, ready: record.approvers.length >= 1 };
  }

  function consumeApproval({ approvalId, requester, action, resource, payload }) {
    const record = approvals.get(approvalId);
    if (!record || record.consumed || record.expiresAt < now()) throw new Error('approval not found or expired');
    if (record.requester !== requester || record.action !== action || record.resource !== resource) {
      throw new Error('approval binding mismatch');
    }
    if (!safeEqual(record.payload_digest, payloadDigest(payload))) throw new Error('approval payload mismatch');
    if (record.approvers.length < 1) throw new Error('second administrator approval required');
    record.consumed = true;
    approvals.delete(approvalId);
    audit({ action: 'approval_consumed', client: requester, approval_id: approvalId, operation: action, status: 'ok' });
    return true;
  }

  return { approve, consumeApproval, issueReauth, requestApproval, verifyReauth };
}
