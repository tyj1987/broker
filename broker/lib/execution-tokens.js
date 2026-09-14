import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { V2Error } from './operations-v2.js';

const TOKEN_RE = /^et1\.[A-Za-z0-9_-]{43}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const MAX_TTL_MS = 60_000;
const DEFAULT_TTL_MS = 30_000;
const MAX_RECORDS = 10_000;
const MAX_TIME_MS = 8.64e15 - MAX_TTL_MS;
const STATE_VERSION = 1;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_STATES = new Set(['ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED']);
const STATE_RECORD_KEYS = new Set([
  'id', 'actor', 'tool', 'target', 'environment', 'requestBinding',
  'tokenHash', 'nonceHash', 'status', 'issuedAt', 'expiresAt', 'consumedAt', 'revokedAt',
]);

function digest(value) {
  return createHash('sha256').update(value).digest('base64url');
}

function boundedString(value, field, max = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) {
    throw new V2Error('invalid_request', `${field} is invalid`);
  }
  return value;
}

function same(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function publicGrant(record) {
  return {
    execution_id: record.id,
    actor: record.actor,
    tool: record.tool,
    target: record.target,
    environment: record.environment,
    request_binding: record.requestBinding,
    issued_at: record.issuedAt,
    expires_at: record.expiresAt,
  };
}

function stateCorrupt(message) {
  return new V2Error('state_corrupt', `execution token state is invalid: ${message}`, 500);
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function currentTime(now) {
  let value;
  try {
    value = now();
  } catch {
    throw new V2Error('clock_invalid', 'execution token clock is invalid', 500);
  }
  if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_TIME_MS) {
    throw new V2Error('clock_invalid', 'execution token clock is invalid', 500);
  }
  return value;
}

function materializeAndPrune(records, byId, now) {
  const cutoff = now - MAX_TTL_MS;
  for (const [tokenHash, record] of records) {
    const terminalAt = record.consumedAt || record.revokedAt;
    if (Date.parse(record.issuedAt) > now || (terminalAt && Date.parse(terminalAt) > now)) {
      throw stateCorrupt('timestamp is in the future');
    }
    if (record.status === 'ACTIVE' && Date.parse(record.expiresAt) <= now) {
      record.status = 'EXPIRED';
    }
    if (Date.parse(record.expiresAt) >= cutoff) continue;
    records.delete(tokenHash);
    byId.delete(record.id);
  }
}

function validateStateRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw stateCorrupt('record must be an object');
  if (Object.keys(value).some((key) => !STATE_RECORD_KEYS.has(key))) throw stateCorrupt('record contains unknown fields');
  for (const [field, max] of [['actor', 256], ['tool', 256], ['target', 256], ['environment', 32], ['requestBinding', 128]]) {
    if (typeof value[field] !== 'string' || value[field].length < 1 || value[field].length > max) {
      throw stateCorrupt(`${field} is invalid`);
    }
  }
  if (!UUID_RE.test(value.id || '')) throw stateCorrupt('id is invalid');
  if (!DIGEST_RE.test(value.tokenHash || '') || !DIGEST_RE.test(value.nonceHash || '')) {
    throw stateCorrupt('digest is invalid');
  }
  if (!TOKEN_STATES.has(value.status)) throw stateCorrupt('status is invalid');
  if (!validTimestamp(value.issuedAt) || !validTimestamp(value.expiresAt)) throw stateCorrupt('timestamp is invalid');
  const lifetime = Date.parse(value.expiresAt) - Date.parse(value.issuedAt);
  if (lifetime < 1_000 || lifetime > MAX_TTL_MS) throw stateCorrupt('lifetime is invalid');
  if (value.status === 'CONSUMED') {
    if (!validTimestamp(value.consumedAt) || Object.hasOwn(value, 'revokedAt')) throw stateCorrupt('consumption marker is invalid');
    if (Date.parse(value.consumedAt) < Date.parse(value.issuedAt)
      || Date.parse(value.consumedAt) >= Date.parse(value.expiresAt)) {
      throw stateCorrupt('consumption time is invalid');
    }
  } else if (value.status === 'REVOKED') {
    if (!validTimestamp(value.revokedAt) || Object.hasOwn(value, 'consumedAt')) throw stateCorrupt('revocation marker is invalid');
    if (Date.parse(value.revokedAt) < Date.parse(value.issuedAt)
      || Date.parse(value.revokedAt) >= Date.parse(value.expiresAt)) {
      throw stateCorrupt('revocation time is invalid');
    }
  } else if (Object.hasOwn(value, 'consumedAt') || Object.hasOwn(value, 'revokedAt')) {
    throw stateCorrupt('terminal marker conflicts with status');
  }
  return structuredClone(value);
}

export class ExecutionTokenBroker {
  constructor({ now = () => Date.now(), maxRecords = MAX_RECORDS } = {}) {
    if (typeof now !== 'function' || !Number.isSafeInteger(maxRecords)
      || maxRecords < 0 || maxRecords > 1_000_000) {
      throw new TypeError('Execution token broker configuration is invalid');
    }
    this.now = now;
    this.maxRecords = maxRecords;
    this.records = new Map();
    this.byId = new Map();
  }

  issue(input) {
    this.prune();
    if (this.records.size >= this.maxRecords) throw new V2Error('capacity', 'execution token capacity reached', 503);
    const actor = boundedString(input?.actor, 'actor');
    const tool = boundedString(input?.tool, 'tool');
    const target = boundedString(input?.target, 'target');
    const environment = boundedString(input?.environment, 'environment', 32);
    const requestBinding = boundedString(input?.request_binding, 'request_binding', 128);
    const ttlMs = Math.min(Number(input?.ttl_ms || DEFAULT_TTL_MS), MAX_TTL_MS);
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000) throw new V2Error('invalid_request', 'execution token ttl is invalid');
    const token = `et1.${randomBytes(32).toString('base64url')}`;
    const nonce = randomBytes(16).toString('base64url');
    const now = currentTime(this.now);
    const record = {
      id: randomUUID(), actor, tool, target, environment, requestBinding,
      tokenHash: digest(token), nonceHash: digest(nonce), status: 'ACTIVE',
      issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + ttlMs).toISOString(),
    };
    this.records.set(record.tokenHash, record);
    this.byId.set(record.id, record.tokenHash);
    return { execution_id: record.id, token, nonce, expires_at: record.expiresAt };
  }

  consume(token, nonce, expected) {
    if (!TOKEN_RE.test(token || '') || !NONCE_RE.test(nonce || '')) throw new V2Error('invalid_execution_token', 'execution token is invalid', 403);
    const record = this.records.get(digest(token));
    if (!record || record.status !== 'ACTIVE') throw new V2Error('execution_token_replay', 'execution token is unavailable', 409);
    const now = currentTime(this.now);
    if (Date.parse(record.expiresAt) <= now) {
      record.status = 'EXPIRED';
      throw new V2Error('execution_token_expired', 'execution token expired', 409);
    }
    const matches = same(record.nonceHash, digest(nonce))
      && same(record.actor, expected?.actor)
      && same(record.tool, expected?.tool)
      && same(record.target, expected?.target)
      && same(record.environment, expected?.environment)
      && same(record.requestBinding, expected?.request_binding);
    if (!matches) throw new V2Error('execution_token_mismatch', 'execution token binding mismatch', 403);
    record.status = 'CONSUMED';
    record.consumedAt = new Date(now).toISOString();
    return publicGrant(record);
  }

  revoke(executionId) {
    const tokenHash = this.byId.get(executionId);
    const record = tokenHash ? this.records.get(tokenHash) : null;
    if (!record) throw new V2Error('not_found', 'execution token not found', 404);
    const now = currentTime(this.now);
    if (record.status === 'ACTIVE' && Date.parse(record.expiresAt) <= now) {
      record.status = 'EXPIRED';
    }
    if (record.status !== 'ACTIVE') throw new V2Error('invalid_state', 'execution token cannot be revoked', 409);
    record.status = 'REVOKED';
    record.revokedAt = new Date(now).toISOString();
    return publicGrant(record);
  }

  exportState() {
    this.prune();
    return {
      version: STATE_VERSION,
      records: [...this.records.values()].map((record) => structuredClone(record)),
    };
  }

  restoreState(snapshot) {
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
      || Object.keys(snapshot).sort().join(',') !== 'records,version'
      || snapshot.version !== STATE_VERSION || !Array.isArray(snapshot.records)) {
      throw stateCorrupt('snapshot envelope is invalid');
    }
    if (snapshot.records.length > this.maxRecords) throw stateCorrupt('snapshot exceeds capacity');
    const records = new Map();
    const byId = new Map();
    for (const candidate of snapshot.records) {
      const record = validateStateRecord(candidate);
      if (records.has(record.tokenHash) || byId.has(record.id)) throw stateCorrupt('snapshot contains duplicate records');
      records.set(record.tokenHash, record);
      byId.set(record.id, record.tokenHash);
    }
    materializeAndPrune(records, byId, currentTime(this.now));
    this.records = records;
    this.byId = byId;
  }

  prune() {
    materializeAndPrune(this.records, this.byId, currentTime(this.now));
  }
}
