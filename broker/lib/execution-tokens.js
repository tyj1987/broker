import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { V2Error } from './operations-v2.js';

const TOKEN_RE = /^et1\.[A-Za-z0-9_-]{43}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const MAX_TTL_MS = 60_000;
const DEFAULT_TTL_MS = 30_000;
const MAX_RECORDS = 10_000;

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

export class ExecutionTokenBroker {
  constructor({ now = () => Date.now(), maxRecords = MAX_RECORDS } = {}) {
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
    const now = this.now();
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
    if (Date.parse(record.expiresAt) <= this.now()) {
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
    record.consumedAt = new Date(this.now()).toISOString();
    return publicGrant(record);
  }

  revoke(executionId) {
    const tokenHash = this.byId.get(executionId);
    const record = tokenHash ? this.records.get(tokenHash) : null;
    if (!record) throw new V2Error('not_found', 'execution token not found', 404);
    if (record.status !== 'ACTIVE') throw new V2Error('invalid_state', 'execution token cannot be revoked', 409);
    record.status = 'REVOKED';
    record.revokedAt = new Date(this.now()).toISOString();
    return publicGrant(record);
  }

  prune() {
    const cutoff = this.now() - MAX_TTL_MS;
    for (const [tokenHash, record] of this.records) {
      if (Date.parse(record.expiresAt) >= cutoff) continue;
      this.records.delete(tokenHash);
      this.byId.delete(record.id);
    }
  }
}
