import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { ToolRegistry, evaluateToolPolicy } from './tool-registry.js';

const APPROVAL_STATES = Object.freeze({
  REQUESTED: 'requested',
  APPROVED: 'approved',
  DENIED: 'denied',
  EXPIRED: 'expired',
  EXECUTED: 'executed',
});

function stable(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
}

function digest(value) {
  return createHash('sha256').update(stable(value)).digest('hex');
}

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function clone(value) {
  return value == null ? value : structuredClone(value);
}

function assertActor(actor) {
  if (!actor || !['agent', 'human'].includes(actor.type) || !actor.id || !actor.role) {
    throw new ControlPlaneError('invalid_actor', 400);
  }
  return Object.freeze({ type: actor.type, id: String(actor.id), role: String(actor.role) });
}

export class ControlPlaneError extends Error {
  constructor(code, statusCode = 400) {
    super(code);
    this.name = 'ControlPlaneError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class ControlPlane {
  #registry;
  #adapters = new Map();
  #approvals = new Map();
  #usedTokens = new Set();
  #tokenKey;
  #now;
  #audit;
  #revoked = false;

  constructor({ registry = new ToolRegistry(), tokenKey, now = () => Date.now(), audit = () => {} } = {}) {
    this.#registry = registry;
    this.#tokenKey = tokenKey || randomBytes(32);
    this.#now = now;
    this.#audit = audit;
  }

  get registry() {
    return this.#registry;
  }

  registerAdapter(name, handler) {
    if (!this.#registry.get(name)) throw new ControlPlaneError('tool_not_found', 404);
    if (typeof handler !== 'function') throw new TypeError('adapter handler must be a function');
    if (this.#adapters.has(name)) throw new ControlPlaneError('adapter_already_registered', 409);
    this.#adapters.set(name, handler);
  }

  setEmergencyRevoke(revoked, actor) {
    const safeActor = assertActor(actor);
    if (safeActor.type !== 'human' || safeActor.role !== 'human-admin') {
      throw new ControlPlaneError('admin_required', 403);
    }
    this.#revoked = Boolean(revoked);
    this.#emit('control_plane_revoke', { actor: safeActor, result: this.#revoked ? 'revoked' : 'restored' });
    return { revoked: this.#revoked };
  }

  evaluate({ tool: name, actor }) {
    return evaluateToolPolicy({ tool: this.#registry.get(name), actor });
  }

  requestApproval({ tool: name, actor, target = {}, inputs = {}, reason = '', ttlSeconds = 300 }) {
    this.#assertAvailable();
    const safeActor = assertActor(actor);
    const tool = this.#registry.get(name);
    const decision = evaluateToolPolicy({ tool, actor: safeActor });
    if (decision.status !== 'approval_required') {
      throw new ControlPlaneError(decision.status === 'denied' ? decision.reason : 'approval_not_required', 403);
    }
    const ttl = Math.min(Math.max(Number(ttlSeconds) || 300, 30), 900);
    const approval = {
      id: randomUUID(),
      tool: name,
      actor: safeActor,
      targetHash: digest(target),
      inputsHash: digest(inputs),
      reason: String(reason).slice(0, 1000),
      status: APPROVAL_STATES.REQUESTED,
      createdAt: this.#now(),
      expiresAt: this.#now() + ttl * 1000,
    };
    this.#approvals.set(approval.id, approval);
    this.#emit('tool_approval_requested', { actor: safeActor, tool: name, target, decision: 'approval_required', approval_id: approval.id });
    return clone(approval);
  }

  decideApproval({ approvalId, approver, decision }) {
    this.#assertAvailable();
    const safeApprover = assertActor(approver);
    if (safeApprover.type !== 'human' || safeApprover.role !== 'human-admin') {
      throw new ControlPlaneError('admin_required', 403);
    }
    const approval = this.#getLiveApproval(approvalId);
    if (approval.status !== APPROVAL_STATES.REQUESTED) throw new ControlPlaneError('approval_already_decided', 409);
    if (!['approve', 'deny'].includes(decision)) throw new ControlPlaneError('invalid_approval_decision', 400);
    approval.status = decision === 'approve' ? APPROVAL_STATES.APPROVED : APPROVAL_STATES.DENIED;
    approval.decidedAt = this.#now();
    approval.approver = safeApprover;
    this.#emit('tool_approval_decided', { actor: safeApprover, tool: approval.tool, decision: approval.status, approval_id: approval.id });
    return clone(approval);
  }

  issueExecutionToken({ approvalId, actor, target = {}, inputs = {}, ttlSeconds = 120 }) {
    this.#assertAvailable();
    const safeActor = assertActor(actor);
    const approval = this.#getLiveApproval(approvalId);
    if (approval.status !== APPROVAL_STATES.APPROVED) throw new ControlPlaneError('approval_not_approved', 403);
    this.#assertBinding(approval, safeActor, target, inputs);
    const ttl = Math.min(Math.max(Number(ttlSeconds) || 120, 10), 300);
    const payload = {
      jti: randomUUID(), approvalId, tool: approval.tool, actor: safeActor,
      targetHash: approval.targetHash, inputsHash: approval.inputsHash,
      iat: this.#now(), exp: this.#now() + ttl * 1000,
    };
    const body = encode(payload);
    const signature = createHmac('sha256', this.#tokenKey).update(body).digest('base64url');
    this.#emit('execution_token_issued', { actor: safeActor, tool: approval.tool, decision: 'allowed', approval_id: approvalId, token_id: payload.jti });
    return `${body}.${signature}`;
  }

  async invoke({ tool: name, actor, target = {}, inputs = {}, token = null }) {
    this.#assertAvailable();
    const safeActor = assertActor(actor);
    const tool = this.#registry.get(name);
    const decision = evaluateToolPolicy({ tool, actor: safeActor });
    const base = { actor: safeActor, tool: name, target, decision: decision.status };
    if (decision.status === 'denied') {
      this.#emit('tool_execution_denied', { ...base, result: decision.reason });
      throw new ControlPlaneError(decision.reason, 403);
    }
    let approval = null;
    if (decision.status === 'approval_required') {
      if (!token) throw new ControlPlaneError('approval_token_required', 403);
      const payload = this.#verifyToken(token);
      if (payload.tool !== name) throw new ControlPlaneError('token_tool_mismatch', 403);
      if (this.#usedTokens.has(payload.jti)) throw new ControlPlaneError('execution_token_replayed', 409);
      approval = this.#getLiveApproval(payload.approvalId);
      if (approval.status !== APPROVAL_STATES.APPROVED) throw new ControlPlaneError('approval_not_approved', 403);
      this.#assertBinding(approval, safeActor, target, inputs);
      this.#usedTokens.add(payload.jti);
      approval.status = APPROVAL_STATES.EXECUTED;
      approval.executedAt = this.#now();
    }
    const adapter = this.#adapters.get(name);
    if (!adapter) throw new ControlPlaneError('adapter_not_registered', 501);
    const executionId = randomUUID();
    this.#emit('tool_execution_started', { ...base, decision: 'allowed', result: 'executing', execution_id: executionId, approval_id: approval?.id });
    try {
      const result = await adapter({ actor: safeActor, target: clone(target), inputs: clone(inputs), executionId });
      this.#emit('tool_execution_finished', { ...base, decision: 'allowed', result: 'succeeded', execution_id: executionId, approval_id: approval?.id });
      return { status: 'succeeded', executionId, result };
    } catch (error) {
      this.#emit('tool_execution_finished', { ...base, decision: 'allowed', result: 'failed', execution_id: executionId, approval_id: approval?.id, error: error?.code || 'adapter_failed' });
      throw new ControlPlaneError('adapter_failed', 502);
    }
  }

  getApproval(id) {
    const approval = this.#approvals.get(id);
    if (!approval) throw new ControlPlaneError('approval_not_found', 404);
    if (approval.status === APPROVAL_STATES.REQUESTED && approval.expiresAt <= this.#now()) approval.status = APPROVAL_STATES.EXPIRED;
    return clone(approval);
  }

  #assertAvailable() {
    if (this.#revoked) throw new ControlPlaneError('control_plane_revoked', 503);
  }

  #getLiveApproval(id) {
    const approval = this.#approvals.get(id);
    if (!approval) throw new ControlPlaneError('approval_not_found', 404);
    if (approval.expiresAt <= this.#now()) {
      approval.status = APPROVAL_STATES.EXPIRED;
      throw new ControlPlaneError('approval_expired', 410);
    }
    return approval;
  }

  #assertBinding(approval, actor, target, inputs) {
    if (approval.actor.type !== actor.type || approval.actor.id !== actor.id || approval.actor.role !== actor.role) {
      throw new ControlPlaneError('approval_actor_mismatch', 403);
    }
    if (approval.targetHash !== digest(target)) throw new ControlPlaneError('approval_target_mismatch', 403);
    if (approval.inputsHash !== digest(inputs)) throw new ControlPlaneError('approval_inputs_mismatch', 403);
  }

  #verifyToken(token) {
    const [body, supplied, extra] = String(token).split('.');
    if (!body || !supplied || extra) throw new ControlPlaneError('invalid_execution_token', 401);
    const expected = createHmac('sha256', this.#tokenKey).update(body).digest();
    let actual;
    try { actual = Buffer.from(supplied, 'base64url'); } catch { throw new ControlPlaneError('invalid_execution_token', 401); }
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new ControlPlaneError('invalid_execution_token', 401);
    let payload;
    try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { throw new ControlPlaneError('invalid_execution_token', 401); }
    if (!payload.jti || payload.exp <= this.#now()) throw new ControlPlaneError('execution_token_expired', 401);
    return payload;
  }

  #emit(action, fields) {
    this.#audit({ timestamp: new Date(this.#now()).toISOString(), action, ...clone(fields) });
  }
}

export { APPROVAL_STATES };
