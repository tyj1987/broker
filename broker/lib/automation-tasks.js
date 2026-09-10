import { createHash, randomUUID } from 'node:crypto';
import { V2Error, canonicalJson } from './operations-v2.js';
import { ExecutionTokenBroker } from './execution-tokens.js';
import { redactDeep } from './redact.js';

const STATES = new Set([
  'REQUESTED', 'PENDING_APPROVAL', 'READY', 'EXECUTING',
  'SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELLED',
]);
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELLED']);
const TRANSITIONS = new Map([
  [null, new Set(['REQUESTED'])],
  ['REQUESTED', new Set(['PENDING_APPROVAL', 'READY', 'FAILED', 'EXPIRED', 'CANCELLED'])],
  ['PENDING_APPROVAL', new Set(['READY', 'FAILED', 'EXPIRED', 'CANCELLED'])],
  ['READY', new Set(['EXECUTING', 'FAILED', 'EXPIRED', 'CANCELLED'])],
  ['EXECUTING', new Set(['SUCCEEDED', 'FAILED', 'EXPIRED'])],
]);
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const VERSION_RE = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9._:-]{16,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_RE = /^[A-Za-z0-9_-]{43}$/;
const MAX_TASKS = 10_000;
const MAX_EVENTS = 64;
const STATE_VERSION = 2;
const STATE_KEYS_V1 = new Set(['version', 'tasks', 'idempotency', 'rate_limits']);
const STATE_KEYS_V2 = new Set([...STATE_KEYS_V1, 'emergency_stop']);
const EMERGENCY_STATE_KEYS = new Set([
  'engaged', 'generation', 'changed_at', 'changed_by', 'reason_code', 'approval_id',
]);
const TASK_STATE_KEYS = new Set([
  'id', 'owner', 'tool', 'tool_version', 'account_ref', 'environment', 'parameters',
  'request_fingerprint', 'identity_method', 'role', 'policy_decision', 'state', 'events',
  'next_sequence', 'created_at', 'updated_at', 'expires_at', 'approval_id', 'execution_id',
  'result', 'error', 'latency_ms',
]);
const EVENT_STATE_KEYS = new Set(['sequence', 'state', 'reason', 'at']);
const IDEMPOTENCY_STATE_KEYS = new Set(['key', 'task_id', 'fingerprint']);
const RATE_LIMIT_STATE_KEYS = new Set([
  'owner', 'tool', 'tool_version', 'environment', 'started_at_ms', 'expires_at_ms', 'count',
]);

function hash(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('base64url');
}

function stateCorrupt(message) {
  return new V2Error('state_corrupt', `automation task state is invalid: ${message}`, 500);
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validBoundedString(value, max = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
}

function initialEmergencyStop() {
  return {
    engaged: false, generation: 0, changedAt: null, changedBy: null,
    reasonCode: null, approvalId: null,
  };
}

function exportedEmergencyStop(value) {
  return {
    engaged: value.engaged, generation: value.generation, changed_at: value.changedAt,
    changed_by: value.changedBy, reason_code: value.reasonCode, approval_id: value.approvalId,
  };
}

function restoreEmergencyStop(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !hasExactKeys(value, EMERGENCY_STATE_KEYS)
    || typeof value.engaged !== 'boolean'
    || !Number.isSafeInteger(value.generation) || value.generation < 0) {
    throw stateCorrupt('emergency stop state is invalid');
  }
  if (value.generation === 0) {
    if (value.engaged || value.changed_at !== null || value.changed_by !== null
      || value.reason_code !== null || value.approval_id !== null) {
      throw stateCorrupt('initial emergency stop state is invalid');
    }
  } else if (!validTimestamp(value.changed_at) || !validBoundedString(value.changed_by)
    || !ID_RE.test(value.reason_code || '') || !UUID_RE.test(value.approval_id || '')) {
    throw stateCorrupt('emergency stop change record is invalid');
  }
  return {
    engaged: value.engaged, generation: value.generation, changedAt: value.changed_at,
    changedBy: value.changed_by, reasonCode: value.reason_code, approvalId: value.approval_id,
  };
}

function exportedTask(task) {
  return {
    id: task.id,
    owner: task.owner,
    tool: task.tool.name,
    tool_version: task.tool.version,
    account_ref: task.accountRef,
    environment: task.environment,
    parameters: structuredClone(task.parameters),
    request_fingerprint: task.requestFingerprint,
    identity_method: task.identityMethod,
    role: task.role,
    policy_decision: task.policyDecision,
    state: task.state,
    events: task.events.map((event) => structuredClone(event)),
    next_sequence: task.nextSequence,
    created_at: task.createdAt,
    updated_at: task.updatedAt,
    expires_at: task.expiresAt,
    approval_id: task.approvalId || null,
    execution_id: task.executionId || null,
    result: task.state === 'SUCCEEDED' ? structuredClone(task.result) : null,
    error: task.state === 'FAILED' ? task.error : null,
    latency_ms: Number.isFinite(task.latencyMs) ? task.latencyMs : null,
  };
}

function restoreTaskRecord(value, toolRegistry) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !hasExactKeys(value, TASK_STATE_KEYS)) {
    throw stateCorrupt('task fields are invalid');
  }
  if (!UUID_RE.test(value.id || '') || !validBoundedString(value.owner)
    || !ID_RE.test(value.tool || '') || !VERSION_RE.test(value.tool_version || '')
    || !ID_RE.test(value.account_ref || '') || !ENVIRONMENTS.has(value.environment)
    || !DIGEST_RE.test(value.request_fingerprint || '')
    || !validBoundedString(value.identity_method, 64) || !validBoundedString(value.role, 64)
    || !['allow', 'deny'].includes(value.policy_decision) || !STATES.has(value.state)) {
    throw stateCorrupt('task identity or state is invalid');
  }
  let tool;
  try {
    tool = toolRegistry?.findByName(value.tool, value.tool_version);
  } catch {
    throw stateCorrupt('task tool lookup failed');
  }
  if (!tool) throw stateCorrupt('task tool is not registered');
  let parameters;
  try {
    parameters = structuredClone(value.parameters);
    assertSchema(parameters, tool.input_schema, 'parameters');
  } catch {
    throw stateCorrupt('task parameters are invalid');
  }
  const expectedFingerprint = hash({
    tool: tool.name, version: tool.version, account: value.account_ref,
    environment: value.environment, parameters,
  });
  if (expectedFingerprint !== value.request_fingerprint) throw stateCorrupt('task fingerprint is invalid');
  if (!validTimestamp(value.created_at) || !validTimestamp(value.updated_at) || !validTimestamp(value.expires_at)) {
    throw stateCorrupt('task timestamps are invalid');
  }
  const createdAtMs = Date.parse(value.created_at);
  const updatedAtMs = Date.parse(value.updated_at);
  const expiresAtMs = Date.parse(value.expires_at);
  if (updatedAtMs < createdAtMs || expiresAtMs - createdAtMs < 1 || expiresAtMs - createdAtMs > 900_000) {
    throw stateCorrupt('task timestamp order is invalid');
  }
  if (!Array.isArray(value.events) || value.events.length < 1 || value.events.length > MAX_EVENTS
    || !Number.isSafeInteger(value.next_sequence) || value.next_sequence < 2) {
    throw stateCorrupt('task event sequence is invalid');
  }
  let priorState = null;
  let priorSequence = 0;
  for (const event of value.events) {
    if (!event || typeof event !== 'object' || Array.isArray(event) || !hasExactKeys(event, EVENT_STATE_KEYS)
      || !Number.isSafeInteger(event.sequence) || event.sequence !== priorSequence + 1
      || !STATES.has(event.state) || !TRANSITIONS.get(priorState)?.has(event.state)
      || !validBoundedString(event.reason, 128) || !validTimestamp(event.at)
      || Date.parse(event.at) < createdAtMs || Date.parse(event.at) > updatedAtMs) {
      throw stateCorrupt('task event is invalid');
    }
    priorSequence = event.sequence;
    priorState = event.state;
  }
  if (priorSequence + 1 !== value.next_sequence || priorState !== value.state
    || value.events.at(-1).at !== value.updated_at) {
    throw stateCorrupt('task event head is invalid');
  }
  const approvalId = value.approval_id;
  const executionId = value.execution_id;
  if ((approvalId !== null && !UUID_RE.test(approvalId || ''))
    || (executionId !== null && !UUID_RE.test(executionId || ''))
    || (value.state === 'PENDING_APPROVAL' && approvalId === null)
    || (value.state === 'EXECUTING' && executionId === null)) {
    throw stateCorrupt('task execution binding is invalid');
  }
  let result;
  if (value.state === 'SUCCEEDED') {
    try {
      result = structuredClone(value.result);
      assertSchema(result, tool.output_schema, 'result');
      if (canonicalJson(redactDeep(result)) !== canonicalJson(result)) throw new Error('unsafe');
    } catch {
      throw stateCorrupt('task result is invalid');
    }
    if (value.error !== null || executionId === null) throw stateCorrupt('successful task markers are invalid');
  } else if (value.result !== null) {
    throw stateCorrupt('non-terminal result is invalid');
  }
  if ((value.state === 'FAILED' && !validBoundedString(value.error, 128))
    || (value.state !== 'FAILED' && value.error !== null)) {
    throw stateCorrupt('task error marker is invalid');
  }
  if (value.latency_ms !== null
    && (!Number.isSafeInteger(value.latency_ms) || value.latency_ms < 0)) {
    throw stateCorrupt('task latency is invalid');
  }
  return {
    id: value.id, owner: value.owner, tool, accountRef: value.account_ref,
    environment: value.environment, parameters, requestFingerprint: value.request_fingerprint,
    identityMethod: value.identity_method, role: value.role, policyDecision: value.policy_decision,
    state: value.state, events: structuredClone(value.events), nextSequence: value.next_sequence,
    createdAt: value.created_at, updatedAt: value.updated_at, expiresAt: value.expires_at,
    ...(approvalId ? { approvalId } : {}), ...(executionId ? { executionId } : {}),
    ...(value.state === 'SUCCEEDED' ? { result } : {}),
    ...(value.state === 'FAILED' ? { error: value.error } : {}),
    ...(value.latency_ms !== null ? { latencyMs: value.latency_ms } : {}),
    running: false,
  };
}
async function executeWithDeadline(executor, parameters, context, timeoutMs, timeoutCode) {
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new V2Error(timeoutCode, timeoutCode === 'task_expired' ? 'task expired during execution' : 'executor timed out', 504);
      reject(error);
      controller.abort(error);
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      Promise.resolve().then(() => executor(parameters, { ...context, signal: controller.signal })),
      deadline,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function assertSchema(value, schema, path = 'value') {
  if (schema.const !== undefined && value !== schema.const) throw new V2Error('schema_mismatch', `${path} does not match its fixed value`);
  if (schema.enum && !schema.enum.includes(value)) throw new V2Error('schema_mismatch', `${path} is not an allowed value`);
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new V2Error('schema_mismatch', `${path} must be an object`);
    const properties = schema.properties || {};
    for (const required of schema.required || []) if (!Object.hasOwn(value, required)) throw new V2Error('schema_mismatch', `${path}.${required} is required`);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) if (!Object.hasOwn(properties, key)) throw new V2Error('schema_mismatch', `${path}.${key} is not allowed`);
    }
    for (const [key, item] of Object.entries(value)) if (properties[key]) assertSchema(item, properties[key], `${path}.${key}`);
    return;
  }
  if (schema.type === 'array') {
    if (!Array.isArray(value)) throw new V2Error('schema_mismatch', `${path} must be an array`);
    if (schema.minItems !== undefined && value.length < schema.minItems) throw new V2Error('schema_mismatch', `${path} has too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) throw new V2Error('schema_mismatch', `${path} has too many items`);
    if (schema.items) value.forEach((item, index) => assertSchema(item, schema.items, `${path}[${index}]`));
    return;
  }
  const valid = schema.type === 'string' ? typeof value === 'string'
    : schema.type === 'integer' ? Number.isSafeInteger(value)
      : schema.type === 'number' ? typeof value === 'number' && Number.isFinite(value)
        : schema.type === 'boolean' ? typeof value === 'boolean'
          : true;
  if (!valid) throw new V2Error('schema_mismatch', `${path} has the wrong type`);
  if (typeof value === 'number' && ((schema.minimum !== undefined && value < schema.minimum)
    || (schema.maximum !== undefined && value > schema.maximum))) {
    throw new V2Error('schema_mismatch', `${path} is outside its allowed range`);
  }
  if (typeof value === 'string' && ((schema.minLength !== undefined && value.length < schema.minLength)
    || (schema.maxLength !== undefined && value.length > schema.maxLength))) {
    throw new V2Error('schema_mismatch', `${path} has an invalid length`);
  }
}

function publicTask(task) {
  return {
    id: task.id,
    owner: task.owner,
    tool: task.tool.name,
    tool_version: task.tool.version,
    provider: task.tool.provider,
    operation_id: task.tool.operation_id,
    account_ref: task.accountRef,
    environment: task.environment,
    target: task.parameters.resource_ref,
    risk_level: task.tool.risk_level,
    state: task.state,
    approval_id: task.approvalId || null,
    execution_id: task.executionId || null,
    result: task.state === 'SUCCEEDED' ? structuredClone(task.result) : undefined,
    error: task.error ? { code: task.error } : undefined,
    latency_ms: Number.isFinite(task.latencyMs) ? task.latencyMs : undefined,
    created_at: task.createdAt,
    updated_at: task.updatedAt,
    expires_at: task.expiresAt,
  };
}

function canAdministerOtherTasks(identity) {
  const context = identity?.context;
  return context?.client?.role === 'admin'
    && context.via === 'session'
    && context.authFactors?.includes('webauthn');
}

export class AutomationTaskBroker {
  constructor({ toolRegistry, authorize, approvalBroker, executionTokens, executors = new Map(), now = () => Date.now(), onEvent = () => {}, onCheckpoint = () => {}, maxTasks = MAX_TASKS } = {}) {
    this.toolRegistry = toolRegistry;
    this.authorize = authorize;
    this.approvalBroker = approvalBroker;
    this.executionTokens = executionTokens || new ExecutionTokenBroker({ now });
    this.executors = executors;
    this.now = now;
    this.onEvent = onEvent;
    if (typeof onCheckpoint !== 'function') {
      throw new V2Error('checkpoint_invalid', 'automation task checkpoint handler must be synchronous', 500);
    }
    this.onCheckpoint = onCheckpoint;
    this.maxTasks = maxTasks;
    this.tasks = new Map();
    this.idempotency = new Map();
    this.executionRateLimits = new Map();
    this.emergencyStop = initialEmergencyStop();
  }

  emergencyStatus() {
    return exportedEmergencyStop(this.emergencyStop);
  }

  setEmergencyStop({ engaged, actor, reasonCode, approvalId }) {
    if (typeof engaged !== 'boolean' || !validBoundedString(actor)
      || !ID_RE.test(reasonCode || '') || !UUID_RE.test(approvalId || '')) {
      throw new V2Error('invalid_request', 'emergency stop change is invalid');
    }
    if (this.emergencyStop.engaged === engaged) {
      throw new V2Error('invalid_state', `emergency stop is already ${engaged ? 'engaged' : 'clear'}`, 409);
    }
    const previous = structuredClone(this.emergencyStop);
    const cancelledTasks = [];
    this.emergencyStop = {
      engaged, generation: previous.generation + 1,
      changedAt: new Date(this.now()).toISOString(), changedBy: actor,
      reasonCode, approvalId,
    };
    try {
      if (engaged) {
        for (const task of this.tasks.values()) {
          if (task.running || !['REQUESTED', 'PENDING_APPROVAL', 'READY'].includes(task.state)) continue;
          const cancelled = { task, previous: structuredClone(task), approvalStatus: null };
          cancelledTasks.push(cancelled);
          if (task.approvalId) {
            cancelled.approvalStatus = this.approvalBroker.cancelForTask(task.approvalId);
          }
          this.transition(task, 'CANCELLED', 'emergency_stop');
        }
      }
      this.onEvent({
        actor, identity: 'session', role: 'admin', tool: 'broker.emergency-stop',
        target: 'control-plane', environment: 'production', risk_level: 'CRITICAL',
        policy_decision: 'allow', approval_id: approvalId,
        state: engaged ? 'ENGAGED' : 'CLEARED', reason: reasonCode,
        at: this.emergencyStop.changedAt,
      });
      this.checkpoint(null, engaged ? 'emergency_stop_engaged' : 'emergency_stop_cleared');
    } catch (error) {
      if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
      this.emergencyStop = previous;
      for (const cancelled of cancelledTasks.reverse()) {
        this.tasks.set(cancelled.task.id, cancelled.previous);
        if (cancelled.task.approvalId && cancelled.approvalStatus !== null) {
          try {
            this.approvalBroker.restoreTaskCancellation(
              cancelled.task.approvalId,
              cancelled.approvalStatus,
            );
          } catch {
            throw new V2Error('state_rollback_failed', 'emergency stop rollback failed', 503);
          }
        }
      }
      throw error;
    }
    return this.emergencyStatus();
  }

  assertExecutionEnabled() {
    if (this.emergencyStop.engaged) {
      throw new V2Error('emergency_stop', 'automation execution is disabled by the emergency stop', 503);
    }
  }

  listTools(identity) {
    if (!this.toolRegistry || typeof this.toolRegistry.listFor !== 'function') return [];
    return this.toolRegistry.listFor(identity)
      .filter((tool) => this.executors.has(`${tool.name}@${tool.version}`));
  }

  apiKeyAllowsTask(identity, task) {
    const context = identity?.context;
    const apiKey = context?.apiKey;
    if (!apiKey) return context?.via !== 'api_key';
    if (!this.toolRegistry || typeof this.toolRegistry.listFor !== 'function') return false;
    const toolVisible = this.toolRegistry.listFor(identity)
      .some((candidate) => candidate.name === task.tool.name && candidate.version === task.tool.version);
    return toolVisible
      && apiKey.allowed_accounts?.includes(task.accountRef)
      && apiKey.allowed_resources?.includes(task.parameters?.resource_ref)
      && apiKey.allowed_environments?.includes(task.environment);
  }

  async create(identity, input) {
    if (!validBoundedString(identity?.name)) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    this.assertExecutionEnabled();
    const allowedKeys = new Set(['tool', 'tool_version', 'account_ref', 'environment', 'parameters', 'idempotency_key']);
    if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).some((key) => !allowedKeys.has(key))) throw new V2Error('invalid_request', 'task request contains unknown fields');
    if (!ID_RE.test(input.tool || '') || typeof input.tool_version !== 'string'
      || !ID_RE.test(input.account_ref || '') || !ENVIRONMENTS.has(input.environment)) throw new V2Error('invalid_request', 'task identity or environment is invalid');
    if (!IDEMPOTENCY_RE.test(input.idempotency_key || '')) throw new V2Error('invalid_request', 'idempotency_key must contain 16 to 128 safe characters');
    const tool = this.toolRegistry?.findByName(input.tool, input.tool_version);
    if (!tool) throw new V2Error('tool_unregistered', 'tool and version are not registered', 404);
    const parameters = structuredClone(input.parameters);
    assertSchema(parameters, tool.input_schema, 'parameters');
    if (!this.apiKeyAllowsTask(identity, {
      tool, accountRef: input.account_ref, environment: input.environment, parameters,
    })) {
      throw new V2Error('forbidden', 'API key is not authorized for this task tool', 403);
    }
    if (!this.executors.has(`${tool.name}@${tool.version}`)) {
      throw new V2Error('executor_unavailable', 'tool executor is not available', 503);
    }
    const requestFingerprint = hash({ tool: tool.name, version: tool.version, account: input.account_ref, environment: input.environment, parameters });
    const idempotencyKey = `${identity.name}:${input.idempotency_key}`;
    this.prune();
    const prior = this.idempotency.get(idempotencyKey);
    if (prior) {
      if (prior.fingerprint !== requestFingerprint) throw new V2Error('idempotency_conflict', 'idempotency key is bound to another task', 409);
      if (prior.promise) return publicTask(await prior.promise);
      const priorTask = this.tasks.get(prior.taskId);
      if (priorTask) return publicTask(priorTask);
      this.idempotency.delete(idempotencyKey);
    }
    const pendingCount = [...this.idempotency.values()].filter((entry) => entry.promise).length;
    if (this.tasks.size + pendingCount >= this.maxTasks) throw new V2Error('capacity', 'task capacity reached', 503);
    const pending = (async () => {
      const operation = {
        identity, provider: tool.provider, operationId: tool.operation_id,
        accountRef: input.account_ref, environment: input.environment, typedParameters: parameters,
      };
      const needsApproval = ['HIGH', 'CRITICAL'].includes(tool.risk_level);
      const decision = await this.authorize(operation, needsApproval ? { ignoreApproval: true } : {});
      this.assertExecutionEnabled();
      if (!decision?.allow) throw new V2Error('forbidden', decision?.reason || 'policy_denied', 403);
      const timestamp = this.now();
      const task = {
        id: randomUUID(), owner: identity.name, tool, accountRef: input.account_ref,
        environment: input.environment, parameters, requestFingerprint,
        identityMethod: identity.context?.via || 'unknown', role: identity.context?.client?.role || 'unknown',
        policyDecision: 'allow',
        state: null, events: [], nextSequence: 1, createdAt: new Date(timestamp).toISOString(),
        updatedAt: new Date(timestamp).toISOString(), expiresAt: new Date(timestamp + Math.min(Number(decision.ttlMs || 300_000), 900_000)).toISOString(),
      };
      this.transition(task, 'REQUESTED', 'task_created');
      if (needsApproval) {
        const approval = this.approvalBroker.create(identity, {
          provider: tool.provider, operation_id: tool.operation_id, account_ref: task.accountRef,
          environment: task.environment, typed_parameters: structuredClone(parameters),
        });
        task.approvalId = approval.id;
        try {
          this.transition(task, 'PENDING_APPROVAL', 'approval_requested');
        } catch (error) {
          this.approvalBroker.cancelForTask(approval.id);
          throw error;
        }
      } else {
        this.transition(task, 'READY', 'policy_allowed');
      }
      this.tasks.set(task.id, task);
      return task;
    })();
    this.idempotency.set(idempotencyKey, { fingerprint: requestFingerprint, promise: pending });
    try {
      const task = await pending;
      this.idempotency.set(idempotencyKey, { taskId: task.id, fingerprint: requestFingerprint });
      try {
        this.checkpoint(task, 'created');
      } catch (error) {
        if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
        this.idempotency.delete(idempotencyKey);
        this.tasks.delete(task.id);
        if (task.approvalId) {
          try {
            this.approvalBroker.rollbackCreation(identity, task.approvalId);
          } catch {
            throw new V2Error('state_rollback_failed', 'task creation rollback failed', 503);
          }
        }
        throw error;
      }
      return publicTask(task);
    } catch (error) {
      if (this.idempotency.get(idempotencyKey)?.promise === pending) this.idempotency.delete(idempotencyKey);
      throw error;
    }
  }

  get(identity, id) {
    const task = this.getOwned(identity, id);
    this.expire(task);
    return publicTask(task);
  }

  eventsFor(identity, id) {
    const task = this.getOwned(identity, id);
    this.expire(task);
    return task.events.map((event) => structuredClone(event));
  }

  async run(identity, id) {
    this.assertExecutionEnabled();
    const task = this.getOwned(identity, id);
    this.expire(task);
    if (TERMINAL.has(task.state) || task.state === 'EXECUTING' || task.running) throw new V2Error('invalid_state', 'task is not executable', 409);
    task.running = true;
    try {
      let authorizedIdentity = identity;
      let approvalClaim = null;
      const operationInput = {
        provider: task.tool.provider, operation_id: task.tool.operation_id, account_ref: task.accountRef,
        environment: task.environment, typed_parameters: structuredClone(task.parameters),
        approval_request_id: task.approvalId,
      };
      if (task.approvalId && ['PENDING_APPROVAL', 'READY'].includes(task.state)) {
        approvalClaim = this.approvalBroker.claimFor(identity, operationInput);
        authorizedIdentity = {
          ...identity,
          context: { ...identity.context, approvalGrants: [...(identity.context?.approvalGrants || []), ...approvalClaim.grants] },
        };
        if (task.state === 'PENDING_APPROVAL') {
          try {
            this.transition(task, 'READY', 'approval_claimed');
          } catch (error) {
            this.approvalBroker.releaseClaim(approvalClaim.id);
            throw error;
          }
        }
      }
      let decision;
      try {
        decision = await this.authorize({
          identity: authorizedIdentity, provider: task.tool.provider, operationId: task.tool.operation_id,
          accountRef: task.accountRef, environment: task.environment, typedParameters: structuredClone(task.parameters),
        });
      } catch (error) {
        if (approvalClaim) this.approvalBroker.releaseClaim(approvalClaim.id);
        throw error;
      }
      if (!decision?.allow) {
        task.policyDecision = 'deny';
        return this.completePreExecutionFailure(task, approvalClaim, decision?.reason || 'policy_denied');
      }
      try {
        this.assertExecutionEnabled();
      } catch (error) {
        if (approvalClaim) this.approvalBroker.releaseClaim(approvalClaim.id);
        throw error;
      }
      task.policyDecision = 'allow';
      const executor = this.executors.get(`${task.tool.name}@${task.tool.version}`);
      if (typeof executor !== 'function') {
        return this.completePreExecutionFailure(task, approvalClaim, 'executor_unavailable');
      }
      const remainingMs = Date.parse(task.expiresAt) - this.now();
      if (remainingMs < 1_000) {
        return this.completePreExecutionFailure(task, approvalClaim, 'task_expired', { state: 'EXPIRED' });
      }
      if (!this.consumeExecutionRateLimit(task)) {
        return this.completePreExecutionFailure(task, approvalClaim, 'tool_rate_limited');
      }
      const executionBinding = {
        actor: identity.name,
        tool: `${task.tool.name}@${task.tool.version}`,
        target: task.parameters.resource_ref,
        environment: task.environment,
        request_binding: task.requestFingerprint,
        ttl_ms: Math.min(30_000, remainingMs),
      };
      let executionGrant;
      try {
        const capability = this.executionTokens.issue(executionBinding);
        executionGrant = this.executionTokens.consume(capability.token, capability.nonce, executionBinding);
        task.executionId = executionGrant.execution_id;
      } catch (error) {
        return this.completePreExecutionFailure(
          task,
          approvalClaim,
          error instanceof V2Error ? error.code : 'execution_token_failed',
          { rateLimitConsumed: true },
        );
      }
      try {
        this.transition(task, 'EXECUTING', 'executor_started');
      } catch (error) {
        if (approvalClaim) this.approvalBroker.releaseClaim(approvalClaim.id);
        this.releaseExecutionRateLimit(task);
        throw error;
      }
      this.checkpoint(task, 'pre_execute');
      const startedAt = this.now();
      let result;
      try {
        const timeoutMs = Math.min(task.tool.timeout_ms, remainingMs);
        const timeoutCode = remainingMs <= task.tool.timeout_ms ? 'task_expired' : 'executor_timeout';
        result = await executeWithDeadline(executor, structuredClone(task.parameters), {
          taskId: task.id, actor: identity.name, accountRef: task.accountRef, environment: task.environment,
          execution: executionGrant,
        }, timeoutMs, timeoutCode);
        assertSchema(result, task.tool.output_schema, 'result');
        if (canonicalJson(redactDeep(result)) !== canonicalJson(result)) {
          throw new V2Error('unsafe_result', 'executor result contains credential material', 502);
        }
        if (this.emergencyStop.engaged) {
          throw new V2Error('emergency_stop', 'executor result was discarded after emergency stop activation', 503);
        }
      } catch (error) {
        task.latencyMs = Math.max(0, this.now() - startedAt);
        if (error instanceof V2Error && error.code === 'task_expired') {
          this.transition(task, 'EXPIRED', 'task_expired');
        } else {
          this.fail(task, error instanceof V2Error ? error.code : 'executor_failed');
        }
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.checkpoint(task, 'terminal');
        return publicTask(task);
      }
      task.result = structuredClone(result);
      task.latencyMs = Math.max(0, this.now() - startedAt);
      // Once an executor has been invoked its upstream result may be
      // indeterminate. Commit the terminal audit before consuming the approval
      // terminal state. If audit fails, EXECUTING prevents any caller replay.
      this.transition(task, 'SUCCEEDED', 'executor_succeeded');
      if (approvalClaim) this.approvalBroker.markSucceeded(approvalClaim.id);
      this.checkpoint(task, 'terminal');
      return publicTask(task);
    } finally {
      task.running = false;
    }
  }

  cancel(identity, id) {
    const task = this.getOwned(identity, id);
    this.expire(task);
    if (task.running || !['REQUESTED', 'PENDING_APPROVAL', 'READY'].includes(task.state)) throw new V2Error('invalid_state', 'task cannot be cancelled', 409);
    const previousTask = structuredClone(task);
    let previousApprovalStatus = null;
    try {
      if (task.approvalId) previousApprovalStatus = this.approvalBroker.cancelForTask(task.approvalId);
      this.transition(task, 'CANCELLED', 'caller_cancelled');
      this.checkpoint(task, 'cancelled');
      return publicTask(task);
    } catch (error) {
      if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
      this.tasks.set(task.id, previousTask);
      if (task.approvalId && previousApprovalStatus !== null) {
        try {
          this.approvalBroker.restoreTaskCancellation(task.approvalId, previousApprovalStatus);
        } catch {
          throw new V2Error('state_rollback_failed', 'task cancellation rollback failed', 503);
        }
      }
      this.assertExecutionEnabled();
      throw error;
    }
  }

  getOwned(identity, id) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
    const task = this.tasks.get(id);
    if (!task) throw new V2Error('not_found', 'task not found', 404);
    if (task.owner !== identity.name && !canAdministerOtherTasks(identity)) {
      throw new V2Error('forbidden', 'task is not visible', 403);
    }
    if (!this.apiKeyAllowsTask(identity, task)) {
      throw new V2Error('forbidden', 'API key is not authorized for this task tool', 403);
    }
    return task;
  }

  expire(task) {
    if (!task.running && !TERMINAL.has(task.state) && Date.parse(task.expiresAt) <= this.now()) {
      const wasExecuting = task.state === 'EXECUTING';
      const previousTask = structuredClone(task);
      let previousApprovalStatus = null;
      try {
        if (task.approvalId && wasExecuting) {
          this.approvalBroker.markFailed(task.approvalId);
          previousApprovalStatus = 'EXECUTING';
        } else if (task.approvalId) {
          previousApprovalStatus = this.approvalBroker.cancelForTask(task.approvalId);
        }
        this.transition(task, 'EXPIRED', 'task_expired');
        this.checkpoint(task, 'expired');
      } catch (error) {
        if (error instanceof V2Error && error.code === 'state_commit_indeterminate') throw error;
        this.tasks.set(task.id, previousTask);
        if (task.approvalId && previousApprovalStatus !== null) {
          try {
            if (wasExecuting) this.approvalBroker.rollbackFailed(task.approvalId);
            else this.approvalBroker.restoreTaskCancellation(task.approvalId, previousApprovalStatus);
          } catch {
            throw new V2Error('state_rollback_failed', 'task expiry rollback failed', 503);
          }
        }
        throw error;
      }
    }
  }

  fail(task, code) {
    this.transition(task, 'FAILED', code);
    task.error = code;
  }

  completePreExecutionFailure(task, approvalClaim, code, { state = 'FAILED', rateLimitConsumed = false } = {}) {
    try {
      if (state === 'EXPIRED') this.transition(task, 'EXPIRED', code);
      else this.fail(task, code);
    } catch (error) {
      if (approvalClaim) this.approvalBroker.releaseClaim(approvalClaim.id);
      if (rateLimitConsumed) this.releaseExecutionRateLimit(task);
      throw error;
    }
    if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
    return publicTask(task);
  }

  consumeExecutionRateLimit(task) {
    const now = this.now();
    const windowMs = task.tool.rate_limit.window_seconds * 1_000;
    const key = `${task.owner}\0${task.tool.name}@${task.tool.version}\0${task.environment}`;
    let bucket = this.executionRateLimits.get(key);
    if (!bucket || now >= bucket.expiresAt) {
      bucket = { startedAt: now, expiresAt: now + windowMs, count: 0 };
      this.executionRateLimits.set(key, bucket);
    }
    if (bucket.count >= task.tool.rate_limit.requests) return false;
    bucket.count += 1;
    return true;
  }

  releaseExecutionRateLimit(task) {
    const key = `${task.owner}\0${task.tool.name}@${task.tool.version}\0${task.environment}`;
    const bucket = this.executionRateLimits.get(key);
    if (bucket?.count > 0) bucket.count -= 1;
  }

  transition(task, state, reason) {
    if (!STATES.has(state)) throw new V2Error('invalid_state', 'unknown task state', 500);
    if (!TRANSITIONS.get(task.state)?.has(state)) throw new V2Error('invalid_state', `task cannot transition from ${task.state || 'NEW'} to ${state}`, 409);
    const timestamp = new Date(this.now()).toISOString();
    const event = { sequence: task.nextSequence, state, reason, at: timestamp };
    this.onEvent({
      task_id: task.id, execution_id: task.executionId || null, actor: task.owner,
      identity: task.identityMethod, role: task.role, policy_decision: task.policyDecision,
      tool: task.tool.name, target: redactDeep(task.parameters.resource_ref), environment: task.environment,
      risk_level: task.tool.risk_level, approval_id: task.approvalId || null,
      result: TERMINAL.has(state) ? state.toLowerCase() : undefined,
      error: state === 'FAILED' ? reason : undefined,
      latency_ms: task.latencyMs, ...event,
    });
    // State is committed only after the mandatory audit sink accepts the
    // transition. This prevents execution from advancing without an audit
    // record and leaves the previous state retryable on a storage outage.
    task.state = state;
    task.updatedAt = timestamp;
    task.nextSequence += 1;
    task.events.push(event);
    if (task.events.length > MAX_EVENTS) task.events.shift();
  }

  checkpoint(task, phase) {
    const result = this.onCheckpoint({
      phase,
      task_id: task?.id || null,
      state: task?.state || null,
      execution_id: task?.executionId || null,
      approval_id: task?.approvalId || this.emergencyStop.approvalId || null,
      at: task?.updatedAt || this.emergencyStop.changedAt,
    });
    if (result && typeof result.then === 'function') {
      Promise.resolve(result).catch(() => {});
      throw new V2Error('checkpoint_invalid', 'automation task checkpoint handler must be synchronous', 500);
    }
  }

  exportState() {
    if ([...this.idempotency.values()].some((entry) => entry.promise)) {
      throw new V2Error('state_busy', 'automation task state has active mutations', 409);
    }
    this.prune();
    return {
      version: STATE_VERSION,
      emergency_stop: exportedEmergencyStop(this.emergencyStop),
      tasks: [...this.tasks.values()].map(exportedTask),
      idempotency: [...this.idempotency.entries()]
        .filter(([, entry]) => entry.taskId && this.tasks.has(entry.taskId))
        .map(([key, entry]) => ({ key, task_id: entry.taskId, fingerprint: entry.fingerprint })),
      rate_limits: [...this.executionRateLimits.entries()].map(([key, bucket]) => {
        const [owner, toolIdentity, environment] = key.split('\0');
        const separator = toolIdentity.lastIndexOf('@');
        return {
          owner,
          tool: toolIdentity.slice(0, separator),
          tool_version: toolIdentity.slice(separator + 1),
          environment,
          started_at_ms: bucket.startedAt,
          expires_at_ms: bucket.expiresAt,
          count: bucket.count,
        };
      }),
    };
  }

  restoreState(snapshot) {
    if ([...this.tasks.values()].some((task) => task.running)
      || [...this.idempotency.values()].some((entry) => entry.promise)) {
      throw new V2Error('state_busy', 'automation task state has active mutations', 409);
    }
    const stateKeys = snapshot?.version === 1 ? STATE_KEYS_V1 : STATE_KEYS_V2;
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
      || !hasExactKeys(snapshot, stateKeys) || ![1, STATE_VERSION].includes(snapshot.version)
      || !Array.isArray(snapshot.tasks) || !Array.isArray(snapshot.idempotency)
      || !Array.isArray(snapshot.rate_limits)) {
      throw stateCorrupt('snapshot envelope is invalid');
    }
    if (snapshot.tasks.length > this.maxTasks || snapshot.idempotency.length > this.maxTasks
      || snapshot.rate_limits.length > this.maxTasks) {
      throw stateCorrupt('snapshot exceeds capacity');
    }
    const tasks = new Map();
    for (const candidate of snapshot.tasks) {
      const task = restoreTaskRecord(candidate, this.toolRegistry);
      if (tasks.has(task.id)) throw stateCorrupt('snapshot contains duplicate tasks');
      tasks.set(task.id, task);
    }
    const idempotency = new Map();
    const boundTasks = new Set();
    for (const candidate of snapshot.idempotency) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
        || !hasExactKeys(candidate, IDEMPOTENCY_STATE_KEYS)
        || !validBoundedString(candidate.key, 512) || !UUID_RE.test(candidate.task_id || '')
        || !DIGEST_RE.test(candidate.fingerprint || '')) {
        throw stateCorrupt('idempotency binding is invalid');
      }
      const task = tasks.get(candidate.task_id);
      const separator = candidate.key.lastIndexOf(':');
      if (!task || separator < 1 || candidate.key.slice(0, separator) !== task.owner
        || !IDEMPOTENCY_RE.test(candidate.key.slice(separator + 1))
        || candidate.fingerprint !== task.requestFingerprint
        || idempotency.has(candidate.key) || boundTasks.has(task.id)) {
        throw stateCorrupt('idempotency binding does not match a task');
      }
      idempotency.set(candidate.key, { taskId: task.id, fingerprint: candidate.fingerprint });
      boundTasks.add(task.id);
    }
    const executionRateLimits = new Map();
    for (const candidate of snapshot.rate_limits) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
        || !hasExactKeys(candidate, RATE_LIMIT_STATE_KEYS) || !validBoundedString(candidate.owner)
        || !ID_RE.test(candidate.tool || '') || !VERSION_RE.test(candidate.tool_version || '')
        || !ENVIRONMENTS.has(candidate.environment)
        || !Number.isSafeInteger(candidate.started_at_ms) || !Number.isSafeInteger(candidate.expires_at_ms)
        || candidate.started_at_ms < 0 || candidate.expires_at_ms <= candidate.started_at_ms
        || !Number.isSafeInteger(candidate.count) || candidate.count < 0) {
        throw stateCorrupt('rate limit bucket is invalid');
      }
      let tool;
      try {
        tool = this.toolRegistry?.findByName(candidate.tool, candidate.tool_version);
      } catch {
        throw stateCorrupt('rate limit tool lookup failed');
      }
      if (!tool || candidate.expires_at_ms - candidate.started_at_ms !== tool.rate_limit.window_seconds * 1_000
        || candidate.count > tool.rate_limit.requests) {
        throw stateCorrupt('rate limit bucket exceeds its registered policy');
      }
      const key = `${candidate.owner}\0${tool.name}@${tool.version}\0${candidate.environment}`;
      if (executionRateLimits.has(key)) throw stateCorrupt('snapshot contains duplicate rate limits');
      executionRateLimits.set(key, {
        startedAt: candidate.started_at_ms,
        expiresAt: candidate.expires_at_ms,
        count: candidate.count,
      });
    }
    this.tasks = tasks;
    this.idempotency = idempotency;
    this.executionRateLimits = executionRateLimits;
    this.emergencyStop = snapshot.version === 1
      ? initialEmergencyStop()
      : restoreEmergencyStop(snapshot.emergency_stop);
    this.prune();
  }

  prune() {
    const cutoff = this.now() - 60 * 60_000;
    for (const [id, task] of this.tasks) if (TERMINAL.has(task.state) && Date.parse(task.updatedAt) < cutoff) this.tasks.delete(id);
    for (const [key, entry] of this.idempotency) {
      if (entry.taskId && !this.tasks.has(entry.taskId)) this.idempotency.delete(key);
    }
    const now = this.now();
    for (const [key, bucket] of this.executionRateLimits) if (now >= bucket.expiresAt) this.executionRateLimits.delete(key);
  }
}
