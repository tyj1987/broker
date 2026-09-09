import { createHash, randomUUID } from 'node:crypto';
import { V2Error, canonicalJson } from './operations-v2.js';
import { ExecutionTokenBroker } from './execution-tokens.js';

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
const IDEMPOTENCY_RE = /^[A-Za-z0-9._:-]{16,128}$/;
const MAX_TASKS = 10_000;
const MAX_EVENTS = 64;

function hash(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('base64url');
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
  constructor({ toolRegistry, authorize, approvalBroker, executionTokens, executors = new Map(), now = () => Date.now(), onEvent = () => {}, maxTasks = MAX_TASKS } = {}) {
    this.toolRegistry = toolRegistry;
    this.authorize = authorize;
    this.approvalBroker = approvalBroker;
    this.executionTokens = executionTokens || new ExecutionTokenBroker({ now });
    this.executors = executors;
    this.now = now;
    this.onEvent = onEvent;
    this.maxTasks = maxTasks;
    this.tasks = new Map();
    this.idempotency = new Map();
    this.executionRateLimits = new Map();
  }

  listTools(identity) {
    if (!this.toolRegistry || typeof this.toolRegistry.listFor !== 'function') return [];
    return this.toolRegistry.listFor(identity)
      .filter((tool) => this.executors.has(`${tool.name}@${tool.version}`));
  }

  apiKeyAllowsTask(identity, task) {
    if (identity?.context?.via !== 'api_key') return true;
    if (!this.toolRegistry || typeof this.toolRegistry.listFor !== 'function') return false;
    const apiKey = identity.context.apiKey;
    const toolVisible = this.toolRegistry.listFor(identity)
      .some((candidate) => candidate.name === task.tool.name && candidate.version === task.tool.version);
    return toolVisible
      && apiKey.allowed_accounts?.includes(task.accountRef)
      && apiKey.allowed_resources?.includes(task.parameters?.resource_ref)
      && apiKey.allowed_environments?.includes(task.environment);
  }

  async create(identity, input) {
    if (!identity?.name) throw new V2Error('unauthorized', 'authenticated identity required', 401);
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
        this.transition(task, 'PENDING_APPROVAL', 'approval_requested');
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
      if (task.state === 'PENDING_APPROVAL') {
        approvalClaim = this.approvalBroker.claimFor(identity, operationInput);
        authorizedIdentity = {
          ...identity,
          context: { ...identity.context, approvalGrants: [...(identity.context?.approvalGrants || []), ...approvalClaim.grants] },
        };
        this.transition(task, 'READY', 'approval_claimed');
      }
      const decision = await this.authorize({
        identity: authorizedIdentity, provider: task.tool.provider, operationId: task.tool.operation_id,
        accountRef: task.accountRef, environment: task.environment, typedParameters: structuredClone(task.parameters),
      });
      if (!decision?.allow) {
        task.policyDecision = 'deny';
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.fail(task, decision?.reason || 'policy_denied');
        return publicTask(task);
      }
      task.policyDecision = 'allow';
      const executor = this.executors.get(`${task.tool.name}@${task.tool.version}`);
      if (typeof executor !== 'function') {
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.fail(task, 'executor_unavailable');
        return publicTask(task);
      }
      const remainingMs = Date.parse(task.expiresAt) - this.now();
      if (remainingMs < 1_000) {
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.transition(task, 'EXPIRED', 'task_expired');
        return publicTask(task);
      }
      if (!this.consumeExecutionRateLimit(task)) {
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.fail(task, 'tool_rate_limited');
        return publicTask(task);
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
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        this.fail(task, error instanceof V2Error ? error.code : 'execution_token_failed');
        return publicTask(task);
      }
      this.transition(task, 'EXECUTING', 'executor_started');
      const startedAt = this.now();
      try {
        const timeoutMs = Math.min(task.tool.timeout_ms, remainingMs);
        const timeoutCode = remainingMs <= task.tool.timeout_ms ? 'task_expired' : 'executor_timeout';
        const result = await executeWithDeadline(executor, structuredClone(task.parameters), {
          taskId: task.id, actor: identity.name, accountRef: task.accountRef, environment: task.environment,
          execution: executionGrant,
        }, timeoutMs, timeoutCode);
        assertSchema(result, task.tool.output_schema, 'result');
        task.result = structuredClone(result);
        task.latencyMs = Math.max(0, this.now() - startedAt);
        if (approvalClaim) this.approvalBroker.markSucceeded(approvalClaim.id);
        this.transition(task, 'SUCCEEDED', 'executor_succeeded');
      } catch (error) {
        task.latencyMs = Math.max(0, this.now() - startedAt);
        if (approvalClaim) this.approvalBroker.markFailed(approvalClaim.id);
        if (error instanceof V2Error && error.code === 'task_expired') {
          this.transition(task, 'EXPIRED', 'task_expired');
        } else {
          this.fail(task, error instanceof V2Error ? error.code : 'executor_failed');
        }
      }
      return publicTask(task);
    } finally {
      task.running = false;
    }
  }

  cancel(identity, id) {
    const task = this.getOwned(identity, id);
    this.expire(task);
    if (task.running || !['REQUESTED', 'PENDING_APPROVAL', 'READY'].includes(task.state)) throw new V2Error('invalid_state', 'task cannot be cancelled', 409);
    if (task.approvalId) this.approvalBroker.cancel(identity, task.approvalId);
    this.transition(task, 'CANCELLED', 'caller_cancelled');
    return publicTask(task);
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
      this.transition(task, 'EXPIRED', 'task_expired');
    }
  }

  fail(task, code) {
    task.error = code;
    this.transition(task, 'FAILED', code);
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

  transition(task, state, reason) {
    if (!STATES.has(state)) throw new V2Error('invalid_state', 'unknown task state', 500);
    if (!TRANSITIONS.get(task.state)?.has(state)) throw new V2Error('invalid_state', `task cannot transition from ${task.state || 'NEW'} to ${state}`, 409);
    const timestamp = new Date(this.now()).toISOString();
    const event = { sequence: task.nextSequence, state, reason, at: timestamp };
    this.onEvent({
      task_id: task.id, execution_id: task.executionId || null, actor: task.owner,
      identity: task.identityMethod, role: task.role, policy_decision: task.policyDecision,
      tool: task.tool.name, target: task.parameters.resource_ref, environment: task.environment,
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

  prune() {
    const cutoff = this.now() - 60 * 60_000;
    for (const [id, task] of this.tasks) if (TERMINAL.has(task.state) && Date.parse(task.updatedAt) < cutoff) this.tasks.delete(id);
    const now = this.now();
    for (const [key, bucket] of this.executionRateLimits) if (now >= bucket.expiresAt) this.executionRateLimits.delete(key);
  }
}
