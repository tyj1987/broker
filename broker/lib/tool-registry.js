import { readFileSync } from 'node:fs';

const TOOL_NAME = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const RISK_LEVELS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const ROLES = new Set(['viewer', 'developer', 'operator', 'admin']);
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const AGENT_IDENTITY_METHODS = new Set(['api_key', 'workload', 'workload_identity', 'oidc', 'mcp', 'agent']);
const TOOL_KEYS = new Set([
  'name', 'version', 'description', 'provider', 'operation_id', 'input_schema', 'output_schema',
  'required_role', 'risk_level', 'environments', 'target', 'timeout_ms', 'rate_limit',
  'approval_policy', 'audit_policy', 'agent_execution',
]);

function assertObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(message);
}

function assertClosedSchema(schema, field, tool) {
  assertObject(schema, `${tool}: ${field} must be an object schema`);
  if (schema.type !== 'object' || schema.additionalProperties !== false) {
    throw new Error(`${tool}: ${field} must deny additional properties`);
  }
  assertObject(schema.properties, `${tool}: ${field}.properties is required`);
  const properties = new Set(Object.keys(schema.properties));
  for (const required of schema.required || []) {
    if (!properties.has(required)) throw new Error(`${tool}: ${field} requires undefined property ${required}`);
  }
}

function validateTool(tool) {
  assertObject(tool, 'tool registry entry must be an object');
  for (const key of Object.keys(tool)) if (!TOOL_KEYS.has(key)) throw new Error(`${tool.name || 'tool'}: unknown field ${key}`);
  for (const key of TOOL_KEYS) if (!Object.hasOwn(tool, key)) throw new Error(`${tool.name || 'tool'}: missing field ${key}`);
  if (!TOOL_NAME.test(tool.name) || !VERSION.test(tool.version)) throw new Error(`${tool.name || 'tool'}: invalid identity`);
  if (typeof tool.description !== 'string' || tool.description.length < 12 || tool.description.length > 240) throw new Error(`${tool.name}: invalid description`);
  if (!ROLES.has(tool.required_role) || !RISK_LEVELS.has(tool.risk_level)) throw new Error(`${tool.name}: invalid role or risk level`);
  if (!Array.isArray(tool.environments) || tool.environments.length === 0
    || new Set(tool.environments).size !== tool.environments.length
    || tool.environments.some((item) => !ENVIRONMENTS.has(item))) throw new Error(`${tool.name}: invalid environments`);
  assertClosedSchema(tool.input_schema, 'input_schema', tool.name);
  assertClosedSchema(tool.output_schema, 'output_schema', tool.name);
  if (!Object.hasOwn(tool.input_schema.properties, 'resource_ref') || tool.target?.resource_parameter !== 'resource_ref') {
    throw new Error(`${tool.name}: target must bind input resource_ref`);
  }
  if (!Number.isSafeInteger(tool.timeout_ms) || tool.timeout_ms < 100 || tool.timeout_ms > 120000) throw new Error(`${tool.name}: invalid timeout`);
  if (!Number.isSafeInteger(tool.rate_limit?.requests) || tool.rate_limit.requests < 1
    || !Number.isSafeInteger(tool.rate_limit?.window_seconds) || tool.rate_limit.window_seconds < 1) throw new Error(`${tool.name}: invalid rate limit`);
  const approvals = tool.approval_policy?.approvals_required;
  const mode = tool.approval_policy?.mode;
  if (!['none', 'step_up', 'two_person'].includes(mode) || !Number.isSafeInteger(approvals) || approvals < 0) throw new Error(`${tool.name}: invalid approval policy`);
  if (mode === 'none' && approvals !== 0) throw new Error(`${tool.name}: approval count conflicts with mode`);
  if (mode === 'step_up' && approvals < 1) throw new Error(`${tool.name}: step-up requires approval`);
  if (mode === 'two_person' && approvals < 2) throw new Error(`${tool.name}: dual control requires two approvals`);
  if (['HIGH', 'CRITICAL'].includes(tool.risk_level) && approvals < 1) throw new Error(`${tool.name}: high-risk tool requires approval`);
  if (tool.risk_level === 'CRITICAL' && tool.agent_execution !== false) throw new Error(`${tool.name}: critical tool must deny agent execution`);
  if (tool.audit_policy?.required !== true || !Array.isArray(tool.audit_policy?.redact)) throw new Error(`${tool.name}: mandatory audit policy is required`);
}

function publicTool(tool) {
  return structuredClone(tool);
}

function isAgentIdentity(identity) {
  const context = identity?.context;
  if (context?.client?.principal_type) return context.client.principal_type !== 'human';
  return context?.via !== 'session' || AGENT_IDENTITY_METHODS.has(context?.via);
}

export class ToolRegistry {
  constructor(document) {
    assertObject(document, 'tool registry must be an object');
    if (document.registry_version !== 1 || !Array.isArray(document.tools) || document.tools.length === 0) {
      throw new Error('tool registry version 1 with at least one tool is required');
    }
    this.byOperation = new Map();
    this.byName = new Map();
    for (const item of document.tools) {
      validateTool(item);
      const operationKey = `${item.provider}:${item.operation_id}`;
      const nameKey = `${item.name}@${item.version}`;
      if (this.byOperation.has(operationKey) || this.byName.has(nameKey)) throw new Error(`${item.name}: duplicate tool registration`);
      const tool = structuredClone(item);
      this.byOperation.set(operationKey, tool);
      this.byName.set(nameKey, tool);
    }
  }

  find(provider, operationId) {
    const tool = this.byOperation.get(`${provider}:${operationId}`);
    return tool ? publicTool(tool) : null;
  }

  listFor(identity) {
    const role = identity?.context?.client?.role;
    if (!role) return [];
    return [...this.byOperation.values()]
      .filter((tool) => (role === 'admin' || role === tool.required_role)
        && (!isAgentIdentity(identity) || tool.agent_execution === true))
      .map(publicTool);
  }

  validateConfiguration(config) {
    const policies = config?.operation_policies;
    if (!policies || typeof policies !== 'object' || Array.isArray(policies)) {
      throw new Error('operation_policies must be configured for the tool registry');
    }
    for (const [provider, operations] of Object.entries(policies)) {
      if (!operations || typeof operations !== 'object' || Array.isArray(operations)) {
        throw new Error(`operation_policies.${provider} must be an object`);
      }
      for (const [operationId, policy] of Object.entries(operations)) {
        if (policy?.enabled !== true) continue;
        const tool = this.byOperation.get(`${provider}:${operationId}`);
        if (!tool) throw new Error(`${provider}:${operationId}: enabled operation is not registered`);
        if (!Array.isArray(policy.environments)
          || policy.environments.some((environment) => !tool.environments.includes(environment))) {
          throw new Error(`${provider}:${operationId}: policy environment exceeds tool registration`);
        }
        const registeredParameters = Object.keys(tool.input_schema.properties).sort();
        const policyParameters = Object.keys(policy.parameter_schema?.properties || {}).sort();
        if (registeredParameters.join('\n') !== policyParameters.join('\n')) {
          throw new Error(`${provider}:${operationId}: policy parameters differ from tool registration`);
        }
        if (['HIGH', 'CRITICAL'].includes(tool.risk_level)
          && (policy.approval_required !== true
            || Number(policy.required_approvals || 1) < tool.approval_policy.approvals_required)) {
          throw new Error(`${provider}:${operationId}: policy weakens tool approval requirements`);
        }
      }
    }
    return true;
  }

  evaluate(request, preliminary, options = {}) {
    if (!preliminary?.allow) return preliminary || { allow: false, reason: 'policy_denied' };
    const tool = this.byOperation.get(`${request.provider}:${request.operationId}`);
    if (!tool) return { allow: false, reason: 'tool_unregistered' };
    const role = request.identity?.context?.client?.role;
    if (role !== 'admin' && role !== tool.required_role) return { allow: false, reason: 'tool_role_denied' };
    if (!tool.environments.includes(request.environment)) return { allow: false, reason: 'tool_environment_denied' };
    if (isAgentIdentity(request.identity) && tool.agent_execution !== true) {
      return { allow: false, reason: 'critical_agent_denied' };
    }
    if (tool.risk_level === 'CRITICAL' && !request.identity?.context?.authFactors?.includes('webauthn')) {
      return { allow: false, reason: 'critical_step_up_required' };
    }
    const policy = options.operationPolicy;
    if (['HIGH', 'CRITICAL'].includes(tool.risk_level)) {
      if (policy?.approval_required !== true) return { allow: false, reason: 'tool_approval_policy_mismatch' };
      if (Number(policy.required_approvals || 1) < tool.approval_policy.approvals_required) {
        return { allow: false, reason: 'tool_approval_policy_mismatch' };
      }
    }
    return { ...preliminary, tool: publicTool(tool) };
  }
}

export function loadToolRegistry(path) {
  let document;
  try {
    document = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`tool registry could not be loaded: ${error.message}`);
  }
  return new ToolRegistry(document);
}
