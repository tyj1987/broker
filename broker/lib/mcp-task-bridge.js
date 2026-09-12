import { redact, redactDeep } from './redact.js';

const CONTROL_FIELDS = new Set(['account_ref', 'environment', 'idempotency_key']);
const RISK_LEVELS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const ENVIRONMENTS = new Set(['development', 'staging', 'production']);
const TASK_ID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SAFE_NAME_RE = /^[a-z][a-z0-9._-]{1,127}$/;
const SAFE_VERSION_RE = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;

function fail(message) {
  throw new Error(message);
}

function safeMcpResult(value) {
  return redactDeep(value);
}

function taskId(args) {
  if (
    !args ||
    typeof args !== 'object' ||
    Array.isArray(args) ||
    !TASK_ID_RE.test(args.task_id || '')
  ) {
    fail('A valid task_id is required');
  }
  if (Object.keys(args).some((key) => key !== 'task_id')) fail('Unknown task control field');
  return args.task_id;
}

function mcpName(tool) {
  const encoded = `${tool.name}__v${tool.version}`.replace(/[^A-Za-z0-9_-]/g, '_');
  return `broker_execute__${encoded}`;
}

function validateTool(tool) {
  if (
    !tool ||
    typeof tool !== 'object' ||
    !SAFE_NAME_RE.test(tool.name || '') ||
    !SAFE_VERSION_RE.test(tool.version || '') ||
    typeof tool.description !== 'string' ||
    !RISK_LEVELS.has(tool.risk_level) ||
    !Array.isArray(tool.environments) ||
    tool.environments.length === 0 ||
    new Set(tool.environments).size !== tool.environments.length ||
    tool.environments.some((environment) => !ENVIRONMENTS.has(environment)) ||
    !tool.input_schema ||
    tool.input_schema.type !== 'object' ||
    tool.input_schema.additionalProperties !== false ||
    !tool.input_schema.properties ||
    typeof tool.input_schema.properties !== 'object'
  ) {
    fail('Broker returned an invalid executable tool');
  }
  if (Object.keys(tool.input_schema.properties).some((key) => CONTROL_FIELDS.has(key))) {
    fail('Broker tool conflicts with MCP control fields');
  }
  return tool;
}

function presentTool(tool) {
  const required = [
    ...new Set([
      'account_ref',
      'environment',
      'idempotency_key',
      ...(tool.input_schema.required || []),
    ]),
  ];
  return {
    name: mcpName(tool),
    description: `${redact(tool.description).slice(0, 240)} Risk: ${tool.risk_level}.`,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required,
      properties: {
        account_ref: { type: 'string', minLength: 1, maxLength: 128 },
        environment: { type: 'string', enum: tool.environments },
        idempotency_key: { type: 'string', minLength: 16, maxLength: 128 },
        ...redactDeep(structuredClone(tool.input_schema.properties)),
      },
    },
  };
}

export const MCP_CONTROL_TOOLS = Object.freeze([
  {
    name: 'broker_task_get',
    description: 'Read the current state and approved result of one owned Broker task.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', format: 'uuid' } },
    },
  },
  {
    name: 'broker_task_run',
    description: 'Run one ready or fully approved Broker task through a fresh policy check.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', format: 'uuid' } },
    },
  },
  {
    name: 'broker_task_cancel',
    description: 'Cancel one owned Broker task before execution.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', format: 'uuid' } },
    },
  },
  {
    name: 'broker_task_events',
    description: 'Read the bounded, credential-free transition events for one owned Broker task.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['task_id'],
      properties: { task_id: { type: 'string', format: 'uuid' } },
    },
  },
]);

export function createMcpTaskBridge({ callBroker } = {}) {
  if (typeof callBroker !== 'function')
    throw new TypeError('MCP task bridge requires a Broker client');

  async function executableTools() {
    const response = await callBroker('/api/v2/tools', { method: 'GET' });
    if (!response || response.registry_version !== 1 || !Array.isArray(response.tools)) {
      fail('Broker returned an invalid tool registry');
    }
    const tools = response.tools.map(validateTool);
    const names = new Set();
    for (const tool of tools) {
      const name = mcpName(tool);
      if (names.has(name)) fail('Broker returned conflicting executable tools');
      names.add(name);
    }
    return tools;
  }

  async function listTools() {
    return [
      ...MCP_CONTROL_TOOLS.map((tool) => structuredClone(tool)),
      ...(await executableTools()).map(presentTool),
    ];
  }

  async function executeTool(tool, args) {
    if (!args || typeof args !== 'object' || Array.isArray(args))
      fail('Tool arguments must be an object');
    const { account_ref, environment, idempotency_key, ...parameters } = args;
    const task = await callBroker('/api/v2/tasks', {
      method: 'POST',
      body: {
        tool: tool.name,
        tool_version: tool.version,
        account_ref,
        environment,
        idempotency_key,
        parameters,
      },
    });
    if (task?.state !== 'READY') return task;
    return callBroker(`/api/v2/tasks/${task.id}/run`, { method: 'POST', body: {} });
  }

  async function callToolRaw(name, args) {
    if (name === 'broker_task_get')
      return callBroker(`/api/v2/tasks/${taskId(args)}`, { method: 'GET' });
    if (name === 'broker_task_run')
      return callBroker(`/api/v2/tasks/${taskId(args)}/run`, { method: 'POST', body: {} });
    if (name === 'broker_task_cancel')
      return callBroker(`/api/v2/tasks/${taskId(args)}/cancel`, { method: 'POST', body: {} });
    if (name === 'broker_task_events')
      return callBroker(`/api/v2/tasks/${taskId(args)}/events`, { method: 'GET' });
    const tool = (await executableTools()).find((candidate) => mcpName(candidate) === name);
    if (!tool) fail('Unknown or unavailable Broker tool');
    return executeTool(tool, args);
  }

  async function callTool(name, args) {
    return safeMcpResult(await callToolRaw(name, args));
  }

  return { listTools, callTool };
}
