const RISK_LEVELS = Object.freeze({
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

const DEFAULT_TOOLS = Object.freeze([
  {
    name: 'infra.health',
    risk: RISK_LEVELS.LOW,
    allowedRoles: ['work-agent', 'codex-agent', 'ops-agent', 'human-admin'],
    approvalRequired: false,
    description: 'Read infrastructure health status.',
  },
  {
    name: 'logs.read',
    risk: RISK_LEVELS.LOW,
    allowedRoles: ['work-agent', 'codex-agent', 'ops-agent', 'human-admin'],
    approvalRequired: false,
    description: 'Read redacted service logs.',
  },
  {
    name: 'github.create_issue',
    risk: RISK_LEVELS.MEDIUM,
    allowedRoles: ['work-agent', 'codex-agent', 'human-admin'],
    approvalRequired: false,
    description: 'Create an issue in an authorized repository.',
  },
  {
    name: 'staging.deploy',
    risk: RISK_LEVELS.MEDIUM,
    allowedRoles: ['codex-agent', 'ops-agent', 'human-admin'],
    approvalRequired: false,
    description: 'Deploy an approved artifact to staging.',
  },
  {
    name: 'production.deploy',
    risk: RISK_LEVELS.HIGH,
    allowedRoles: ['codex-agent', 'ops-agent', 'human-admin'],
    approvalRequired: true,
    description: 'Deploy an approved artifact to production.',
  },
  {
    name: 'cloudflare.dns.write',
    risk: RISK_LEVELS.HIGH,
    allowedRoles: ['ops-agent', 'human-admin'],
    approvalRequired: true,
    description: 'Modify an authorized DNS record.',
  },
  {
    name: 'broker.policy.write',
    risk: RISK_LEVELS.HIGH,
    allowedRoles: ['human-admin'],
    approvalRequired: true,
    description: 'Modify broker authorization policy.',
  },
  {
    name: 'db.drop',
    risk: RISK_LEVELS.CRITICAL,
    allowedRoles: ['human-admin'],
    approvalRequired: true,
    agentForbidden: true,
    description: 'Destructive database drop operation.',
  },
  {
    name: 'production.root_shell',
    risk: RISK_LEVELS.CRITICAL,
    allowedRoles: ['human-admin'],
    approvalRequired: true,
    agentForbidden: true,
    description: 'Obtain a production root shell.',
  },
  {
    name: 'broker.master_key.export',
    risk: RISK_LEVELS.CRITICAL,
    allowedRoles: ['human-admin'],
    approvalRequired: true,
    agentForbidden: true,
    description: 'Export broker root cryptographic material.',
  },
]);

function freezeTool(tool) {
  return Object.freeze({
    ...tool,
    allowedRoles: Object.freeze([...(tool.allowedRoles || [])]),
  });
}

export class ToolRegistry {
  #tools = new Map();

  constructor(tools = DEFAULT_TOOLS) {
    for (const tool of tools) this.register(tool);
  }

  register(tool) {
    validateTool(tool);
    if (this.#tools.has(tool.name)) {
      throw new Error(`tool already registered: ${tool.name}`);
    }
    const frozen = freezeTool(tool);
    this.#tools.set(tool.name, frozen);
    return frozen;
  }

  get(name) {
    return this.#tools.get(name) || null;
  }

  list() {
    return [...this.#tools.values()];
  }
}

export function evaluateToolPolicy({ tool, actor }) {
  if (!tool) {
    return decision('denied', 'tool_not_found');
  }

  if (!actor || !actor.id || !actor.role || !actor.type) {
    return decision('denied', 'invalid_actor');
  }

  const isAgent = actor.type === 'agent';
  if (tool.risk === RISK_LEVELS.CRITICAL && isAgent) {
    return decision('denied', 'critical_tool_forbidden_for_agent', tool);
  }

  if (tool.agentForbidden && isAgent) {
    return decision('denied', 'tool_forbidden_for_agent', tool);
  }

  if (!tool.allowedRoles.includes(actor.role)) {
    return decision('denied', 'role_not_allowed', tool);
  }

  if (tool.approvalRequired) {
    return decision('approval_required', 'approval_required', tool);
  }

  return decision('allowed', 'policy_allowed', tool);
}

function decision(status, reason, tool = null) {
  return Object.freeze({
    status,
    reason,
    risk: tool?.risk || null,
    tool: tool?.name || null,
  });
}

function validateTool(tool) {
  if (!tool || typeof tool !== 'object') throw new TypeError('tool must be an object');
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/.test(tool.name || '')) {
    throw new TypeError('invalid tool name');
  }
  if (!Object.values(RISK_LEVELS).includes(tool.risk)) {
    throw new TypeError(`invalid risk level for ${tool.name}`);
  }
  if (!Array.isArray(tool.allowedRoles) || tool.allowedRoles.length === 0) {
    throw new TypeError(`allowedRoles required for ${tool.name}`);
  }
  if (typeof tool.approvalRequired !== 'boolean') {
    throw new TypeError(`approvalRequired must be boolean for ${tool.name}`);
  }
}

export { DEFAULT_TOOLS, RISK_LEVELS };
