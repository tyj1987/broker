import assert from 'node:assert/strict';
import {
  ToolRegistry,
  evaluateToolPolicy,
  RISK_LEVELS,
} from '../broker/lib/tool-registry.js';

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    throw error;
  }
}

const registry = new ToolRegistry();

test('registry exposes default tools', () => {
  assert.ok(registry.list().length >= 8);
  assert.equal(registry.get('infra.health').risk, RISK_LEVELS.LOW);
});

test('LOW tool is allowed for authorized agent', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('infra.health'),
    actor: { type: 'agent', id: 'work-1', role: 'work-agent' },
  });
  assert.equal(result.status, 'allowed');
});

test('unauthorized role is denied', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('staging.deploy'),
    actor: { type: 'agent', id: 'work-1', role: 'work-agent' },
  });
  assert.equal(result.status, 'denied');
  assert.equal(result.reason, 'role_not_allowed');
});

test('HIGH tool requires approval', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('production.deploy'),
    actor: { type: 'agent', id: 'codex-1', role: 'codex-agent' },
  });
  assert.equal(result.status, 'approval_required');
});

test('CRITICAL tool is permanently denied to agents', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('db.drop'),
    actor: { type: 'agent', id: 'ops-1', role: 'human-admin' },
  });
  assert.equal(result.status, 'denied');
  assert.equal(result.reason, 'critical_tool_forbidden_for_agent');
});

test('CRITICAL tool reaches approval gate for human admin', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('db.drop'),
    actor: { type: 'human', id: 'admin-1', role: 'human-admin' },
  });
  assert.equal(result.status, 'approval_required');
});

test('unknown tool is denied', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('does.not.exist'),
    actor: { type: 'agent', id: 'work-1', role: 'work-agent' },
  });
  assert.equal(result.status, 'denied');
  assert.equal(result.reason, 'tool_not_found');
});

test('invalid actor is denied', () => {
  const result = evaluateToolPolicy({
    tool: registry.get('infra.health'),
    actor: { type: 'agent' },
  });
  assert.equal(result.status, 'denied');
  assert.equal(result.reason, 'invalid_actor');
});

test('duplicate registration fails closed', () => {
  assert.throws(() => registry.register({
    name: 'infra.health',
    risk: RISK_LEVELS.LOW,
    allowedRoles: ['human-admin'],
    approvalRequired: false,
  }), /already registered/);
});

console.log(`# ${passed} tool-registry tests passed`);
