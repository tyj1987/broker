import assert from 'node:assert/strict';
import { ControlPlane, ControlPlaneError } from '../broker/lib/control-plane.js';

let now = Date.parse('2026-09-09T00:00:00Z');
const events = [];
const plane = new ControlPlane({ tokenKey: Buffer.alloc(32, 7), now: () => now, audit: event => events.push(event) });
plane.registerAdapter('infra.health', async ({ actor }) => ({ ok: true, actor: actor.id }));
plane.registerAdapter('production.deploy', async ({ inputs }) => ({ deployed: inputs.commit_sha }));

async function rejectsCode(fn, code) {
  await assert.rejects(async () => fn(), error => error instanceof ControlPlaneError && error.code === code);
}

const low = await plane.invoke({ tool: 'infra.health', actor: { type: 'agent', id: 'work-1', role: 'work-agent' } });
assert.equal(low.status, 'succeeded');
assert.equal(low.result.ok, true);

const actor = { type: 'agent', id: 'codex-1', role: 'codex-agent' };
const target = { service: '52trz-api', environment: 'production' };
const inputs = { commit_sha: 'abc123' };
await rejectsCode(() => plane.invoke({ tool: 'production.deploy', actor, target, inputs }), 'approval_token_required');

const approval = plane.requestApproval({ tool: 'production.deploy', actor, target, inputs, reason: 'tested release' });
await rejectsCode(() => plane.decideApproval({ approvalId: approval.id, approver: actor, decision: 'approve' }), 'admin_required');
plane.decideApproval({ approvalId: approval.id, approver: { type: 'human', id: 'admin-1', role: 'human-admin' }, decision: 'approve' });
const token = plane.issueExecutionToken({ approvalId: approval.id, actor, target, inputs });
await rejectsCode(() => plane.invoke({ tool: 'production.deploy', actor, target: { ...target, service: 'other' }, inputs, token }), 'approval_target_mismatch');
const deployed = await plane.invoke({ tool: 'production.deploy', actor, target, inputs, token });
assert.equal(deployed.result.deployed, 'abc123');
await rejectsCode(() => plane.invoke({ tool: 'production.deploy', actor, target, inputs, token }), 'execution_token_replayed');

const expiring = plane.requestApproval({ tool: 'production.deploy', actor, target, inputs, ttlSeconds: 30 });
now += 31_000;
await rejectsCode(() => plane.decideApproval({ approvalId: expiring.id, approver: { type: 'human', id: 'admin-1', role: 'human-admin' }, decision: 'approve' }), 'approval_expired');

await rejectsCode(() => plane.invoke({ tool: 'db.drop', actor: { type: 'agent', id: 'evil', role: 'human-admin' } }), 'critical_tool_forbidden_for_agent');
assert.ok(events.some(event => event.action === 'tool_approval_requested'));
assert.ok(events.some(event => event.action === 'tool_execution_finished' && event.result === 'succeeded'));
assert.ok(events.every(event => event.actor && event.tool && event.target && event.decision && event.result && event.timestamp || !event.action.startsWith('tool_execution')));

plane.setEmergencyRevoke(true, { type: 'human', id: 'admin-1', role: 'human-admin' });
await rejectsCode(() => plane.invoke({ tool: 'infra.health', actor }), 'control_plane_revoked');

console.log('# control-plane lifecycle tests passed');
