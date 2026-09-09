import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { corePolicyPayload, createOperationAuthorizer, evaluateWithCore } from '../broker/lib/go-policy-client.js';

const policy = {
  enabled: true,
  roles: ['automation'],
  security_profiles: ['strict'],
  identity_methods: ['mtls'],
  environments: ['production'],
  accounts: ['primary'],
  resources: ['tyj1987/broker'],
  ttl_seconds: 120,
  required_approvals: 2,
  contract_verified: true,
  parameter_schema: { type: 'object', properties: {} },
  source_cidrs: ['127.0.0.0/8'],
  not_before: '2026-09-09T00:00:00Z',
  not_after: '2026-09-10T00:00:00Z',
};
const config = { operation_policies: { github: { 'repo.read': policy } } };
const operation = {
  identity: {
    name: 'agent',
    context: {
      clientName: 'agent', sourceIp: '127.0.0.1', via: 'mtls', authFactors: ['webauthn'],
      client: {
        role: 'automation', security_profile: 'strict', allowed_services: ['github'],
        allowed_accounts: ['primary'], allowed_resources: ['tyj1987/broker'],
        allowed_environments: ['production'],
      },
      approvalGrants: [
        { provider: 'github', operation_id: 'repo.read', account_ref: 'primary', approved_by: 'alice', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'repo.read', account_ref: 'primary', approved_by: 'bob', expires_at_ms: Date.now() + 60_000 },
      ],
    },
  },
  provider: 'github', operationId: 'repo.read', accountRef: 'primary', environment: 'production',
  typedParameters: { resource_ref: 'tyj1987/broker' },
};

const payload = corePolicyPayload(config, operation, { allow: true, ttlMs: 90_000 });
assert.equal(payload.request.approval_count, 2);
assert.equal(payload.request.step_up, true);
assert.deepEqual(payload.subject.providers, ['github']);
assert.deepEqual(payload.rule.source_cidrs, ['127.0.0.0/8']);
assert.equal(payload.rule.not_before, policy.not_before);
assert.equal(payload.rule.not_after, policy.not_after);
const preflightPayload = corePolicyPayload(config, operation, { allow: true, ttlMs: 90_000 }, Date.now(), { ignoreApproval: true });
assert.equal(preflightPayload.rule.required_approvals, 0);
assert.equal(preflightPayload.subject.requires_two_persons, true);

const socket = process.platform === 'win32'
  ? `\\\\.\\pipe\\secret-broker-${randomUUID()}`
  : join(tmpdir(), `secret-broker-${randomUUID()}.sock`);
const server = createServer((request, response) => {
  if (request.url === '/v1/evaluate') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"allow":true,"ttl_ms":45000,"code":"allowed"}');
  }
});
await new Promise((resolve) => server.listen(socket, resolve));
try {
  assert.deepEqual(await evaluateWithCore(socket, payload), { allow: true, reason: 'allowed', ttlMs: 45_000 });
  const authorize = createOperationAuthorizer(config, { socketPath: socket, requireCore: true });
  const decision = await authorize(operation, { allow: true, ttlMs: 90_000, marker: true });
  assert.equal(decision.allow, true);
  assert.equal(decision.ttlMs, 45_000);
  assert.equal(decision.marker, true);
  const preflight = await authorize(operation, { allow: true, ttlMs: 90_000 }, { ignoreApproval: true });
  assert.equal(preflight.allow, true);
} finally {
  await new Promise((resolve) => server.close(resolve));
}

const missing = createOperationAuthorizer(config, { socketPath: '', requireCore: true });
assert.deepEqual(await missing(operation, { allow: true }), { allow: false, reason: 'core_required' });
assert.equal((await evaluateWithCore(socket, payload, 100)).allow, false);

console.log('Go policy client: local transport, fail-closed behavior, and TTL narrowing passed');
