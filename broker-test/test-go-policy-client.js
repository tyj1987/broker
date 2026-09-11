import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

const tool = {
  name: 'github.repository.read', version: '1.0.0', risk_level: 'LOW', agent_execution: true,
  target: { kind: 'github-repository', resource_parameter: 'resource_ref' },
};

const payload = corePolicyPayload(config, operation, { allow: true, ttlMs: 90_000, tool });
assert.equal(payload.request.approval_count, 2);
assert.equal(payload.request.step_up, true);
assert.equal(payload.request.tool, 'github.repository.read@1.0.0');
assert.equal(payload.request.target_kind, 'github-repository');
assert.equal(payload.request.risk_level, 'LOW');
assert.equal(payload.subject.principal_type, 'agent');
assert.deepEqual(payload.subject.providers, ['github']);
assert.deepEqual(payload.rule.source_cidrs, ['127.0.0.0/8']);
assert.equal(payload.rule.not_before, policy.not_before);
assert.equal(payload.rule.not_after, policy.not_after);
const preflightPayload = corePolicyPayload(config, operation, { allow: true, ttlMs: 90_000, tool }, Date.now(), { ignoreApproval: true });
assert.equal(preflightPayload.rule.required_approvals, 2);
assert.equal(preflightPayload.request.approval_phase, true);
assert.equal(preflightPayload.subject.requires_two_persons, true);

const sparsePolicy = {
  ...policy,
  ttl_seconds: 0,
  required_approvals: 0,
  approval_required: true,
  resources: undefined,
  source_cidrs: undefined,
  not_before: undefined,
  not_after: undefined,
};
const sparseOperation = {
  ...operation,
  typedParameters: { resource_ref: 42 },
  identity: {
    name: 'human',
    context: {
      via: 'session',
      clientName: 'human',
      client: {
        ...operation.identity.context.client,
        principal_type: 'human',
        allowed_services: [],
        allowed_accounts: [],
        allowed_resources: [],
        allowed_environments: [],
      },
      apiKey: {
        allowed_operations: ['other:repo.read'],
        allowed_services: [],
        allowed_accounts: [],
        allowed_resources: [],
        allowed_environments: [],
      },
      approvalGrants: [
        null,
        { provider: 'other', operation_id: 'repo.read', account_ref: 'primary', approved_by: 'alice', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'other', account_ref: 'primary', approved_by: 'alice', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'repo.read', account_ref: 'other', approved_by: 'alice', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'repo.read', account_ref: 'primary', approved_by: '', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'repo.read', account_ref: 'primary', approved_by: 'human', expires_at_ms: Date.now() + 60_000 },
        { provider: 'github', operation_id: 'repo.read', account_ref: 'primary', approved_by: 'expired', expires_at_ms: 0 },
      ],
    },
  },
};
const sparsePayload = corePolicyPayload(
  { operation_policies: { github: { 'repo.read': sparsePolicy } } },
  sparseOperation,
  { allow: true, tool: {} },
);
assert.equal(sparsePayload.subject.principal_type, 'human');
assert.deepEqual(sparsePayload.subject.tools, []);
assert.deepEqual(sparsePayload.subject.operations, ['other:repo.read']);
assert.deepEqual(sparsePayload.subject.providers, ['github']);
assert.equal(sparsePayload.request.resource, '');
assert.equal(sparsePayload.request.requested_ttl_ms, 300_000);
assert.equal(sparsePayload.request.step_up, false);
assert.equal(sparsePayload.request.approval_count, 0);
assert.equal(sparsePayload.request.source_ip, '');
assert.deepEqual(sparsePayload.rule.resources, []);
assert.equal(sparsePayload.rule.required_approvals, 1);

const socket = process.platform === 'win32'
  ? `\\\\.\\pipe\\secret-broker-${randomUUID()}`
  : join(tmpdir(), `secret-broker-${randomUUID()}.sock`);
let responseFactory = (requestBinding) => ({
  allow: true, ttl_ms: 45_000, code: 'allowed', request_binding: requestBinding,
});
let responseStatus = 200;
let rawResponse = null;
const server = createServer((request, response) => {
  if (request.url === '/v1/evaluate') {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    request.on('end', () => {
      const requestBinding = createHash('sha256')
        .update(Buffer.concat(chunks))
        .digest('base64url');
      response.writeHead(responseStatus, { 'content-type': 'application/json' });
      response.end(rawResponse ?? JSON.stringify(responseFactory(requestBinding)));
    });
  }
});
await new Promise((resolve) => server.listen(socket, resolve));
try {
  assert.deepEqual(await evaluateWithCore(socket, payload), { allow: true, reason: 'allowed', ttlMs: 45_000 });
  const authorize = createOperationAuthorizer(config, { socketPath: socket, requireCore: true });
  const decision = await authorize(operation, { allow: true, ttlMs: 90_000, marker: true, tool });
  assert.equal(decision.allow, true);
  assert.equal(decision.ttlMs, 45_000);
  assert.equal(decision.marker, true);
  const preflight = await authorize(operation, { allow: true, ttlMs: 90_000, tool }, { ignoreApproval: true });
  assert.equal(preflight.allow, true);

  responseFactory = (requestBinding) => ({
    allow: false, ttl_ms: 0, code: 'role_denied', request_binding: requestBinding,
  });
  assert.deepEqual(await evaluateWithCore(socket, payload), {
    allow: false, reason: 'role_denied', ttlMs: undefined,
  });
  for (const invalidResponse of [
    () => ({ allow: true, ttl_ms: 45_000, code: 'allowed', request_binding: 'a'.repeat(43) }),
    (binding) => ({ allow: true, ttl_ms: 0, code: 'allowed', request_binding: binding }),
    (binding) => ({ allow: true, ttl_ms: 90_001, code: 'allowed', request_binding: binding }),
    (binding) => ({ allow: true, ttl_ms: 45_000, code: 'role_denied', request_binding: binding }),
    (binding) => ({ allow: false, ttl_ms: 1, code: 'role_denied', request_binding: binding }),
    (binding) => ({ allow: false, ttl_ms: 0, code: 'allowed', request_binding: binding }),
    (binding) => ({ allow: true, ttl_ms: 45_000, code: 'Allowed', request_binding: binding }),
    (binding) => ({ allow: true, ttl_ms: 45_000, code: 'allowed', request_binding: binding, extra: true }),
  ]) {
    responseFactory = invalidResponse;
    assert.equal(
      (await evaluateWithCore(socket, payload)).reason,
      'core_invalid_response',
    );
  }
  responseFactory = (requestBinding) => ({
    allow: true, ttl_ms: 45_000, code: 'allowed', request_binding: requestBinding,
  });
  responseStatus = 503;
  assert.equal((await evaluateWithCore(socket, payload)).reason, 'core_rejected');
  responseStatus = 200;
  rawResponse = '{invalid';
  assert.equal((await evaluateWithCore(socket, payload)).reason, 'core_invalid_response');
  rawResponse = 'x'.repeat(65 * 1024);
  assert.equal((await evaluateWithCore(socket, payload)).reason, 'core_unavailable');
  rawResponse = null;

  assert.deepEqual(
    await authorize(operation, { allow: false, reason: 'preliminary_denied' }),
    { allow: false, reason: 'preliminary_denied' },
  );
  const functional = createOperationAuthorizer(() => config, {
    socketPath: socket, requireCore: true,
  });
  assert.equal((await functional(operation, { allow: true, tool })).allow, true);
  responseFactory = (requestBinding) => ({
    allow: false, ttl_ms: 0, code: 'role_denied', request_binding: requestBinding,
  });
  assert.equal((await functional(operation, { allow: true, tool })).reason, 'role_denied');
} finally {
  await new Promise((resolve) => server.close(resolve));
}

const missing = createOperationAuthorizer(config, { socketPath: '', requireCore: true });
assert.deepEqual(await missing(operation, { allow: true }), { allow: false, reason: 'core_required' });
const optional = createOperationAuthorizer(config, { socketPath: '', requireCore: false });
assert.deepEqual(await optional(operation, { allow: true, marker: true }), { allow: true, marker: true });
const missingConfig = createOperationAuthorizer(null, { socketPath: socket, requireCore: true });
assert.deepEqual(
  await missingConfig(operation, { allow: true }),
  { allow: false, reason: 'core_config_missing' },
);
assert.equal((await evaluateWithCore(socket, payload, 100)).allow, false);

console.log('Go policy client: local transport, fail-closed behavior, and TTL narrowing passed');
