import * as assert from 'node:assert/strict';
import { test } from 'node:test';
import { BrokerClient, BrokerConnectionError, BrokerError, redact } from '../client';
import { startMockBroker } from './mock_broker';

test('redaction covers supported credential forms', () => {
  for (const secret of [
    'ghp_xxxxABCDEFGHIJabcdefghij',
    'sk-abcdefghijklmnopqrstuvwxyz',
    'AKIAIOSFODNN7EXAMPLE',
    'eyJAbcdefghijklmnop.eyJqrstuvwxyzABCDEFG.eyJqrstuvwxyzABCDEFG',
  ]) assert.ok(!redact(`credential=${secret}`).includes(secret));
  assert.equal(redact('ordinary text'), 'ordinary text');
});

test('client rejects insecure endpoint configuration', () => {
  assert.throws(
    () => new BrokerClient({ endpoint: 'http://insecure', clientCert: '', clientKey: '', caCert: '' }),
    /must be https/,
  );
  assert.throws(
    () => new BrokerClient({ endpoint: '', clientCert: '', clientKey: '', caCert: '' }),
    /endpoint required/,
  );
});

test('error types retain safe diagnostic context', () => {
  const brokerError = new BrokerError('test', 403, '{"error":"forbidden"}');
  assert.equal(brokerError.status, 403);
  assert.match(brokerError.message, /403/);
  const connectionError = new BrokerConnectionError('health', new Error('ECONNREFUSED'));
  assert.match(connectionError.message, /health/);
});

test('mock broker supports health and typed V2 operations', async () => {
  const mock = await startMockBroker();
  try {
    const client = new BrokerClient({
      endpoint: `https://127.0.0.1:${mock.port}`,
      clientCert: '', clientKey: '', caCert: mock.certPath,
      insecureSkipVerify: true,
    });
    assert.equal((await client.health()).ok, true);
    const operation = await client.createOperation({
      provider: 'github', operation_id: 'repo.read', account_ref: 'personal',
      environment: 'development', typed_parameters: { owner: 'o', repo: 'r' },
    });
    assert.equal(operation.status, 'waiting');
    assert.equal((await client.getOperation(operation.id)).status, 'completed');
    const task = await client.createTask({
      tool: 'broker.tools.inspect', tool_version: '1.0.0', account_ref: 'control-plane',
      environment: 'production', parameters: { resource_ref: 'tool-registry' },
      idempotency_key: 'vscode-sdk-task-0001',
    });
    assert.equal(task.state, 'READY');
    assert.equal((await client.getTask(task.id)).state, 'SUCCEEDED');
    assert.equal((await client.taskEvents(task.id))[0].sequence, 1);
    assert.equal((await client.runTask(task.id)).state, 'SUCCEEDED');
    assert.equal((await client.cancelTask(task.id)).state, 'CANCELLED');
    await assert.rejects(client.getTask(''), /task id/);
    const approval = await client.createApproval({
      provider: 'github', operation_id: 'repo.read', account_ref: 'personal',
      environment: 'production', typed_parameters: { resource_ref: 'repository' },
    });
    assert.equal(approval.status, 'REQUESTED');
    assert.equal((await client.listApprovals())[0].id, approval.id);
    assert.equal((await client.cancelApproval(approval.id)).status, 'CANCELLED');
    await assert.rejects(client.decideApproval(approval.id, 'approve'), /WebAuthn browser workbench/);
  } finally {
    await mock.stop();
  }
});

test('HTTP denial surfaces as BrokerError', async () => {
  const mock = await startMockBroker();
  try {
    const client = new BrokerClient({
      endpoint: `https://127.0.0.1:${mock.port}`,
      clientCert: '', clientKey: '', caCert: mock.certPath,
      insecureSkipVerify: true,
    });
    await assert.rejects(client.proxy('github', 'GET', '/forbidden'), (error: unknown) => (
      error instanceof BrokerError && error.status === 403
    ));
  } finally {
    await mock.stop();
  }
});

test('connection error is typed', async () => {
  const client = new BrokerClient({ endpoint: 'https://127.0.0.1:1', clientCert: '', clientKey: '', caCert: '' });
  await assert.rejects(client.health(), BrokerConnectionError);
});
