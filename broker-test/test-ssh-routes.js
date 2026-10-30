// broker-test/test-ssh-routes.js — SSH HTTP route error-boundary tests

import { handleSshProxy } from '../broker/routes/ssh-proxy.js';
import { SshConfigurationError, SshInputError } from '../broker/ssh-proxy.js';

let passed = 0;
let failed = 0;

function ok(name, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL  ${name}`);
  }
}

function response() {
  return { statusCode: 0, body: null };
}

function send(res, status, body) {
  res.statusCode = status;
  res.body = body;
}

function jsonError(res, status, message) {
  send(res, status, { error: message, status });
}

function dependencies(overrides = {}) {
  return {
    send,
    jsonError,
    readBody: async () => overrides.body || {},
    audit: overrides.audit || (() => {}),
    ctx: overrides.ctx || {
      cn: 'client.alice',
      requestId: 'req-1',
      client: { role: 'developer' },
    },
    rateLimit: overrides.rateLimit || (() => true),
    getSecret:
      overrides.getSecret ||
      (async () => ({
        private_key: 'synthetic-private-key',
        host: 'host.example',
        username: 'app',
        port: 22,
        known_hosts: 'host.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFRlc3RIb3N0S2V5',
      })),
    sshExecFn: overrides.sshExecFn,
    sshTunnelFn: overrides.sshTunnelFn,
    stopTunnelFn: overrides.stopTunnelFn,
    listTunnelsFn: overrides.listTunnelsFn,
  };
}

console.log('[exec route error boundary]');
{
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/exec' },
    dependencies({ body: { target: 'bad-target', command: 'id' } }),
  );
  ok('invalid target returns 400', res.statusCode === 400);
  ok('safe input error remains actionable', /user@host/.test(res.body?.error || ''));
}
{
  const events = [];
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/exec' },
    dependencies({
      body: { target: 'app@host.example', command: 'id' },
      audit: (event) => events.push(event),
      sshExecFn: async () => {
        throw new SshConfigurationError('known_hosts missing at C:\\sensitive\\path');
      },
    }),
  );
  ok('secret configuration error returns 422', res.statusCode === 422);
  ok(
    'secret configuration detail is hidden',
    res.body?.error === 'SSH secret configuration is invalid',
  );
  ok(
    'secret configuration detail remains in audit',
    events.some((event) => /sensitive/.test(event.error)),
  );
}
{
  const events = [];
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/exec' },
    dependencies({
      body: { target: 'app@host.example', command: 'id' },
      audit: (event) => events.push(event),
      sshExecFn: async () => {
        throw new Error('spawn ENOENT at C:\\internal\\ssh.exe');
      },
    }),
  );
  ok('internal execution failure returns 502', res.statusCode === 502);
  ok('internal execution detail is hidden', res.body?.error === 'SSH operation failed');
  ok(
    'internal execution detail remains in audit',
    events.some((event) => /internal/.test(event.error)),
  );
}

console.log('\n[tunnel route error boundary]');
{
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/tunnel' },
    dependencies({
      body: {
        target: 'app@host.example',
        local_port: 70000,
        remote_host: 'db.internal',
        remote_port: 5432,
      },
      sshTunnelFn: async () => {
        throw new SshInputError('localPort must be 1-65535');
      },
    }),
  );
  ok('tunnel input error returns 400', res.statusCode === 400);
  ok('tunnel input error remains actionable', res.body?.error === 'localPort must be 1-65535');
}
{
  const events = [];
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/tunnel' },
    dependencies({
      body: {
        target: 'app@host.example',
        local_port: 15432,
        remote_host: 'db.internal',
        remote_port: 5432,
      },
      audit: (event) => events.push(event),
      sshTunnelFn: async () => {
        throw new Error('connection failed using C:\\internal\\key');
      },
    }),
  );
  ok('tunnel internal failure returns 502', res.statusCode === 502);
  ok('tunnel internal detail is hidden', res.body?.error === 'SSH operation failed');
  ok(
    'tunnel internal detail remains in audit',
    events.some((event) => /internal/.test(event.error)),
  );
}

console.log('\n[list and stop routes use injected operations]');
{
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'GET', pathname: '/api/v1/ssh/tunnels' },
    dependencies({ listTunnelsFn: () => [{ id: 'tunnel-1' }] }),
  );
  ok('tunnel list uses common send response', res.statusCode === 200);
  ok('tunnel list returns injected metadata', res.body?.items?.[0]?.id === 'tunnel-1');
}
{
  const res = response();
  await handleSshProxy(
    {},
    res,
    { method: 'POST', pathname: '/api/v1/ssh/tunnel/stop' },
    dependencies({ body: { id: 'tunnel-1' }, stopTunnelFn: async () => true }),
  );
  ok('tunnel stop uses injected operation', res.statusCode === 200 && res.body?.id === 'tunnel-1');
}

console.log('\n[route fall-through]');
{
  const res = response();
  const handled = await handleSshProxy(
    {},
    res,
    { method: 'GET', pathname: '/api/v1/not-ssh' },
    dependencies(),
  );
  ok('unrelated route falls through', handled === false && res.statusCode === 0);
}

console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
