// broker-test/test-shutdown.js — V4.9.x broker/lib/shutdown.js 单元测试
// 覆盖 installGracefulShutdown + rejectIfShuttingDown

import { installGracefulShutdown, rejectIfShuttingDown } from '../broker/lib/shutdown.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// installGracefulShutdown: shuttingDown state
// ============================================================
section('installGracefulShutdown state');
{
  let exitCode = null;
  const origExit = process.exit;
  process.exit = (code) => { exitCode = code; };
  try {
    const { shuttingDown, shutdown } = installGracefulShutdown({
      server: null,
      timeoutMs: 1000,
      logger: () => {},
    });
    ok('initial state: not shutting down', shuttingDown() === false);
    await shutdown('test1');
    ok('after shutdown(): shutting down', shuttingDown() === true);
    ok('process.exit called with 0', exitCode === 0);
  } finally {
    process.exit = origExit;
  }
}

// ============================================================
// installGracefulShutdown: idempotency
// ============================================================
section('shutdown idempotency');
{
  let exitCount = 0;
  const origExit = process.exit;
  process.exit = () => { exitCount++; };
  try {
    const { shuttingDown, shutdown } = installGracefulShutdown({
      server: null,
      timeoutMs: 1000,
      logger: () => {},
    });
    await shutdown('test1');
    ok('shuttingDown is true after first call', shuttingDown() === true);
    await shutdown('test2');
    ok('second call: still true (no re-trigger)', shuttingDown() === true);
    ok('process.exit called once', exitCount === 1);
  } finally {
    process.exit = origExit;
  }
}

// ============================================================
// installGracefulShutdown: onShutdown hooks
// ============================================================
section('onShutdown hooks');
{
  let exitCode = null;
  let hook1Called = false;
  let hook2Called = false;
  const origExit = process.exit;
  process.exit = (code) => { exitCode = code; };
  try {
    const { shutdown } = installGracefulShutdown({
      server: null,
      onShutdown: [
        async () => { hook1Called = true; },
        () => { hook2Called = true; },
      ],
      timeoutMs: 1000,
      logger: () => {},
    });
    await shutdown('test');
    ok('hook1 called', hook1Called === true);
    ok('hook2 called', hook2Called === true);
    ok('exit code 0', exitCode === 0);
  } finally {
    process.exit = origExit;
  }
}

// ============================================================
// installGracefulShutdown: hook error does not abort
// ============================================================
section('hook error tolerance');
{
  let exitCode = null;
  let goodCalled = false;
  const origExit = process.exit;
  process.exit = (code) => { exitCode = code; };
  try {
    const { shutdown } = installGracefulShutdown({
      server: null,
      onShutdown: [
        async () => { throw new Error('hook fail'); },
        async () => { goodCalled = true; },
      ],
      timeoutMs: 1000,
      logger: () => {},
    });
    await shutdown('test');
    ok('subsequent hook still runs', goodCalled === true);
    ok('exit code still 0 despite hook failure', exitCode === 0);
  } finally {
    process.exit = origExit;
  }
}

// ============================================================
// installGracefulShutdown: server.close called
// ============================================================
section('server.close');
{
  let exitCode = null;
  let closeCalled = false;
  const origExit = process.exit;
  process.exit = (code) => { exitCode = code; };
  try {
    const fakeServer = {
      close(cb) { closeCalled = true; if (cb) cb(); },
      closeIdleConnections() { /* no-op */ },
    };
    const { shutdown } = installGracefulShutdown({
      server: fakeServer,
      timeoutMs: 1000,
      logger: () => {},
    });
    await shutdown('test');
    ok('server.close called', closeCalled === true);
    ok('exit code 0', exitCode === 0);
  } finally {
    process.exit = origExit;
  }
}

// ============================================================
// rejectIfShuttingDown
// ============================================================
section('rejectIfShuttingDown');
{
  let shuttingDownReturn = false;
  const shuttingDownFn = () => shuttingDownReturn;
  const { jsonError } = await import('../broker/lib/http.js');

  // Not shutting down → returns false, no error sent
  let jsonErrorCalled = false;
  const origJsonError = jsonError;
  // monkey-patch: just track calls
  const mockJsonError = (res, code, msg) => { jsonErrorCalled = true; return origJsonError(res, code, msg); };

  const res = { headersSent: false, writeHead() {}, end() {} };
  shuttingDownReturn = false;
  ok('not shutting down: returns false', rejectIfShuttingDown(shuttingDownFn, res, mockJsonError) === false);
  ok('not shutting down: no error sent', jsonErrorCalled === false);

  // Shutting down → returns true, error sent
  shuttingDownReturn = true;
  const res2 = { headersSent: false, writeHead() {}, end() {} };
  ok('shutting down: returns true', rejectIfShuttingDown(shuttingDownFn, res2, mockJsonError) === true);
  ok('shutting down: error sent', jsonErrorCalled === true);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
