import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserOperationExecutor, BrowserWorkerError } from '../src/executor.js';

function fakeBrowser(result = { status: 'ok', records: 1 }) {
  const state = { options: null, routes: [], closed: 0, navigated: null };
  const page = { async goto(url) { state.navigated = url; } };
  const context = {
    async route(_pattern, handler) { state.routes.push(handler); },
    async newPage() { return page; },
    async close() { state.closed += 1; },
  };
  return {
    state,
    browser: { async newContext(options) { state.options = options; return context; } },
    adapter: {
      provider: 'aliyun', operationId: 'account.summary', startUrl: 'https://signin.aliyun.com/login.htm',
      allowedOrigins: ['https://home.console.aliyun.com'],
      async execute({ page: current, startUrl }) { await current.goto(startUrl); return result; },
    },
  };
}

const request = {
  provider: 'aliyun', operation_id: 'account.summary', account_ref: 'primary', environment: 'staging',
  typed_parameters: { resource_ref: 'summary' },
};

test('runs a reviewed adapter in a disposable restricted context', async () => {
  const fixture = fakeBrowser();
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  assert.deepEqual(await executor.execute(request), { status: 'ok', records: 1 });
  assert.deepEqual(fixture.state.options, { acceptDownloads: false, serviceWorkers: 'block', permissions: [] });
  assert.equal(fixture.state.navigated, fixture.adapter.startUrl);
  assert.equal(fixture.state.closed, 1);
});

test('blocks caller-controlled browser primitives', async () => {
  const fixture = fakeBrowser();
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  for (const forbidden of ['url', 'selector', 'javascript', 'headers', 'cookie', 'storageState']) {
    await assert.rejects(() => executor.execute({ ...request, typed_parameters: { [forbidden]: 'x' } }),
      (error) => error instanceof BrowserWorkerError && error.code === 'forbidden_parameter');
  }
  await assert.rejects(() => executor.execute({ ...request, url: 'https://evil.test' }),
    (error) => error instanceof BrowserWorkerError && error.code === 'forbidden_parameter');
});

test('rejects malformed environment, parameters, and oversized input', async () => {
  const fixture = fakeBrowser();
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  await assert.rejects(() => executor.execute({ ...request, environment: 'unknown' }), /environment is invalid/);
  await assert.rejects(() => executor.execute({ ...request, typed_parameters: [] }), /must be an object/);
  await assert.rejects(() => executor.execute({ ...request, typed_parameters: { value: 'x'.repeat(70_000) } }), /too large/);
});

test('fails closed for unregistered operations and sensitive output', async () => {
  const fixture = fakeBrowser({ status: 'ok', session_token: 'not-returned' });
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  await assert.rejects(() => executor.execute({ ...request, operation_id: 'unknown' }), /reviewed browser adapter/);
  await assert.rejects(() => executor.execute(request), (error) => error.code === 'unsafe_result');
  assert.equal(fixture.state.closed, 1);
});

test('rejects sensitive fields nested in adapter output', async () => {
  const fixture = fakeBrowser({ status: 'ok', data: { cookie: 'not-returned' } });
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  await assert.rejects(() => executor.execute(request), (error) => error.code === 'unsafe_result');
  assert.equal(fixture.state.closed, 1);
});

test('network policy allows only exact adapter origins', async () => {
  const fixture = fakeBrowser();
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  await executor.execute(request);
  const decisions = [];
  const route = (url) => ({
    request: () => ({ url: () => url }),
    continue: () => decisions.push(`allow:${url}`),
    abort: () => decisions.push(`deny:${url}`),
  });
  await fixture.state.routes[0](route('https://home.console.aliyun.com/api'));
  await fixture.state.routes[0](route('https://home.console.aliyun.com.evil.test/steal'));
  await fixture.state.routes[0](route('http://signin.aliyun.com/'));
  assert.deepEqual(decisions, [
    'allow:https://home.console.aliyun.com/api',
    'deny:https://home.console.aliyun.com.evil.test/steal',
    'deny:http://signin.aliyun.com/',
  ]);
});

test('always closes the context when an adapter fails', async () => {
  const fixture = fakeBrowser();
  fixture.adapter.execute = async () => { throw new Error('page_changed'); };
  const executor = new BrowserOperationExecutor({ browser: fixture.browser, adapters: [fixture.adapter] });
  await assert.rejects(() => executor.execute(request), /page_changed/);
  assert.equal(fixture.state.closed, 1);
});
