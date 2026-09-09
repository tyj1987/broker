import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import {
  createPinnedHttpsRequest,
  PINNED_HTTPS_LIMITS,
  PinnedRequestError,
} from '../broker/lib/pinned-https-request.js';

const PUBLIC_V4 = { address: '93.184.216.34', family: 4 };
const expectCode = (code) => (error) => error instanceof PinnedRequestError && error.code === code;

function createRequestMock({
  status = 200,
  headers = {},
  chunks = ['ok'],
  responseError,
  requestError,
} = {}) {
  const state = {};
  const requestImpl = (options, callback) => {
    state.options = options;
    const request = new EventEmitter();
    request.setTimeout = (value, handler) => {
      state.timeout = value;
      state.timeoutHandler = handler;
    };
    request.destroy = () => {
      state.requestDestroyed = true;
    };
    request.end = (body) => {
      state.body = body;
      if (requestError) {
        queueMicrotask(() => request.emit('error', new Error(requestError)));
        return;
      }
      const response = Readable.from(chunks);
      response.statusCode = status;
      response.headers = headers;
      const originalDestroy = response.destroy.bind(response);
      response.destroy = (...args) => {
        state.responseDestroyed = true;
        return originalDestroy(...args);
      };
      queueMicrotask(() => {
        callback(response);
        if (responseError) queueMicrotask(() => response.emit('error', new Error(responseError)));
      });
    };
    state.request = request;
    return request;
  };
  return { state, requestImpl };
}

const mock = createRequestMock({
  status: 201,
  headers: { 'x-test': 'yes' },
  chunks: ['hel', 'lo'],
});
let resolveInput;
const request = createPinnedHttpsRequest({
  resolveHost: async (...args) => {
    resolveInput = args;
    return [PUBLIC_V4];
  },
  requestImpl: mock.requestImpl,
  timeoutMs: 2500,
});
const signal = new AbortController().signal;
const response = await request({
  origin: 'https://api.github.com',
  method: 'POST',
  path: '/app/installations/1/access_tokens',
  headers: {
    Accept: 'application/json',
    Authorization: 'Bearer unit-jwt',
    'Content-Type': 'application/json',
  },
  body: '{"ok":true}',
  max_response_bytes: 100,
  redirect: 'manual',
  signal,
});
assert.equal(response.status, 201);
assert.equal(response.body.toString(), 'hello');
assert.equal(response.headers['x-test'], 'yes');
assert.equal(resolveInput[0], 'api.github.com');
assert.equal(resolveInput[1].signal, signal);
assert.deepEqual(
  {
    protocol: mock.state.options.protocol,
    hostname: mock.state.options.hostname,
    port: mock.state.options.port,
    method: mock.state.options.method,
    path: mock.state.options.path,
    servername: mock.state.options.servername,
    rejectUnauthorized: mock.state.options.rejectUnauthorized,
    timeout: mock.state.timeout,
  },
  {
    protocol: 'https:',
    hostname: 'api.github.com',
    port: 443,
    method: 'POST',
    path: '/app/installations/1/access_tokens',
    servername: 'api.github.com',
    rejectUnauthorized: true,
    timeout: 2500,
  },
);
assert.equal(mock.state.options.headers.authorization, 'Bearer unit-jwt');
assert.equal(
  mock.state.options.headers['content-length'],
  String(Buffer.byteLength('{"ok":true}')),
);
assert.equal(mock.state.body.toString(), '{"ok":true}');
let lookupResult;
mock.state.options.lookup('api.github.com', {}, (...args) => {
  lookupResult = args;
});
assert.deepEqual(lookupResult, [null, PUBLIC_V4.address, 4]);
mock.state.options.lookup('api.github.com', { all: true }, (...args) => {
  lookupResult = args;
});
assert.deepEqual(lookupResult, [null, [PUBLIC_V4]]);
mock.state.options.lookup('evil.example', {}, (...args) => {
  lookupResult = args;
});
assert.equal(lookupResult[0].code, 'PINNED_DNS_MISMATCH');

assert.throws(() => createPinnedHttpsRequest({ resolveHost: null }), TypeError);
assert.throws(() => createPinnedHttpsRequest({ requestImpl: null }), TypeError);
assert.throws(() => createPinnedHttpsRequest({ timeoutMs: 99 }), TypeError);
const makeRequest = ({ addresses = [PUBLIC_V4], mockOptions = {}, requestImpl } = {}) => {
  const item = createRequestMock(mockOptions);
  return {
    item,
    call: createPinnedHttpsRequest({
      resolveHost: async () => addresses,
      requestImpl: requestImpl || item.requestImpl,
    }),
  };
};
const validInput = {
  origin: 'https://api.github.com',
  method: 'GET',
  path: '/repos/owner/repo',
  headers: { Accept: 'application/json' },
  max_response_bytes: 32,
  redirect: 'manual',
};
for (const [change, code] of [
  [{ redirect: 'follow' }, 'PINNED_REDIRECT_POLICY_REQUIRED'],
  [{ origin: 'http://api.github.com' }, 'OUTBOUND_POLICY_DENIED'],
  [{ path: 'https://evil.example' }, 'OUTBOUND_POLICY_DENIED'],
  [{ method: 'TRACE' }, 'OUTBOUND_POLICY_DENIED'],
  [{ method: 'GET', body: 'x' }, 'PINNED_BODY_DENIED'],
  [{ method: 'POST', body: {} }, 'PINNED_BODY_INVALID'],
  [{ method: 'POST', body: 'x'.repeat(1024 * 1024 + 1) }, 'PINNED_BODY_TOO_LARGE'],
  [{ headers: null }, 'PINNED_HEADERS_INVALID'],
  [{ headers: { Host: 'evil.example' } }, 'PINNED_HEADERS_INVALID'],
  [{ headers: { Good: 'ok', good: 'duplicate' } }, 'PINNED_HEADERS_INVALID'],
  [{ headers: { Accept: 'ok\r\nbad' } }, 'PINNED_HEADERS_INVALID'],
  [{ max_response_bytes: 0 }, 'PINNED_RESPONSE_LIMIT_INVALID'],
])
  await assert.rejects(
    makeRequest().call({ ...validInput, ...change }),
    (error) => error.code === code,
  );

await assert.rejects(
  createPinnedHttpsRequest({
    resolveHost: async () => {
      throw new Error('dns detail');
    },
  })(validInput),
  (error) => expectCode('PINNED_DNS_FAILED')(error) && !error.message.includes('detail'),
);
const aborted = new AbortController();
aborted.abort();
await assert.rejects(
  createPinnedHttpsRequest({ resolveHost: async () => [PUBLIC_V4] })({
    ...validInput,
    signal: aborted.signal,
  }),
  expectCode('PINNED_REQUEST_ABORTED'),
);
await assert.rejects(
  createPinnedHttpsRequest({
    resolveHost: async () => new Promise(() => {}),
    timeoutMs: 100,
  })(validInput),
  expectCode('PINNED_DNS_TIMEOUT'),
);
await assert.rejects(
  makeRequest({ addresses: [] }).call(validInput),
  expectCode('PINNED_DNS_FAILED'),
);
await assert.rejects(
  makeRequest({ addresses: [{ address: '127.0.0.1', family: 4 }] }).call(validInput),
  expectCode('PINNED_DNS_DENIED'),
);
await assert.rejects(
  makeRequest({ addresses: [PUBLIC_V4, { address: '10.0.0.1', family: 4 }] }).call(validInput),
  expectCode('PINNED_DNS_DENIED'),
);
await assert.rejects(
  makeRequest({ addresses: [{ ...PUBLIC_V4, family: 0 }] }).call(validInput),
  expectCode('PINNED_DNS_FAILED'),
);

await assert.rejects(
  makeRequest({ mockOptions: { chunks: ['x'.repeat(33)] } }).call(validInput),
  expectCode('PINNED_RESPONSE_TOO_LARGE'),
);
const declared = makeRequest({ mockOptions: { headers: { 'content-length': '33' }, chunks: [] } });
await assert.rejects(declared.call(validInput), expectCode('PINNED_RESPONSE_TOO_LARGE'));
assert.equal(declared.item.state.responseDestroyed, true);
await assert.rejects(
  makeRequest({ mockOptions: { responseError: 'response detail' } }).call(validInput),
  (error) => expectCode('PINNED_RESPONSE_FAILED')(error) && !error.message.includes('detail'),
);
await assert.rejects(
  makeRequest({ mockOptions: { requestError: 'request detail' } }).call(validInput),
  (error) => expectCode('PINNED_REQUEST_FAILED')(error) && !error.message.includes('detail'),
);
await assert.rejects(
  makeRequest({
    requestImpl: () => {
      throw new Error('sync detail');
    },
  }).call(validInput),
  (error) => expectCode('PINNED_REQUEST_FAILED')(error) && !error.message.includes('detail'),
);
await assert.rejects(
  makeRequest({
    requestImpl: () => ({
      setTimeout: () => {
        throw new Error('setup detail');
      },
      destroy: () => {},
    }),
  }).call(validInput),
  (error) => expectCode('PINNED_REQUEST_FAILED')(error) && !error.message.includes('detail'),
);

const timeoutState = {};
const timeoutCall = createPinnedHttpsRequest({
  resolveHost: async () => [PUBLIC_V4],
  requestImpl: () => {
    const pendingRequest = new EventEmitter();
    pendingRequest.setTimeout = (_value, handler) => {
      timeoutState.handler = handler;
    };
    pendingRequest.destroy = () => {
      timeoutState.destroyed = true;
    };
    pendingRequest.end = () => {};
    return pendingRequest;
  },
});
const timeoutPromise = timeoutCall(validInput);
await new Promise((resolve) => setImmediate(resolve));
timeoutState.handler();
await assert.rejects(timeoutPromise, expectCode('PINNED_REQUEST_TIMEOUT'));
assert.equal(timeoutState.destroyed, true);

assert.deepEqual(PINNED_HTTPS_LIMITS, {
  maximum_request_bytes: 1024 * 1024,
  maximum_response_bytes: 10 * 1024 * 1024,
  maximum_timeout_ms: 60_000,
});

console.log('pinned HTTPS request: DNS pinning, TLS, bounds, redirects and safe failures passed');
