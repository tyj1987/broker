import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { PassThrough, Readable } from 'node:stream';

import { createMcpTaskBridge, MCP_CONTROL_TOOLS } from '../broker/lib/mcp-task-bridge.js';
import {
  boot,
  createBrokerClient,
  createMcpHttpServer,
  createMcpStdioServer,
  normalizeBrokerOrigin,
  parseArgs,
} from '../broker/mcp-server.js';

const TASK_ID = '00000000-0000-4000-8000-000000000010';
const API_KEY = `mb_test_${'A'.repeat(32)}`;
const LISTENER_TOKEN = 'B'.repeat(43);
const executable = {
  name: 'google_drive.document.read',
  version: '1.0.0',
  description: 'Read one filtered document with sk-proj-canary-secret-token-1234567890.',
  risk_level: 'MEDIUM',
  environments: ['production'],
  input_schema: {
    type: 'object',
    additionalProperties: false,
    required: ['resource_ref'],
    properties: {
      resource_ref: {
        type: 'string',
        description: 'Use sk-proj-schema-canary-secret-token-1234567890 only for tests.',
        default: 'Bearer sk-proj-schema-canary-secret-token-1234567890',
        examples: ['https://private.example/sk-proj-schema-canary-secret-token-1234567890'],
      },
    },
  },
};

assert.deepEqual(parseArgs(['node', 'mcp', '--port', '3001']), { port: '3001' });
assert.throws(() => parseArgs(['node', 'mcp', 'value']), /positional/);
assert.throws(() => parseArgs(['node', 'mcp', '--port']), /Missing/);
assert.throws(() => parseArgs(['node', 'mcp', '--port', '1', '--port', '2']), /duplicate/);
assert.throws(() => parseArgs(['node', 'mcp', '--', 'value']), /duplicate/);
assert.equal(normalizeBrokerOrigin('https://broker.52trz.com'), 'https://broker.52trz.com');
assert.equal(normalizeBrokerOrigin('https://127.0.0.1:18443'), 'https://127.0.0.1:18443');
for (const value of [
  'http://broker.52trz.com',
  'https://user@broker.52trz.com',
  'https://broker.52trz.com/path',
  'https://broker.52trz.com?token=x',
  'https://broker.52trz.com#fragment',
]) {
  assert.throws(() => normalizeBrokerOrigin(value), /HTTPS origin/);
}
assert.throws(() => normalizeBrokerOrigin('not a url'), /invalid/);
for (const value of ['https://evil.example', 'https://169.254.169.254', 'https://127.0.0.1:8443']) {
  assert.throws(() => normalizeBrokerOrigin(value), /approved origin/);
}

const calls = [];
let createState = 'READY';
const bridge = createMcpTaskBridge({
  callBroker: async (path, options) => {
    calls.push([path, options]);
    if (path === '/api/v2/tools') return { registry_version: 1, tools: [executable] };
    if (path === '/api/v2/tasks') return {
      id: TASK_ID,
      state: createState,
      token: 'canary-secret-token',
      result: { authorization: 'Bearer canary-secret-token' },
    };
    if (path.endsWith('/events')) return { events: [] };
    return {
      id: TASK_ID,
      state: path.endsWith('/cancel') ? 'CANCELLED' : 'SUCCEEDED',
      token: 'canary-secret-token',
      result: { authorization: 'Bearer canary-secret-token' },
    };
  },
});
const tools = await bridge.listTools();
assert.equal(tools.length, MCP_CONTROL_TOOLS.length + 1);
const driveTool = tools.find((tool) => tool.name.startsWith('broker_execute__'));
assert.equal(driveTool.name, 'broker_execute__google_drive_document_read__v1_0_0');
assert.equal(driveTool.inputSchema.additionalProperties, false);
assert.equal(driveTool.description.includes('sk-proj-canary-secret-token'), false);
const projectedSchema = JSON.stringify(driveTool.inputSchema.properties.resource_ref);
assert.equal(projectedSchema.includes('schema-canary-secret-token'), false);
assert.equal(projectedSchema.includes('sk-proj-***'), true);
assert.deepEqual(driveTool.inputSchema.required, [
  'account_ref',
  'environment',
  'idempotency_key',
  'resource_ref',
]);

calls.length = 0;
const completed = await bridge.callTool(driveTool.name, {
  account_ref: 'reports',
  environment: 'production',
  idempotency_key: 'mcp-drive-task-0001',
  resource_ref: '1AbCdEfGhIjKlMnOpQrStUvWxYz',
});
assert.equal(completed.state, 'SUCCEEDED');
assert.equal(completed.token, '[REDACTED]');
assert.equal(completed.result.authorization, '[REDACTED]');
assert.deepEqual(calls[1], [
  '/api/v2/tasks',
  {
    method: 'POST',
    body: {
      tool: 'google_drive.document.read',
      tool_version: '1.0.0',
      account_ref: 'reports',
      environment: 'production',
      idempotency_key: 'mcp-drive-task-0001',
      parameters: { resource_ref: '1AbCdEfGhIjKlMnOpQrStUvWxYz' },
    },
  },
]);
assert.deepEqual(calls[2], [`/api/v2/tasks/${TASK_ID}/run`, { method: 'POST', body: {} }]);

createState = 'PENDING_APPROVAL';
calls.length = 0;
assert.equal(
  (
    await bridge.callTool(driveTool.name, {
      account_ref: 'reports',
      environment: 'production',
      idempotency_key: 'mcp-drive-task-0002',
      resource_ref: '1AbCdEfGhIjKlMnOpQrStUvWxYz',
    })
  ).state,
  'PENDING_APPROVAL',
);
assert.equal(calls.length, 2);

for (const [name, suffix, method] of [
  ['broker_task_get', '', 'GET'],
  ['broker_task_run', '/run', 'POST'],
  ['broker_task_cancel', '/cancel', 'POST'],
  ['broker_task_events', '/events', 'GET'],
]) {
  calls.length = 0;
  await bridge.callTool(name, { task_id: TASK_ID });
  assert.equal(calls[0][0], `/api/v2/tasks/${TASK_ID}${suffix}`);
  assert.equal(calls[0][1].method, method);
}
await assert.rejects(bridge.callTool('broker_task_get', { task_id: '../other' }), /valid task_id/);
await assert.rejects(
  bridge.callTool('broker_task_get', { task_id: TASK_ID, extra: true }),
  /Unknown task control field/,
);
await assert.rejects(bridge.callTool('list_secrets', {}), /Unknown or unavailable/);
await assert.rejects(bridge.callTool(driveTool.name, null), /arguments must be an object/);
assert.throws(() => createMcpTaskBridge(), TypeError);

for (const invalidRegistry of [
  null,
  { registry_version: 2, tools: [] },
  { registry_version: 1, tools: {} },
  { registry_version: 1, tools: [null] },
  { registry_version: 1, tools: [{ ...executable, version: 'latest' }] },
  {
    registry_version: 1,
    tools: [
      {
        ...executable,
        input_schema: {
          ...executable.input_schema,
          properties: { account_ref: { type: 'string' } },
        },
      },
    ],
  },
  { registry_version: 1, tools: [executable, executable] },
]) {
  const invalidBridge = createMcpTaskBridge({ callBroker: async () => invalidRegistry });
  await assert.rejects(invalidBridge.listTools());
}

let requestOptions;
const requestImpl = (options, callback) => {
  requestOptions = options;
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {};
  request.end = () => {
    const response = Readable.from([JSON.stringify({ registry_version: 1, tools: [] })]);
    response.statusCode = 200;
    queueMicrotask(() => callback(response));
  };
  return request;
};
const client = createBrokerClient({
  origin: 'https://127.0.0.1:18443',
  apiKey: API_KEY,
  requestImpl,
});
assert.deepEqual(await client('/api/v2/tools'), { registry_version: 1, tools: [] });
assert.equal(requestOptions.rejectUnauthorized, true);
assert.equal(requestOptions.servername, '127.0.0.1');
assert.equal(requestOptions.headers.Authorization, `Bearer ${API_KEY}`);
await assert.rejects(client('https://attacker.invalid/api/v2/tools'), /not allowed/);
await assert.rejects(client('/api/v1/secrets/resolve'), /not allowed/);
assert.throws(
  () => createBrokerClient({ origin: 'https://broker.52trz.com', apiKey: 'mb_live_master' }),
  /valid scoped/,
);
assert.throws(
  () => createBrokerClient({ origin: 'https://broker.52trz.com', apiKey: API_KEY, requestImpl: 1 }),
  /implementation/,
);
for (const timeoutMs of [99, 60_001, 100.5]) {
  assert.throws(
    () => createBrokerClient({ origin: 'https://broker.52trz.com', apiKey: API_KEY, timeoutMs }),
    /timeout/,
  );
}
assert.throws(
  () => createBrokerClient({ origin: 'https://broker.52trz.com', apiKey: API_KEY, cert: 'cert' }),
  /configured together/,
);
await assert.rejects(client('/api/v2/tools', { method: 'DELETE' }), /method/);
await assert.rejects(client('/api/v2/tools', { body: {} }), /GET request body/);
await assert.rejects(
  client('/api/v2/tasks', { method: 'POST', body: { value: 'x'.repeat(1024 * 1024) } }),
  /too large/,
);

function brokerClientForResponse({
  statusCode = 200,
  chunks = ['{}'],
  responseError,
  requestError,
}) {
  return createBrokerClient({
    origin: 'https://broker.52trz.com',
    apiKey: API_KEY,
    requestImpl: (_options, callback) => {
      const request = new EventEmitter();
      request.setTimeout = () => {};
      request.destroy = () => {};
      request.end = () => {
        if (requestError) {
          queueMicrotask(() => request.emit('error', new Error('sensitive upstream detail')));
          return;
        }
        const response = new EventEmitter();
        response.statusCode = statusCode;
        response.destroy = () => {};
        queueMicrotask(() => {
          callback(response);
          for (const chunk of chunks) response.emit('data', chunk);
          if (responseError) response.emit('error', new Error('sensitive response detail'));
          else response.emit('end');
        });
      };
      return request;
    },
  });
}
await assert.rejects(
  brokerClientForResponse({ statusCode: 403, chunks: ['{"error":{"code":"policy_denied"}}'] })(
    '/api/v2/tools',
  ),
  /403, policy_denied/,
);
await assert.rejects(
  brokerClientForResponse({ statusCode: 409, chunks: ['{"error":"invalid_state","message":"not executable"}'] })(
    '/api/v2/tasks/00000000-0000-4000-8000-000000000010/run', { method: 'POST', body: {} },
  ),
  /409, invalid_state/,
);
await assert.rejects(
  brokerClientForResponse({ statusCode: 500, chunks: ['{"error":"unsafe code"}'] })(
    '/api/v2/tools',
  ),
  /500, broker_request_failed/,
);
await assert.rejects(
  brokerClientForResponse({ statusCode: 500, chunks: ['not-json'] })('/api/v2/tools'),
  /500, broker_request_failed/,
);
await assert.rejects(
  brokerClientForResponse({ chunks: ['not-json'] })('/api/v2/tools'),
  /invalid JSON/,
);
await assert.rejects(
  brokerClientForResponse({ responseError: true })('/api/v2/tools'),
  /response failed/,
);
await assert.rejects(
  brokerClientForResponse({ requestError: true })('/api/v2/tools'),
  /request failed/,
);
await assert.rejects(
  brokerClientForResponse({ chunks: [Buffer.alloc(1024 * 1024 + 1)] })('/api/v2/tools'),
  /response is too large/,
);
const throwingClient = createBrokerClient({
  origin: 'https://broker.52trz.com',
  apiKey: API_KEY,
  requestImpl: () => {
    throw new Error('sensitive request detail');
  },
});
await assert.rejects(throwingClient('/api/v2/tools'), /request failed/);

let httpHandler;
createMcpHttpServer({
  bridge,
  listenerToken: LISTENER_TOKEN,
  port: 3001,
  createServerImpl: (handler) => {
    httpHandler = handler;
    return { listen() {} };
  },
});
async function httpRequest({
  host = '127.0.0.1:3001',
  origin,
  authorization = `Bearer ${LISTENER_TOKEN}`,
  body = '{}',
  url = '/mcp',
  method = 'POST',
  contentType = 'application/json',
} = {}) {
  const request = new EventEmitter();
  request.method = method;
  request.url = url;
  request.headers = { host, 'content-type': contentType };
  request.destroy = () => {};
  if (origin) request.headers.origin = origin;
  if (authorization) request.headers.authorization = authorization;
  const observed = { headers: null, status: null, body: null };
  const response = {
    writeHead(status, headers) {
      observed.status = status;
      observed.headers = headers;
    },
    end(value) {
      observed.body = value;
    },
  };
  const pending = httpHandler(request, response);
  queueMicrotask(() => {
    request.emit('data', Buffer.from(body));
    request.emit('end');
  });
  await pending;
  return observed;
}
assert.equal((await httpRequest({ origin: 'https://attacker.invalid' })).status, 403);
assert.equal((await httpRequest({ host: 'attacker.invalid:3001' })).status, 403);
assert.equal((await httpRequest({ authorization: null })).status, 401);
assert.equal((await httpRequest({ authorization: 'Basic local' })).status, 401);
assert.equal((await httpRequest({ authorization: `Bearer ${'C'.repeat(43)}` })).status, 401);
assert.equal((await httpRequest({ authorization: 'Bearer short' })).status, 401);
assert.equal((await httpRequest({ method: 'GET', url: '/health' })).status, 200);
assert.equal((await httpRequest({ method: 'GET', url: '/mcp' })).status, 404);
assert.equal((await httpRequest({ url: '/other' })).status, 404);
assert.equal((await httpRequest({ contentType: 'text/plain' })).status, 404);
assert.equal((await httpRequest({ body: 'not-json' })).status, 400);
assert.equal((await httpRequest({ body: '[]' })).status, 400);
assert.equal((await httpRequest({ body: JSON.stringify(Array(33).fill({})) })).status, 400);
assert.equal(
  (
    await httpRequest({
      body: JSON.stringify([
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'ping' },
      ]),
    })
  ).status,
  200,
);
assert.equal(
  (
    await httpRequest({
      body: JSON.stringify([{ jsonrpc: '2.0', method: 'notifications/initialized' }]),
    })
  ).status,
  204,
);
assert.equal(
  (await httpRequest({ body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'initialize' }) }))
    .status,
  200,
);
assert.equal(
  (await httpRequest({ body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'unknown' }) }))
    .status,
  200,
);
assert.equal((await httpRequest({ body: '{}' })).status, 200);
const rpc = await httpRequest({
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
});
assert.equal(rpc.status, 200);
assert.equal(Object.hasOwn(rpc.headers, 'Access-Control-Allow-Origin'), false);
assert.equal(
  JSON.parse(rpc.body).result.tools.some((tool) => tool.name === driveTool.name),
  true,
);
const rpcCall = await httpRequest({
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: { name: 'broker_task_get', arguments: { task_id: TASK_ID } },
  }),
});
assert.equal(JSON.parse(rpcCall.body).result.isError, false);
const rpcCallFailure = await httpRequest({
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 6,
    method: 'tools/call',
    params: { name: 'list_secrets', arguments: {} },
  }),
});
assert.equal(JSON.parse(rpcCallFailure.body).result.isError, true);
const tooLargeBody = await httpRequest({ body: JSON.stringify('x'.repeat(1024 * 1024)) });
assert.equal(tooLargeBody.status, 400);
assert.throws(() => createMcpHttpServer({ bridge, listenerToken: 'short' }), /listener token/);
assert.throws(() => createMcpHttpServer({ listenerToken: LISTENER_TOKEN }), /bridge/);
for (const port of [0, 65_536, 1.5]) {
  assert.throws(() => createMcpHttpServer({ bridge, listenerToken: LISTENER_TOKEN, port }), /port/);
}

const stdioInput = new PassThrough();
const stdioOutput = new PassThrough();
let stdioText = '';
stdioOutput.on('data', (chunk) => { stdioText += chunk.toString('utf8'); });
const stdioServer = createMcpStdioServer({ bridge, input: stdioInput, output: stdioOutput });
stdioInput.write(`${JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'initialize' })}\n`);
stdioInput.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
stdioInput.write(`${JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'tools/list' })}\n`);
await stdioServer.pending;
const stdioMessages = stdioText.trim().split('\n').map((line) => JSON.parse(line));
assert.deepEqual(stdioMessages.map((message) => message.id), [11, 12]);
assert.match(stdioMessages[0].result.instructions, /Never request, print, store or infer credentials/);
assert.equal(stdioMessages[1].result.tools.some((tool) => tool.name === driveTool.name), true);
stdioText = '';
stdioInput.write('not-json\n');
stdioInput.write('[]\n');
await stdioServer.pending;
const stdioErrors = stdioText.trim().split('\n').map((line) => JSON.parse(line));
assert.deepEqual(stdioErrors.map((message) => message.error.code), [-32700, -32600]);

const failingMcpInput = new PassThrough();
const failingMcpOutput = new PassThrough();
let failingMcpText = '';
failingMcpOutput.on('data', (chunk) => { failingMcpText += chunk.toString('utf8'); });
const failingMcp = createMcpStdioServer({
  bridge: {
    async listTools() { throw new Error('canary-secret /srv/private/key.pem'); },
    async callTool() { throw new Error('canary-secret /srv/private/key.pem'); },
  },
  input: failingMcpInput,
  output: failingMcpOutput,
});
failingMcpInput.write('{"jsonrpc":"2.0","id":21,"method":"tools/list"}\n');
failingMcpInput.write('{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"x"}}\n');
await failingMcp.pending;
assert.doesNotMatch(failingMcpText, /canary-secret|\/srv\/private/);
assert.match(failingMcpText, /tool_list_failed|tool_execution_failed/);
assert.throws(() => createMcpStdioServer({ input: stdioInput, output: stdioOutput }), /bridge/);
assert.throws(() => createMcpStdioServer({ bridge, input: {}, output: stdioOutput }), /streams/);

let bootListen;
const bootFiles = new Map([
  ['api-key', API_KEY],
  ['listener-token', LISTENER_TOKEN],
  ['cert', 'certificate'],
  ['key', 'private-key'],
  ['ca', 'certificate-authority'],
]);
const bootServer = await boot(
  [
    'node',
    'mcp',
    '--api-key-file',
    'api-key',
    '--listener-token-file',
    'listener-token',
    '--client-cert-file',
    'cert',
    '--client-key-file',
    'key',
    '--ca-file',
    'ca',
    '--broker',
    'https://broker.52trz.com',
    '--port',
    '3002',
    '--host',
    '::1',
  ],
  {},
  {
    readFileImpl: (path) => {
      if (!bootFiles.has(path)) throw new Error('missing');
      return Buffer.from(bootFiles.get(path));
    },
    requestImpl,
    createServerImpl: () => ({
      listen(port, host, callback) {
        bootListen = { port, host };
        callback();
      },
    }),
  },
);
assert.equal(typeof bootServer.listen, 'function');
assert.deepEqual(bootListen, { port: 3002, host: '::1' });
const bootStdioInput = new PassThrough();
const bootStdioOutput = new PassThrough();
const bootStdio = await boot(
  ['node', 'mcp', '--api-key-file', 'api-key', '--transport', 'stdio'],
  {},
  {
    readFileImpl: (path) => Buffer.from(bootFiles.get(path)),
    requestImpl,
    input: bootStdioInput,
    output: bootStdioOutput,
  },
);
assert.equal(typeof bootStdio.pending.then, 'function');
await assert.rejects(
  boot(
    ['node', 'mcp', '--api-key-file', 'api-key', '--transport', 'stdio', '--port', '3001'],
    {},
    { readFileImpl: (path) => Buffer.from(bootFiles.get(path)), requestImpl },
  ),
  /not allowed with stdio/,
);
await assert.rejects(
  boot(
    ['node', 'mcp', '--api-key-file', 'api-key', '--transport', 'invalid'],
    {},
    { readFileImpl: (path) => Buffer.from(bootFiles.get(path)), requestImpl },
  ),
  /transport is invalid/,
);
await assert.rejects(boot(['node', 'mcp', '--master-key', 'value'], {}), /not supported/);
await assert.rejects(boot(['node', 'mcp'], { MCP_MASTER_KEY: 'value' }), /not supported/);
await assert.rejects(
  boot(
    ['node', 'mcp', '--api-key-file', 'missing'],
    {},
    {
      readFileImpl: () => {
        throw new Error('missing');
      },
    },
  ),
  /could not be read/,
);
await assert.rejects(
  boot(
    ['node', 'mcp', '--api-key-file', 'api'],
    {},
    { readFileImpl: () => Buffer.from('invalid') },
  ),
  /API key file is invalid/,
);
await assert.rejects(
  boot(
    ['node', 'mcp', '--api-key-file', 'api', '--listener-token-file', 'listener'],
    {},
    { readFileImpl: (path) => Buffer.from(path === 'api' ? API_KEY : 'invalid') },
  ),
  /listener token file is invalid/,
);
await assert.rejects(
  boot(
    [
      'node',
      'mcp',
      '--api-key-file',
      'api',
      '--listener-token-file',
      'listener',
      '--host',
      '0.0.0.0',
    ],
    {},
    { readFileImpl: (path) => Buffer.from(path === 'api' ? API_KEY : LISTENER_TOKEN) },
  ),
  /loopback/,
);

const source = readFileSync(new URL('../broker/mcp-server.js', import.meta.url), 'utf8');
for (const forbidden of [
  'let MASTER_KEY',
  "ARGS['master-key']",
  'MCP_INSECURE_TLS',
  "name: 'list_secrets'",
  "name: 'call_service'",
  '/api/v1/secrets/resolve',
  "Access-Control-Allow-Origin', '*'",
]) {
  assert.equal(
    source.includes(forbidden),
    false,
    `MCP source retains forbidden surface: ${forbidden}`,
  );
}

console.log(
  'mcp task bridge: executable discovery, typed tasks and strict Broker transport passed',
);
