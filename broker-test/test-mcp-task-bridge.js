import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

import { createMcpTaskBridge, MCP_CONTROL_TOOLS } from '../broker/lib/mcp-task-bridge.js';
import {
  createBrokerClient,
  createMcpHttpServer,
  normalizeBrokerOrigin,
  parseArgs,
} from '../broker/mcp-server.js';

const TASK_ID = '00000000-0000-4000-8000-000000000010';
const API_KEY = `mb_test_${'A'.repeat(32)}`;
const executable = {
  name: 'google_drive.document.read',
  version: '1.0.0',
  description: 'Read one filtered document.',
  risk_level: 'MEDIUM',
  environments: ['production'],
  input_schema: {
    type: 'object',
    additionalProperties: false,
    required: ['resource_ref'],
    properties: { resource_ref: { type: 'string' } },
  },
};

assert.deepEqual(parseArgs(['node', 'mcp', '--port', '3001']), { port: '3001' });
assert.throws(() => parseArgs(['node', 'mcp', 'value']), /positional/);
assert.throws(() => parseArgs(['node', 'mcp', '--port']), /Missing/);
assert.equal(normalizeBrokerOrigin('https://broker.example:8443'), 'https://broker.example:8443');
for (const value of [
  'http://broker.example',
  'https://user@broker.example',
  'https://broker.example/path',
  'https://broker.example?token=x',
]) {
  assert.throws(() => normalizeBrokerOrigin(value), /HTTPS origin/);
}

const calls = [];
let createState = 'READY';
const bridge = createMcpTaskBridge({
  callBroker: async (path, options) => {
    calls.push([path, options]);
    if (path === '/api/v2/tools') return { registry_version: 1, tools: [executable] };
    if (path === '/api/v2/tasks') return { id: TASK_ID, state: createState };
    if (path.endsWith('/events')) return { events: [] };
    return { id: TASK_ID, state: path.endsWith('/cancel') ? 'CANCELLED' : 'SUCCEEDED' };
  },
});
const tools = await bridge.listTools();
assert.equal(tools.length, MCP_CONTROL_TOOLS.length + 1);
const driveTool = tools.find((tool) => tool.name.startsWith('broker_execute__'));
assert.equal(driveTool.name, 'broker_execute__google_drive_document_read__v1_0_0');
assert.equal(driveTool.inputSchema.additionalProperties, false);
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
  origin: 'https://broker.example:8443',
  apiKey: API_KEY,
  requestImpl,
});
assert.deepEqual(await client('/api/v2/tools'), { registry_version: 1, tools: [] });
assert.equal(requestOptions.rejectUnauthorized, true);
assert.equal(requestOptions.servername, 'broker.example');
assert.equal(requestOptions.headers.Authorization, `Bearer ${API_KEY}`);
await assert.rejects(client('https://attacker.invalid/api/v2/tools'), /not allowed/);
await assert.rejects(client('/api/v1/secrets/resolve'), /not allowed/);
assert.throws(
  () => createBrokerClient({ origin: 'https://broker.example', apiKey: 'mb_live_master' }),
  /valid scoped/,
);

let httpHandler;
createMcpHttpServer({
  bridge,
  port: 3001,
  createServerImpl: (handler) => {
    httpHandler = handler;
    return { listen() {} };
  },
});
async function httpRequest({ host = '127.0.0.1:3001', origin, body = '{}', url = '/mcp' } = {}) {
  const request = new EventEmitter();
  request.method = 'POST';
  request.url = url;
  request.headers = { host, 'content-type': 'application/json' };
  if (origin) request.headers.origin = origin;
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
const rpc = await httpRequest({
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
});
assert.equal(rpc.status, 200);
assert.equal(Object.hasOwn(rpc.headers, 'Access-Control-Allow-Origin'), false);
assert.equal(
  JSON.parse(rpc.body).result.tools.some((tool) => tool.name === driveTool.name),
  true,
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
