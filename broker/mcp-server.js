import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { stdin as processStdin, stdout as processStdout } from 'node:process';
import { fileURLToPath } from 'node:url';

import { createMcpTaskBridge } from './lib/mcp-task-bridge.js';
import { redact, redactDeep } from './lib/redact.js';

const MAX_HTTP_BODY_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const API_KEY_RE = /^mb_(?:live|test)_[0-9A-Za-z]{32}$/;
const LISTENER_TOKEN_RE = /^[A-Za-z0-9_-]{43,128}$/;
const TASK_PATH_RE = /^\/api\/v2\/(?:tools|tasks(?:\/[a-f0-9-]+(?:\/(?:run|cancel|events))?)?)$/;
const ALLOWED_BROKER_ORIGINS = new Set(['https://127.0.0.1:18443', 'https://broker.52trz.com']);
const SERVER_INFO = Object.freeze({
  name: 'secret-broker-mcp-server',
  version: '4.2.0',
  protocolVersion: '2025-06-18',
});
const SERVER_INSTRUCTIONS = [
  'Use only the typed Broker tools returned by tools/list.',
  'Never request, print, store or infer credentials.',
  'Respect PENDING_APPROVAL and do not retry an uncertain execution.',
  'Use a fresh idempotency_key for each new intent and reuse it only for an exact retry.',
].join(' ');

export function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith('--')) throw new Error('Unexpected positional MCP argument');
    const name = value.slice(2);
    if (!name || Object.hasOwn(args, name)) throw new Error('Invalid duplicate MCP argument');
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`Missing value for --${name}`);
    args[name] = next;
    index += 1;
  }
  return args;
}

export function normalizeBrokerOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Broker URL is invalid');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error('Broker URL must be an HTTPS origin');
  }
  if (!ALLOWED_BROKER_ORIGINS.has(url.origin)) {
    throw new Error('Broker URL is not an approved origin');
  }
  return url.origin;
}

function safeBrokerError(status, body) {
  let code = 'broker_request_failed';
  try {
    const parsed = JSON.parse(body);
    const candidate =
      typeof parsed?.error === 'string' ? parsed.error : parsed?.error?.code || parsed?.code;
    if (/^[a-z][a-z0-9_]{1,63}$/.test(candidate || '')) code = candidate;
  } catch {
    // Upstream bodies are intentionally omitted from MCP errors.
  }
  const error = new Error(`Broker request failed (${status}, ${code})`);
  error.code = code;
  error.status = status;
  return error;
}

export function createBrokerClient({
  origin,
  apiKey,
  ca,
  cert,
  key,
  requestImpl = httpsRequest,
  timeoutMs = REQUEST_TIMEOUT_MS,
} = {}) {
  const brokerOrigin = normalizeBrokerOrigin(origin);
  if (!API_KEY_RE.test(apiKey || ''))
    throw new TypeError('A valid scoped Broker API key is required');
  if (typeof requestImpl !== 'function')
    throw new TypeError('Broker request implementation is invalid');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError('Broker request timeout is invalid');
  }
  if ((cert && !key) || (key && !cert))
    throw new TypeError('Broker client certificate and key must be configured together');

  return async function callBroker(path, { method = 'GET', body } = {}) {
    if (!TASK_PATH_RE.test(path || '') || path.includes('..'))
      throw new Error('Broker path is not allowed');
    if (!['GET', 'POST'].includes(method)) throw new Error('Broker method is not allowed');
    if (method === 'GET' && body !== undefined) throw new Error('GET request body is not allowed');
    const encoded = body === undefined ? null : Buffer.from(JSON.stringify(body));
    if (encoded && encoded.byteLength > MAX_HTTP_BODY_BYTES)
      throw new Error('Broker request is too large');
    const url = new URL(path, brokerOrigin);
    if (url.origin !== brokerOrigin) throw new Error('Broker origin changed');

    return new Promise((resolve, reject) => {
      let settled = false;
      let request;
      const finish = (handler, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        handler(value);
      };
      const deadline = setTimeout(() => {
        request?.destroy();
        finish(reject, new Error('Broker request timed out'));
      }, timeoutMs);
      try {
        request = requestImpl(
          {
            protocol: 'https:',
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname,
            method,
            rejectUnauthorized: true,
            servername: url.hostname,
            ca,
            cert,
            key,
            headers: {
              Accept: 'application/json',
              Authorization: `Bearer ${apiKey}`,
              ...(encoded
                ? {
                    'Content-Type': 'application/json',
                    'Content-Length': String(encoded.byteLength),
                  }
                : {}),
            },
          },
          (response) => {
            const chunks = [];
            let total = 0;
            response.on('data', (chunk) => {
              if (settled) return;
              const value = Buffer.from(chunk);
              total += value.byteLength;
              if (total > MAX_HTTP_BODY_BYTES) {
                response.destroy();
                finish(reject, new Error('Broker response is too large'));
                return;
              }
              chunks.push(value);
            });
            response.on('end', () => {
              if (settled) return;
              const text = Buffer.concat(chunks).toString('utf8');
              if (response.statusCode < 200 || response.statusCode >= 300) {
                finish(reject, safeBrokerError(response.statusCode, text));
                return;
              }
              try {
                finish(resolve, JSON.parse(text));
              } catch {
                finish(reject, new Error('Broker returned invalid JSON'));
              }
            });
            response.on('error', () => finish(reject, new Error('Broker response failed')));
          },
        );
        request.setTimeout(timeoutMs, () => {
          request.destroy();
          finish(reject, new Error('Broker request timed out'));
        });
        request.on('error', () => finish(reject, new Error('Broker request failed')));
        request.end(encoded || undefined);
      } catch {
        request?.destroy?.();
        finish(reject, new Error('Broker request failed'));
      }
    });
  };
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function safeMcpErrorCode(error, fallback = 'tool_execution_failed') {
  const code = error?.code;
  return typeof code === 'string' &&
    /^[a-z][a-z0-9_]{1,63}$/.test(code) &&
    !/(secret|password|private|canary|material)/i.test(code)
    ? code
    : fallback;
}

async function handleRpc(bridge, request) {
  if (!request || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
    return rpcError(request?.id ?? null, -32600, 'Invalid JSON-RPC request');
  }
  if (request.method === 'notifications/initialized') return null;
  if (request.method === 'initialize') {
    return rpcResult(request.id, {
      protocolVersion: SERVER_INFO.protocolVersion,
      serverInfo: { name: SERVER_INFO.name, version: SERVER_INFO.version },
      capabilities: { tools: {} },
      instructions: SERVER_INSTRUCTIONS,
    });
  }
  if (request.method === 'ping') return rpcResult(request.id, {});
  if (request.method === 'tools/list') {
    try {
      return rpcResult(request.id, { tools: redactDeep(await bridge.listTools()) });
    } catch (error) {
      return rpcError(request.id, -32603, safeMcpErrorCode(error, 'tool_list_failed'));
    }
  }
  if (request.method === 'tools/call') {
    try {
      const data = redactDeep(
        await bridge.callTool(request.params?.name, request.params?.arguments || {}),
      );
      return rpcResult(request.id, {
        content: [{ type: 'text', text: JSON.stringify(data) }],
        isError: false,
      });
    } catch (error) {
      return rpcResult(request.id, {
        content: [{ type: 'text', text: `Error: ${safeMcpErrorCode(error)}` }],
        isError: true,
      });
    }
  }
  return rpcError(request.id, -32601, 'Method not found');
}

export function createMcpStdioServer({
  bridge,
  input = processStdin,
  output = processStdout,
} = {}) {
  if (!bridge || typeof bridge.listTools !== 'function' || typeof bridge.callTool !== 'function') {
    throw new TypeError('MCP bridge is invalid');
  }
  if (!input || typeof input.on !== 'function' || !output || typeof output.write !== 'function') {
    throw new TypeError('MCP stdio streams are invalid');
  }

  let buffer = Buffer.alloc(0);
  let stopped = false;
  let pending = Promise.resolve();
  const write = (message) => output.write(`${JSON.stringify(message)}\n`);
  const processLine = async (line) => {
    if (!line.trim()) return;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      write(rpcError(null, -32700, 'Parse error'));
      return;
    }
    if (Array.isArray(request)) {
      write(rpcError(null, -32600, 'Invalid JSON-RPC request'));
      return;
    }
    const response = await handleRpc(bridge, request);
    if (response !== null) write(response);
  };
  const stopOversizedInput = () => {
    if (stopped) return;
    stopped = true;
    buffer = Buffer.alloc(0);
    write(rpcError(null, -32700, 'MCP message is too large'));
    input.pause?.();
  };

  input.on('data', (chunk) => {
    if (stopped) return;
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    if (buffer.byteLength > MAX_HTTP_BODY_BYTES) {
      stopOversizedInput();
      return;
    }
    let newline;
    while ((newline = buffer.indexOf(0x0a)) >= 0) {
      const line = buffer.subarray(0, newline).toString('utf8').replace(/\r$/, '');
      buffer = buffer.subarray(newline + 1);
      pending = pending
        .then(() => processLine(line))
        .catch(() => {
          write(rpcError(null, -32603, 'Internal error'));
        });
    }
  });
  input.on('end', () => {
    if (stopped || buffer.byteLength === 0) return;
    const line = buffer.toString('utf8').replace(/\r$/, '');
    buffer = Buffer.alloc(0);
    pending = pending
      .then(() => processLine(line))
      .catch(() => {
        write(rpcError(null, -32603, 'Internal error'));
      });
  });
  return Object.freeze({
    get pending() {
      return pending;
    },
  });
}

function allowedHost(value, port) {
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  return allowed.has(String(value || '').toLowerCase());
}

function authorizedListenerRequest(header, listenerToken) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const candidate = Buffer.from(header.slice(7));
  const expected = Buffer.from(listenerToken);
  return candidate.byteLength === expected.byteLength && timingSafeEqual(candidate, expected);
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    request.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_HTTP_BODY_BYTES) {
        reject(new Error('Request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', () => reject(new Error('Request body failed')));
  });
}

export function createMcpHttpServer({
  bridge,
  listenerToken,
  port = 3001,
  createServerImpl = createHttpServer,
} = {}) {
  if (!bridge || typeof bridge.listTools !== 'function' || typeof bridge.callTool !== 'function') {
    throw new TypeError('MCP bridge is invalid');
  }
  if (!LISTENER_TOKEN_RE.test(listenerToken || '')) {
    throw new TypeError('MCP listener token is invalid');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new TypeError('MCP port is invalid');

  return createServerImpl(async (request, response) => {
    const send = (status, body) => {
      response.writeHead(status, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      response.end(body === '' ? '' : JSON.stringify(body));
    };
    if (!allowedHost(request.headers.host, port) || request.headers.origin) {
      send(403, { error: 'request_origin_denied' });
      return;
    }
    if (!authorizedListenerRequest(request.headers.authorization, listenerToken)) {
      send(401, { error: 'listener_unauthorized' });
      return;
    }
    if (request.method === 'GET' && request.url === '/health') {
      send(200, { status: 'ok', server: SERVER_INFO.name, version: SERVER_INFO.version });
      return;
    }
    if (
      request.method !== 'POST' ||
      !['/', '/mcp'].includes(request.url) ||
      !String(request.headers['content-type'] || '')
        .toLowerCase()
        .startsWith('application/json')
    ) {
      send(404, { error: 'not_found' });
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(await readRequestBody(request));
    } catch {
      send(400, rpcError(null, -32700, 'Parse error'));
      return;
    }
    if (Array.isArray(parsed)) {
      if (parsed.length < 1 || parsed.length > 32) {
        send(400, rpcError(null, -32600, 'Invalid batch'));
        return;
      }
      const results = (await Promise.all(parsed.map((item) => handleRpc(bridge, item)))).filter(
        Boolean,
      );
      send(results.length ? 200 : 204, results.length ? results : '');
      return;
    }
    const result = await handleRpc(bridge, parsed);
    send(result === null ? 204 : 200, result === null ? '' : result);
  });
}

function readCredential(path, label, readFileImpl = readFileSync) {
  if (typeof path !== 'string' || !path) throw new Error(`${label} file is required`);
  try {
    return readFileImpl(path);
  } catch {
    throw new Error(`${label} file could not be read`);
  }
}

export async function boot(
  argv = process.argv,
  environment = process.env,
  {
    readFileImpl = readFileSync,
    requestImpl = httpsRequest,
    createServerImpl = createHttpServer,
    input = processStdin,
    output = processStdout,
  } = {},
) {
  const args = parseArgs(argv);
  if (args['master-key'] || args['master-key-file'] || environment.MCP_MASTER_KEY) {
    throw new Error('MCP master keys are not supported');
  }
  const apiKey = readCredential(args['api-key-file'], 'Broker API key', readFileImpl)
    .toString('utf8')
    .trim();
  if (!API_KEY_RE.test(apiKey)) throw new Error('Broker API key file is invalid');
  const transport = args.transport || 'http';
  if (!['http', 'stdio'].includes(transport)) throw new Error('MCP transport is invalid');
  const origin = normalizeBrokerOrigin(args.broker || 'https://127.0.0.1:18443');

  const cert = args['client-cert-file']
    ? readCredential(args['client-cert-file'], 'Broker client certificate', readFileImpl)
    : undefined;
  const key = args['client-key-file']
    ? readCredential(args['client-key-file'], 'Broker client key', readFileImpl)
    : undefined;
  const ca = args['ca-file']
    ? readCredential(args['ca-file'], 'Broker CA', readFileImpl)
    : undefined;
  const callBroker = createBrokerClient({ origin, apiKey, cert, key, ca, requestImpl });
  const bridge = createMcpTaskBridge({ callBroker });
  if (transport === 'stdio') {
    if (args['listener-token-file'] || args.host || args.port) {
      throw new Error('HTTP listener options are not allowed with stdio transport');
    }
    await bridge.listTools();
    const server = createMcpStdioServer({ bridge, input, output });
    console.error('[mcp] ready on stdio; typed Broker tasks only');
    return server;
  }
  const listenerToken = readCredential(
    args['listener-token-file'],
    'MCP listener token',
    readFileImpl,
  )
    .toString('utf8')
    .trim();
  if (!LISTENER_TOKEN_RE.test(listenerToken) || listenerToken === apiKey) {
    throw new Error('MCP listener token file is invalid');
  }
  const port = Number(args.port || 3001);
  const host = args.host || '127.0.0.1';
  if (!['127.0.0.1', '::1'].includes(host)) throw new Error('MCP must bind to a loopback address');
  const server = createMcpHttpServer({ bridge, listenerToken, port, createServerImpl });
  await bridge.listTools();
  server.listen(port, host, () => {
    console.error(`[mcp] ready on ${host}:${port}; typed Broker tasks only`);
  });
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  boot().catch((error) => {
    console.error(`[mcp] startup failed: ${redact(error.message)}`);
    process.exitCode = 1;
  });
}
