import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { fileURLToPath } from 'node:url';

import { createMcpTaskBridge } from './lib/mcp-task-bridge.js';
import { redact } from './lib/redact.js';

const MAX_HTTP_BODY_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const API_KEY_RE = /^mb_(?:live|test)_[0-9A-Za-z]{32}$/;
const TASK_PATH_RE = /^\/api\/v2\/(?:tools|tasks(?:\/[a-f0-9-]+(?:\/(?:run|cancel|events))?)?)$/;
const SERVER_INFO = Object.freeze({
  name: 'secret-broker-mcp-server',
  version: '4.2.0',
  protocolVersion: '2025-06-18',
});

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
  return url.origin;
}

function safeBrokerError(status, body) {
  let code = 'broker_request_failed';
  try {
    const parsed = JSON.parse(body);
    const candidate = parsed?.error?.code || parsed?.code;
    if (/^[a-z][a-z0-9_]{1,63}$/.test(candidate || '')) code = candidate;
  } catch {
    // Upstream bodies are intentionally omitted from MCP errors.
  }
  return new Error(`Broker request failed (${status}, ${code})`);
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
    });
  }
  if (request.method === 'ping') return rpcResult(request.id, {});
  if (request.method === 'tools/list') {
    try {
      return rpcResult(request.id, { tools: await bridge.listTools() });
    } catch (error) {
      return rpcError(request.id, -32603, redact(error.message));
    }
  }
  if (request.method === 'tools/call') {
    try {
      const data = await bridge.callTool(request.params?.name, request.params?.arguments || {});
      return rpcResult(request.id, {
        content: [{ type: 'text', text: JSON.stringify(data) }],
        isError: false,
      });
    } catch (error) {
      return rpcResult(request.id, {
        content: [{ type: 'text', text: `Error: ${redact(error.message)}` }],
        isError: true,
      });
    }
  }
  return rpcError(request.id, -32601, 'Method not found');
}

function allowedHost(value, port) {
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  return allowed.has(String(value || '').toLowerCase());
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
  port = 3001,
  createServerImpl = createHttpServer,
} = {}) {
  if (!bridge || typeof bridge.listTools !== 'function' || typeof bridge.callTool !== 'function') {
    throw new TypeError('MCP bridge is invalid');
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

function readCredential(path, label) {
  if (typeof path !== 'string' || !path) throw new Error(`${label} file is required`);
  try {
    return readFileSync(path);
  } catch {
    throw new Error(`${label} file could not be read`);
  }
}

export async function boot(argv = process.argv, environment = process.env) {
  const args = parseArgs(argv);
  if (args['master-key'] || args['master-key-file'] || environment.MCP_MASTER_KEY) {
    throw new Error('MCP master keys are not supported');
  }
  const apiKey = readCredential(args['api-key-file'], 'Broker API key').toString('utf8').trim();
  if (!API_KEY_RE.test(apiKey)) throw new Error('Broker API key file is invalid');
  const origin = normalizeBrokerOrigin(args.broker || 'https://127.0.0.1:18443');
  const port = Number(args.port || 3001);
  const host = args.host || '127.0.0.1';
  if (!['127.0.0.1', '::1'].includes(host)) throw new Error('MCP must bind to a loopback address');

  const cert = args['client-cert-file']
    ? readCredential(args['client-cert-file'], 'Broker client certificate')
    : undefined;
  const key = args['client-key-file']
    ? readCredential(args['client-key-file'], 'Broker client key')
    : undefined;
  const ca = args['ca-file'] ? readCredential(args['ca-file'], 'Broker CA') : undefined;
  const callBroker = createBrokerClient({ origin, apiKey, cert, key, ca });
  const bridge = createMcpTaskBridge({ callBroker });
  const server = createMcpHttpServer({ bridge, port });
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
