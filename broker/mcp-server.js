// broker/mcp-server.js — v3.0 M3.3 MCP Server
// HTTP + JSON-RPC 2.0 (MCP spec >= 2025-06-18)
// Auto-refresh child API key with master key
//
// 启动:
//   node mcp-server.js --broker https://broker.52trz.com:8443 \
//       --master-key mb_live_xxxx --port 3001
//
// 鉴权:
//   - master key 启动时从 CLI 传入 (不入磁盘, 不入日志)
//   - 内部 cache child key (1h TTL), 过期前 5min auto-refresh
//   - 所有 broker 调用带 Authorization: Bearer <child_key>
//
// 安全:
//   - master key 仅用于 issue-child (scope 限定, 不能直接 resolve secrets)
//   - child key 自动用 master.child_scopes, 不会越权
//   - 所有 MCP 调用 100% 进 broker audit
//   - 工具调用结果不含密钥明文 (call_service 返回上游响应, 不是 GITHUB_PAT)

import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

// ============================================================
// CLI args
// ============================================================
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      args[k] = v;
    }
  }
  return args;
}
const ARGS = parseArgs(process.argv);
const BROKER_URL = (ARGS['broker'] || process.env.BROKER_URL || 'https://127.0.0.1:18443').replace(/\/$/, '');
const PORT = parseInt(ARGS.port || process.env.MCP_PORT || '3001', 10);
const HOST = ARGS.host || process.env.MCP_HOST || '127.0.0.1';
const MASTER_KEY = ARGS['master-key'] || process.env.MCP_MASTER_KEY || '';
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const CHILD_NAME = ARGS['child-name'] || process.env.MCP_CHILD_NAME || 'mcp-server-child';

if (!MASTER_KEY) {
  console.error('[mcp] ERROR: --master-key mb_live_xxxx is required');
  process.exit(1);
}
if (!MASTER_KEY.startsWith('mb_')) {
  console.error('[mcp] ERROR: --master-key must be a broker master API key (mb_live_... or mb_test_...)');
  process.exit(1);
}

// ============================================================
// Child key cache + auto-refresh
// ============================================================
let childCache = {
  secret: null,
  expires_at: null,
  refreshTimer: null,
};

async function refreshChildKey() {
  const url = `${BROKER_URL}/api/v1/api-keys/issue-child`;
  const body = JSON.stringify({ name: `${CHILD_NAME}-${Math.floor(Date.now() / 1000)}` });
  const res = await callBrokerRaw(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${MASTER_KEY}`,
      'Content-Type': 'application/json',
    },
    body,
  });
  if (res.status !== 200) {
    throw new Error(`issue-child failed: ${res.status} ${res.body.slice(0, 200)}`);
  }
  const j = JSON.parse(res.body);
  if (!j.ok || !j.secret) throw new Error(`issue-child bad response: ${res.body.slice(0, 200)}`);
  const expiresAt = new Date(j.key.expires_at);
  childCache.secret = j.secret;
  childCache.expires_at = expiresAt;
  scheduleNextRefresh();
  console.error(`[mcp] child key refreshed, expires ${expiresAt.toISOString()}`);
  return j.secret;
}

function scheduleNextRefresh() {
  if (childCache.refreshTimer) clearTimeout(childCache.refreshTimer);
  if (!childCache.expires_at) return;
  const delay = childCache.expires_at.getTime() - Date.now() - REFRESH_MARGIN_MS;
  const safeDelay = Math.max(delay, 30_000);
  childCache.refreshTimer = setTimeout(() => {
    refreshChildKey().catch(e => {
      console.error(`[mcp] refresh failed: ${e.message}, retry in 30s`);
      childCache.refreshTimer = setTimeout(refreshChildKey, 30_000);
    });
  }, safeDelay);
}

async function getChildKey() {
  if (!childCache.secret || !childCache.expires_at) {
    return await refreshChildKey();
  }
  if (childCache.expires_at.getTime() - Date.now() < 60_000) {
    return await refreshChildKey();
  }
  return childCache.secret;
}

// ============================================================
// HTTP client → broker
// ============================================================
function callBrokerRaw(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? httpsRequest : httpRequest;
    const reqOpts = {
      method: opts.method || 'GET',
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers: opts.headers || {},
      rejectUnauthorized: process.env.MCP_INSECURE_TLS === '1' ? false : true,
    };
    const req = lib(reqOpts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf-8') }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function callBroker(path, opts = {}) {
  const token = await getChildKey();
  const url = `${BROKER_URL}${path}`;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
    ...(opts.headers || {}),
  };
  if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const res = await callBrokerRaw(url, {
    method: opts.method || 'GET',
    headers,
    body: opts.body,
  });
  let json = null;
  try { json = JSON.parse(res.body); } catch (_) { /* not JSON */ }
  return { status: res.status, body: res.body, json };
}

// ============================================================
// MCP tools
// ============================================================
const TOOLS = [
  {
    name: 'list_secrets',
    description: '列出当前 client 可访问的 secret 名字（不返回值）。返回 JSON 数组。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'describe_secret',
    description: '查看某个 secret 的元信息（name/type/description/last_used），不返回 secret 值。',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string', description: 'secret 名称' } },
      required: ['name'],
    },
  },
  {
    name: 'call_service',
    description: '调外部服务（e.g. GitHub API）。Agent 拿到的是服务响应（JSON），不是密钥。',
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: '服务名 (e.g. github, aliyun_ecs)' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
        path: { type: 'string' },
        query: { type: 'object', additionalProperties: { type: 'string' } },
        body: { type: 'object' },
      },
      required: ['service', 'method', 'path'],
    },
  },
  {
    name: 'get_health',
    description: 'broker 健康度 + uptime。',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_api_keys',
    description: '列出当前 client 自己的 API Keys。',
    inputSchema: {
      type: 'object',
      properties: { include_master: { type: 'boolean', default: false } },
    },
  },
  {
    name: 'get_audit',
    description: '查询 broker audit log（默认 50 条）。',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', default: 50 },
        since: { type: 'string' },
      },
    },
  },
];

async function toolListSecrets() {
  const r = await callBroker('/api/v1/secrets');
  if (r.status !== 200) throw new Error(`list_secrets failed: ${r.status} ${r.body.slice(0, 200)}`);
  const items = r.json?.secrets || [];
  const names = items.map(s => s.name || s).filter(Boolean);
  return { names, count: names.length, _items: items };
}

async function toolDescribeSecret(args) {
  if (!args?.name) throw new Error('Missing {name}');
  const r = await callBroker(`/api/v1/secrets/${encodeURIComponent(args.name)}`);
  if (r.status === 404) return { found: false, name: args.name };
  if (r.status !== 200) throw new Error(`describe_secret failed: ${r.status} ${r.body.slice(0, 200)}`);
  const item = r.json?.secret || r.json || {};
  return { name: item.name, type: item.type, description: item.description, has_value: !!item.value };
}

async function toolCallService(args) {
  if (!args?.service || !args?.method || !args?.path) throw new Error('Missing {service, method, path}');
  const r = await callBroker(`/api/v1/services/${encodeURIComponent(args.service)}/proxy`, {
    method: 'POST',
    body: JSON.stringify({ method: args.method, path: args.path, query: args.query || {}, body: args.body || null }),
  });
  return { status: r.status, body: r.body, json: r.json };
}

async function toolGetHealth() {
  const r = await callBroker('/health');
  return { status: r.status, broker_response: r.json || r.body };
}

async function toolListApiKeys(args) {
  const r = await callBroker('/api/v1/api-keys');
  if (r.status !== 200) throw new Error(`list_api_keys failed: ${r.status} ${r.body.slice(0, 200)}`);
  let keys = r.json?.keys || [];
  if (!args?.include_master) keys = keys.filter(k => !k.is_master);
  return { count: keys.length, keys };
}

async function toolGetAudit(args) {
  const limit = Math.min(parseInt(args?.limit || 50, 10), 200);
  const since = args?.since ? `&since=${encodeURIComponent(args.since)}` : '';
  const r = await callBroker(`/api/v1/audit?limit=${limit}${since}`);
  if (r.status !== 200) throw new Error(`get_audit failed: ${r.status} ${r.body.slice(0, 200)}`);
  return r.json || { events: [] };
}

const TOOL_HANDLERS = {
  list_secrets: toolListSecrets,
  describe_secret: toolDescribeSecret,
  call_service: toolCallService,
  get_health: toolGetHealth,
  list_api_keys: toolListApiKeys,
  get_audit: toolGetAudit,
};

// ============================================================
// JSON-RPC 2.0
// ============================================================
const SERVER_INFO = {
  name: 'secret-broker-mcp-server',
  version: '3.0.0',
  protocolVersion: '2025-06-18',
};

function jsonRpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function jsonRpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

async function handleRpcInit(req) {
  return jsonRpcResult(req.id, {
    protocolVersion: SERVER_INFO.protocolVersion,
    serverInfo: { name: SERVER_INFO.name, version: SERVER_INFO.version },
    capabilities: { tools: {} },
  });
}
async function handleRpcListTools(req) {
  return jsonRpcResult(req.id, { tools: TOOLS });
}
async function handleRpcCallTool(req) {
  const name = req.params?.name;
  const args = req.params?.arguments || {};
  const handler = TOOL_HANDLERS[name];
  if (!handler) return jsonRpcError(req.id, -32601, `Unknown tool: ${name}`);
  try {
    const data = await handler(args);
    return jsonRpcResult(req.id, {
      content: [{ type: 'text', text: JSON.stringify(data) }],
      isError: false,
    });
  } catch (e) {
    return jsonRpcResult(req.id, {
      content: [{ type: 'text', text: `Error: ${e.message}` }],
      isError: true,
    });
  }
}
async function handleRpcPing(req) { return jsonRpcResult(req.id, {}); }

const RPC_HANDLERS = {
  initialize: handleRpcInit,
  'notifications/initialized': () => null,
  'tools/list': handleRpcListTools,
  'tools/call': handleRpcCallTool,
  ping: handleRpcPing,
};

// ============================================================
// HTTP server
// ============================================================
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', () => resolve(''));
  });
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const httpServer = createHttpServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (req.method === 'GET' && req.url === '/health') {
    return send(res, 200, {
      ok: true, server: SERVER_INFO.name, version: SERVER_INFO.version,
      protocol: SERVER_INFO.protocolVersion,
      child_key_expires_at: childCache.expires_at?.toISOString() || null,
      tools: TOOLS.map(t => t.name),
    });
  }

  if (req.method === 'POST' && (req.url === '/' || req.url === '/mcp')) {
    const raw = await readBody(req);
    let req2;
    try { req2 = JSON.parse(raw); }
    catch (e) { return send(res, 400, jsonRpcError(null, -32700, 'Parse error: ' + e.message)); }

    if (Array.isArray(req2)) {
      const results = await Promise.all(req2.map(r => handleOne(r)));
      const filtered = results.filter(Boolean);
      if (filtered.length === 0) return send(res, 204, '');
      return send(res, 200, filtered);
    }
    const r = await handleOne(req2);
    if (r === null) return send(res, 204, '');
    return send(res, 200, r);
  }

  return send(res, 404, { error: 'Not found' });
});

async function handleOne(req2) {
  if (!req2 || req2.jsonrpc !== '2.0' || !req2.method) {
    return jsonRpcError(req2?.id ?? null, -32600, 'Invalid JSON-RPC 2.0 request');
  }
  const handler = RPC_HANDLERS[req2.method];
  if (!handler) return jsonRpcError(req2.id, -32601, `Method not found: ${req2.method}`);
  return await handler(req2);
}

// ============================================================
// Boot
// ============================================================
async function boot() {
  console.error(`[mcp] starting ${SERVER_INFO.name} v${SERVER_INFO.version}`);
  console.error(`[mcp] broker: ${BROKER_URL}`);
  console.error(`[mcp] listen: http://${HOST}:${PORT}/`);
  console.error(`[mcp] master key: ${MASTER_KEY.slice(0, 12)}...${MASTER_KEY.slice(-4)} (length=${MASTER_KEY.length})`);
  try {
    await refreshChildKey();
  } catch (e) {
    console.error(`[mcp] FATAL: initial refresh failed: ${e.message}`);
    console.error(`[mcp] (1) Check master key is valid`);
    console.error(`[mcp] (2) Check broker URL reachable: ${BROKER_URL}/health`);
    process.exit(1);
  }
  httpServer.listen(PORT, HOST, () => {
    console.error(`[mcp] ready — POST JSON-RPC 2.0 to http://${HOST}:${PORT}/`);
  });
}

process.on('SIGTERM', () => { console.error('[mcp] SIGTERM, exit'); process.exit(0); });
process.on('SIGINT', () => { console.error('[mcp] SIGINT, exit'); process.exit(0); });

boot().catch(e => { console.error(`[mcp] boot failed: ${e.message}`); process.exit(1); });
