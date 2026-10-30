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
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { BROKER_VERSION } from './version.js';
import { readBody as readBodySafe, send as sendHttp, wrapAsyncRequestHandler } from './lib/http.js';
// v3.0 M4.5: healthcheck 引擎复用 (broker 内核 / mcp-server 外延 同一份)
// 注: 实际会从 broker/healthcheck.js 动态 import (见下面 lazy load)
let _healthcheckModule = null;
async function getHealthcheck() {
  if (!_healthcheckModule) {
    _healthcheckModule = await import('./healthcheck.js');
  }
  return _healthcheckModule;
}

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
const BROKER_URL = (ARGS['broker'] || process.env.BROKER_URL || 'https://127.0.0.1:18443').replace(
  /\/$/,
  '',
);
const PORT = parseInt(ARGS.port || process.env.MCP_PORT || '3001', 10);
const HOST = ARGS.host || process.env.MCP_HOST || '127.0.0.1';
const MCP_AUTH_TOKEN = ARGS['auth-token'] || process.env.MCP_AUTH_TOKEN || '';
const MCP_ALLOW_INSECURE_REMOTE = process.env.MCP_ALLOW_INSECURE_REMOTE === '1';
const MCP_CORS_ORIGINS = String(ARGS['cors-origin'] || process.env.MCP_CORS_ORIGIN || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
function boundedPositiveInt(value, fallback, hardMax) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? Math.min(parsed, hardMax) : fallback;
}
const MCP_MAX_BATCH_SIZE = boundedPositiveInt(process.env.MCP_MAX_BATCH_SIZE, 50, 1_000);
const MCP_MAX_BROKER_RESPONSE_BYTES = boundedPositiveInt(
  process.env.MCP_MAX_BROKER_RESPONSE_BYTES,
  16 * 1024 * 1024,
  64 * 1024 * 1024,
);
const MCP_BROKER_TIMEOUT_MS = boundedPositiveInt(
  process.env.MCP_BROKER_TIMEOUT_MS,
  30_000,
  5 * 60_000,
);
// Master key resolution: --master-key-file (preferred, 永不入 ps) > --master-key / MCP_MASTER_KEY (兼容)
let MASTER_KEY = ARGS['master-key'] || process.env.MCP_MASTER_KEY || '';
if (ARGS['master-key']) {
  console.error(
    '[mcp] WARNING: --master-key is visible in the process list; prefer --master-key-file or MCP_MASTER_KEY',
  );
}
if (ARGS['master-key-file']) {
  try {
    MASTER_KEY = readFileSync(ARGS['master-key-file'], 'utf8').trim();
  } catch (e) {
    console.error(
      `[mcp] ERROR: cannot read --master-key-file ${ARGS['master-key-file']}: ${e.message}`,
    );
    process.exit(1);
  }
}
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const CHILD_NAME = ARGS['child-name'] || process.env.MCP_CHILD_NAME || 'mcp-server-child';

if (!MASTER_KEY) {
  console.error('[mcp] ERROR: --master-key mb_live_xxxx is required');
  process.exit(1);
}
if (!MASTER_KEY.startsWith('mb_')) {
  console.error(
    '[mcp] ERROR: --master-key must be a broker master API key (mb_live_... or mb_test_...)',
  );
  process.exit(1);
}
if (!LOOPBACK_HOSTS.has(HOST) && (!MCP_AUTH_TOKEN || !MCP_ALLOW_INSECURE_REMOTE)) {
  console.error(
    '[mcp] ERROR: non-loopback plain-HTTP binding requires both MCP_AUTH_TOKEN and MCP_ALLOW_INSECURE_REMOTE=1; prefer a loopback bind behind an HTTPS reverse proxy',
  );
  process.exit(1);
}

// ============================================================
// Child key cache + auto-refresh
// ============================================================
const childCache = {
  secret: null,
  key: null,
  expires_at: null,
  refreshTimer: null,
};

async function refreshChildKey() {
  const url = `${BROKER_URL}/api/v1/api-keys/issue-child`;
  const body = JSON.stringify({ name: `${CHILD_NAME}-${Math.floor(Date.now() / 1000)}` });
  const res = await callBrokerRaw(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${MASTER_KEY}`,
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
  childCache.key = j.key ? { ...j.key } : null;
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
    refreshChildKey().catch((e) => {
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
class BrokerResponseTooLargeError extends Error {
  constructor(limit) {
    super(`Broker response exceeded ${limit} bytes`);
    this.name = 'BrokerResponseTooLargeError';
    this.code = 'BROKER_RESPONSE_TOO_LARGE';
  }
}

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
    let settled = false;
    const rejectOnce = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const req = lib(reqOpts, (res) => {
      const advertised = Number(res.headers['content-length']);
      if (Number.isFinite(advertised) && advertised > MCP_MAX_BROKER_RESPONSE_BYTES) {
        res.destroy();
        rejectOnce(new BrokerResponseTooLargeError(MCP_MAX_BROKER_RESPONSE_BYTES));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        if (settled) return;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > MCP_MAX_BROKER_RESPONSE_BYTES) {
          res.destroy();
          rejectOnce(new BrokerResponseTooLargeError(MCP_MAX_BROKER_RESPONSE_BYTES));
          return;
        }
        chunks.push(buffer);
      });
      res.on('error', rejectOnce);
      res.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({ status: res.statusCode, body: Buffer.concat(chunks, size).toString('utf-8') });
      });
    });
    req.setTimeout(MCP_BROKER_TIMEOUT_MS, () => {
      req.destroy(new Error(`Broker request timed out after ${MCP_BROKER_TIMEOUT_MS}ms`));
    });
    req.on('error', rejectOnce);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function callBroker(path, opts = {}) {
  const token = await getChildKey();
  const url = `${BROKER_URL}${path}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    ...(opts.headers || {}),
  };
  if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const res = await callBrokerRaw(url, {
    method: opts.method || 'GET',
    headers,
    body: opts.body,
  });
  let json = null;
  try {
    json = JSON.parse(res.body);
  } catch (_) {
    /* not JSON */
  }
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
    description:
      '返回当前 MCP Server 正在使用的 delegated child API key 公开元信息（不枚举同账号其他 Key，不返回 secret）。',
    inputSchema: { type: 'object', properties: {} },
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
  {
    // v3.0 M4.5: 走 mcp-server 出网验单个 secret 凭据 (broker 自身不出网, 委托 mcp-server)
    name: 'check_credential',
    description:
      '验单个 secret 凭据是否仍有效 (调上游 no-side-effect API). 凭据零接触: 返 status/detail/latency, 不返 value.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string', description: 'secret name' } },
      required: ['name'],
    },
  },
  {
    // v3.0 M4.5: 跑全部 4 secrets healthcheck, 返 {name: {status, detail, latency_ms, type, ts}}
    name: 'run_healthcheck',
    description:
      '跑全部 secret 凭据自检 (mcp-server 出网, 凭据零接触). 返 summary + 每 secret status.',
    inputSchema: { type: 'object', properties: {} },
  },
];

async function toolListSecrets() {
  const r = await callBroker('/api/v1/secrets');
  if (r.status !== 200) throw new Error(`list_secrets failed: ${r.status} ${r.body.slice(0, 200)}`);
  const items = r.json?.secrets || [];
  const names = items.map((s) => s.name || s).filter(Boolean);
  return { names, count: names.length, _items: items };
}

async function toolDescribeSecret(args) {
  if (!args?.name) throw new Error('Missing {name}');
  // broker 端没有 GET /api/v1/secrets/:name 元信息端点, 走 POST /api/v1/secrets/resolve
  // 拿完整 secret 然后剥掉 value 字段 (凭据零接触: value 永不入 MCP 响应)
  const r = await callBroker('/api/v1/secrets/resolve', {
    method: 'POST',
    body: JSON.stringify({ name: args.name }),
  });
  if (r.status === 404 || r.status === 403) return { found: false, name: args.name };
  if (r.status !== 200) {
    throw new Error(`describe_secret failed: ${r.status} ${r.body.slice(0, 200)}`);
  }
  const item = r.json || {};
  // ⚠️ 凭据零接触: 显式 redact 所有可能的 value 字段
  return {
    found: true,
    name: item.name,
    type: item.type,
    description: item.description,
    has_value: !!(item.value || (item.fields && Object.keys(item.fields).length > 0)),
    // 不返 value / fields / token 等任何密钥字段
  };
}

async function toolCallService(args) {
  if (!args?.service || !args?.method || !args?.path) {
    throw new Error('Missing {service, method, path}');
  }
  // broker 端 proxy 路径是 /api/v1/proxy/:name (不是 /api/v1/services/:name/proxy)
  const r = await callBroker(`/api/v1/proxy/${encodeURIComponent(args.service)}`, {
    method: 'POST',
    body: JSON.stringify({
      method: args.method,
      path: args.path,
      query: args.query || {},
      body: args.body || null,
    }),
  });
  return { status: r.status, body: r.body, json: r.json };
}

async function toolGetHealth() {
  const r = await callBroker('/health');
  return { status: r.status, broker_response: r.json || r.body };
}

async function toolListApiKeys() {
  const key = childCache.key;
  if (!key) return { count: 0, keys: [] };
  const safe = {
    id: key.id || null,
    name: key.name || CHILD_NAME,
    client: key.client || null,
    scopes: Array.isArray(key.scopes) ? key.scopes : [],
    allowed_secrets: Array.isArray(key.allowed_secrets) ? key.allowed_secrets : [],
    allowed_services: Array.isArray(key.allowed_services) ? key.allowed_services : [],
    expires_at: key.expires_at || childCache.expires_at?.toISOString() || null,
    parent_master_id: key.parent_master_id || null,
    is_master: false,
    delegated: true,
  };
  return { count: 1, keys: [safe] };
}

async function toolGetAudit(args) {
  const limit = Math.min(parseInt(args?.limit || 50, 10), 200);
  const since = args?.since ? `&since=${encodeURIComponent(args.since)}` : '';
  const r = await callBroker(`/api/v1/me/audit?limit=${limit}${since}`);
  if (r.status !== 200) throw new Error(`get_audit failed: ${r.status} ${r.body.slice(0, 200)}`);
  return r.json || { events: [] };
}

// v3.0 M4.5: 验单个 secret 凭据 (mcp-server 走 client.mavis cert 出网)
// 凭据零接触: 内部调 broker resolve 拿 value, 调 healthcheck.checkSecret 拿结果,
// 返回的只有 status/detail/latency/type, 绝不返 secret value.
async function toolCheckCredential(args) {
  if (!args?.name) throw new Error('Missing {name}');
  const r = await callBroker('/api/v1/secrets/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: args.name }),
  });
  if (r.status !== 200) throw new Error(`resolve failed: ${r.status} ${r.body.slice(0, 200)}`);
  const data = r.json;
  if (!data?.type) throw new Error('resolve returned no type');
  const { checkSecret } = await getHealthcheck();
  // fields 是 broker 返回的结构化凭据. healthcheck.checkSecret 内部按 type-schemas 抽字段.
  const result = await checkSecret(args.name, data.fields || {}, data.type);
  // 凭据零接触: 不返 data.value / data.fields, 只返 status 元信息
  return { name: args.name, type: data.type, ...result };
}

// v3.0 M4.5 + v3.1 M5.3: 跑全部 secret healthcheck (loop 调 check_credential + 累加 5 维 summary)
async function toolRunHealthcheck(_args) {
  const list = await callBroker('/api/v1/secrets');
  if (list.status !== 200) throw new Error(`list_secrets failed: ${list.status}`);
  const items = list.json?.secrets || [];
  const checks = {};
  // v3.1 M5.3: 5 维 status 兜底 (M4 4 维 + unreachable / misconfigured)
  const summary = {
    ok: 0,
    expired: 0,
    unreachable: 0,
    misconfigured: 0,
    fail: 0,
    skipped: 0,
    total: 0,
  };
  const t0 = Date.now();
  for (const s of items) {
    const name = typeof s === 'string' ? s : s.name;
    if (!name) continue;
    try {
      const r = await toolCheckCredential({ name });
      checks[name] = { ...r, ts: new Date().toISOString() };
      summary[r.status] = (summary[r.status] || 0) + 1;
    } catch (e) {
      // toolCheckCredential 内部已用 classifyError, 这里 catch 兜底网络/解析错误 → fail
      checks[name] = { status: 'fail', detail: e.message, ts: new Date().toISOString() };
      summary.fail++;
    }
    summary.total++;
  }
  // v3.1 M5.3: last_status 计算看 4 个非 ok 维度 (M4 只看 expired/fail)
  const allPass =
    summary.expired === 0 &&
    summary.unreachable === 0 &&
    summary.misconfigured === 0 &&
    summary.fail === 0;
  return {
    last_status: allPass ? 'ok' : 'degraded',
    last_run_at: new Date().toISOString(),
    duration_ms: Date.now() - t0,
    summary,
    checks,
  };
}

const TOOL_HANDLERS = {
  list_secrets: toolListSecrets,
  describe_secret: toolDescribeSecret,
  call_service: toolCallService,
  get_health: toolGetHealth,
  list_api_keys: toolListApiKeys,
  get_audit: toolGetAudit,
  check_credential: toolCheckCredential,
  run_healthcheck: toolRunHealthcheck,
};

// ============================================================
// JSON-RPC 2.0
// ============================================================
const SERVER_INFO = {
  name: 'secret-broker-mcp-server',
  version: BROKER_VERSION,
  protocolVersion: '2025-06-18',
};

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}
function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

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
    console.error(`[mcp] tool ${name} failed: ${e?.message || String(e)}`);
    return jsonRpcResult(req.id, {
      content: [{ type: 'text', text: 'Tool execution failed' }],
      isError: true,
    });
  }
}
async function handleRpcPing(req) {
  return jsonRpcResult(req.id, {});
}

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
function tokenMatches(candidate, expected) {
  if (!candidate || !expected) return false;
  const a = createHash('sha256').update(String(candidate)).digest();
  const b = createHash('sha256').update(String(expected)).digest();
  return timingSafeEqual(a, b);
}

function rpcAuthorized(req) {
  if (!MCP_AUTH_TOKEN) return true;
  const match = /^Bearer\s+(\S+)$/.exec(String(req.headers.authorization || ''));
  return !!match && tokenMatches(match[1], MCP_AUTH_TOKEN);
}

function applyCorsPolicy(req, res) {
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true; // native MCP clients do not send Origin
  if (!MCP_CORS_ORIGINS.includes(origin)) return false;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return true;
}

function send(res, status, body, extraHeaders = {}) {
  return sendHttp(res, status, body, {
    noSecurityHeaders: true,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders,
  });
}

const httpServer = createHttpServer(
  wrapAsyncRequestHandler(
    async (req, res) => {
      if (!applyCorsPolicy(req, res)) {
        return send(res, 403, { error: 'Browser origin is not allowed' });
      }
      if (req.method === 'OPTIONS') {
        return send(res, 204, '');
      }

      if (req.method === 'GET' && req.url === '/health') {
        return send(res, 200, { ok: true });
      }

      if (req.method === 'POST' && (req.url === '/' || req.url === '/mcp')) {
        if (!rpcAuthorized(req)) return send(res, 401, { error: 'Unauthorized' });
        const req2 = await readBodySafe(req);
        if (
          req2 === null ||
          (req2 &&
            typeof req2 === 'object' &&
            !Array.isArray(req2) &&
            Object.keys(req2).length === 1 &&
            typeof req2._raw === 'string')
        ) {
          return send(res, 400, jsonRpcError(null, -32700, 'Parse error'));
        }

        if (Array.isArray(req2)) {
          if (req2.length === 0) {
            return send(res, 400, jsonRpcError(null, -32600, 'Empty JSON-RPC batch'));
          }
          if (req2.length > MCP_MAX_BATCH_SIZE) {
            return send(
              res,
              400,
              jsonRpcError(null, -32600, `JSON-RPC batch exceeds ${MCP_MAX_BATCH_SIZE} items`),
            );
          }
          const results = await Promise.all(req2.map((request) => handleOne(request)));
          const filtered = results.filter(Boolean);
          if (filtered.length === 0) return send(res, 204, '');
          return send(res, 200, filtered);
        }
        const r = await handleOne(req2);
        if (r === null) return send(res, 204, '');
        return send(res, 200, r);
      }

      return send(res, 404, { error: 'Not found' });
    },
    {
      errorResponder: (res, status, message) => send(res, status, { error: message }),
      onError: (err) => console.error(`[mcp] request error: ${err?.message || String(err)}`),
    },
  ),
);

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
  console.error(
    `[mcp] master key: <loaded from ${ARGS['master-key-file'] || 'env/CLI'}, length=${MASTER_KEY.length}> (凭据零接触: secret 永不入日志)`,
  );
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

process.on('SIGTERM', () => {
  console.error('[mcp] SIGTERM, exit');
  process.exit(0);
});
process.on('SIGINT', () => {
  console.error('[mcp] SIGINT, exit');
  process.exit(0);
});

boot().catch((e) => {
  console.error(`[mcp] boot failed: ${e.message}`);
  process.exit(1);
});
