// broker/healthcheck.js — v3.0 M4 + v3.1 M5.3 + v3.1.1 M5.6 凭据自检引擎
// 每日 04:00 cron 触发 (broker/cron-tasks.js)
// 对每个 secret: dry_run = true, 调上游 no-side-effect API, 验凭据
// 失败: 写 audit + 推 SSE + dashboard 红色 stat
//
// 设计:
// - secret.type → 抽 fields (按 type-schemas 字段名)
// - 结果写 broker/audit/audit-<date>.jsonl (action: 'healthcheck', status: 'ok'|'expired'|'unreachable'|'misconfigured'|'fail'|'skipped')
// - 同时推 HEALTHCHECK_BUS (EventEmitter): 'run_complete' + 'status_change' (M5.6)
// - 持久化最新状态到 secrets/healthcheck-state.json (writable; secrets/ 在 ReadWritePaths 里)
// - M5.6: 状态变化持久化到 secrets/alert-history.jsonl (jsonl append-only, last 1000 entries)
//
// v3.1 M5.3 状态 5 维 (M4 4 维 + 新 2):
//   ok             业务验证通过 (凭据对, 上游服务正常)
//   expired        401/403 真凭据问题 (用户需要轮换)
//   unreachable    基础设施不可达 (DNS fail / ECONNRESET / IP 段被风控 — 用户改不了 ECS IP)
//   misconfigured  配置错 (缺字段 / ssh target 不可达 / 端口错 — 用户要改 broker.yaml)
//   fail           兜底 (其它未知错误)
//   skipped        type 不支持 / 无凭据 (don't fail healthcheck just because we don't have a check)
//
// 不在 v3.0 范围: SMS / Email / Webhook 外发 (留 v3.1), 凭据零接触
//
// 烟雾测试 (no-side-effect):
// - github_pat:   GET https://api.github.com/user
// - aliyun_ak:    https://ecs.aliyuncs.com/?Action=DescribeRegions
// - openai_key:   GET https://api.openai.com/v1/models
// - ssh_connection: TCP connect <host>:<port> (用 net.Socket, 不开 shell)
// - 其他 type: 返回 status='skipped' (don't fail healthcheck just because we don't have a check)

import { request as httpsRequest } from 'node:https';
import { connect as netConnect } from 'node:net';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { createHmac, createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Config
// ============================================================
// STATE_PATH: 必须放在 systemd 写得到的目录. broker/ 是 ReadOnlyPaths
// 默认放 /opt/secret-broker/secrets/healthcheck-state.json (ReadWritePaths)
// 也可用 env 覆盖. 每次 load/save 重新读 env, 方便测试动态切换
function resolveStatePath() {
  return process.env.HEALTHCHECK_STATE_PATH
    || join(__dirname, '..', 'secrets', 'healthcheck-state.json');
}

const TIMEOUT_MS = 10_000;
const MAX_STATE_AGE_MS = 7 * 24 * 60 * 60 * 1000;  // 7 days

// ============================================================
// Event bus (server.js 已有 ALERT_BUS, 这里 emit 后 server.js bridge)
// ============================================================
export const HEALTHCHECK_BUS = new EventEmitter();
HEALTHCHECK_BUS.setMaxListeners(0);

// ============================================================
// 状态持久化 (broker 进程间共享)
// ============================================================
let state = { last_run_at: null, last_status: 'unknown', checks: {} };

function loadState() {
  const p = resolveStatePath();
  if (existsSync(p)) {
    try { state = JSON.parse(readFileSync(p, 'utf-8')); } catch { /* ignore */ }
  }
  return state;
}

function saveState() {
  try {
    writeFileSync(resolveStatePath(), JSON.stringify(state, null, 2));
  } catch (e) {
    console.error('[healthcheck] state save failed:', e.message);
  }
}

// ============================================================
// v3.1.1 M5.6: alert_history 持久化 (jsonl append-only, last 1000 entries)
// 每次 healthcheck 跑完, 比较老 vs 新 status, 有变化则写一条
// 也用于 SSE 推 status_change 事件 (M5.6 dashboard 实时告警)
// ============================================================
function resolveAlertHistoryPath() {
  return process.env.ALERT_HISTORY_PATH
    || join(__dirname, '..', 'secrets', 'alert-history.jsonl');
}

const ALERT_HISTORY_MAX = 1000;
let alertHistory = [];       // 内存 [{ ts, summary, changes: { name: { from, to, ts } } }]
let lastChecks = {};         // name -> status (上次 run 后的状态, 启动时从 alert_history load)

function loadAlertHistory() {
  const p = resolveAlertHistoryPath();
  if (existsSync(p)) {
    try {
      const lines = readFileSync(p, 'utf-8').split('\n').filter(Boolean);
      alertHistory = lines.map(l => JSON.parse(l));
      // 同步 lastChecks 为最新一条的状态 (last entry wins)
      for (const entry of alertHistory) {
        for (const [name, change] of Object.entries(entry.changes || {})) {
          lastChecks[name] = change.to;
        }
      }
    } catch (e) {
      console.error('[healthcheck] alert_history load failed:', e.message);
    }
  }
  return alertHistory;
}

function saveAlertHistory() {
  // trim to last ALERT_HISTORY_MAX entries
  if (alertHistory.length > ALERT_HISTORY_MAX) {
    alertHistory = alertHistory.slice(-ALERT_HISTORY_MAX);
  }
  try {
    const lines = alertHistory.map(e => JSON.stringify(e)).join('\n') + '\n';
    writeFileSync(resolveAlertHistoryPath(), lines);
  } catch (e) {
    console.error('[healthcheck] alert_history save failed:', e.message);
  }
}

// 检测状态变化, 返 { changes: { name: { from, to, ts } } }, 并同步 lastChecks
function detectChanges(currentChecks) {
  const changes = {};
  for (const [name, c] of Object.entries(currentChecks)) {
    const prevStatus = lastChecks[name];
    const newStatus = c.status;
    if (prevStatus !== newStatus) {
      changes[name] = { from: prevStatus || 'unknown', to: newStatus, ts: c.ts || new Date().toISOString() };
      lastChecks[name] = newStatus;
    }
  }
  // 也检测消失的 secret (在 lastChecks 但没在 currentChecks)
  for (const name of Object.keys(lastChecks)) {
    if (!currentChecks[name]) {
      changes[name] = { from: lastChecks[name], to: 'removed', ts: new Date().toISOString() };
      delete lastChecks[name];
    }
  }
  return changes;
}

// 暴露给测试 / 外部清状态
// 清: 内存 lastChecks + alertHistory + 文件 (alert-history.jsonl)
export function clearLastChecks() {
  lastChecks = {};
  alertHistory = [];
  try {
    const p = resolveAlertHistoryPath();
    if (existsSync(p)) {
      try { unlinkSync(p); } catch (e) {
        console.error('[healthcheck] clearLastChecks unlink failed:', e.message, 'path=', p);
      }
    }
  } catch (e) {
    console.error('[healthcheck] clearLastChecks resolvePath failed:', e.message);
  }
}

// ============================================================
// 字段抽取: 从 entry.fields 按 type 拿对应的"凭据值"
// 约定: 每个 type 有 1 个"主凭据字段" (token / api_key / value / access_key_id / private_key / ...)
// 返: { primary: <主值>, meta: <其它上下文如 host> } 或 null
// ============================================================
function pickCredential(type, fields) {
  if (!fields || typeof fields !== 'object') return null;
  switch (type) {
    case 'github_pat':
    case 'gitlab_pat':
    case 'gitee_pat':
      return { primary: fields.token, meta: {} };
    case 'openai_key':
    case 'anthropic_key':
    case 'google_ai_key':
    case 'mistral_key':
    case 'cohere_key':
    case 'deepseek_key':
      return { primary: fields.api_key, meta: {} };
    case 'aliyun_ak':
      return {
        primary: fields.access_key_id,
        meta: { access_key_secret: fields.access_key_secret, region: fields.region || 'cn-hangzhou' }
      };
    case 'tencent_sk':
      return {
        primary: fields.secret_id,
        meta: { secret_key: fields.secret_key, region: fields.region || 'ap-guangzhou' }
      };
    case 'aws_access_key':
      return {
        primary: fields.access_key_id,
        meta: { secret_access_key: fields.secret_access_key, region: fields.region || 'us-east-1' }
      };
    case 'ssh_connection':
      // healthcheck 只测 TCP 可达性, 不需要凭据值. 但 meta.host 是关键.
      // 完全空 (无 host 无 private_key 无 password) → 没东西可验 → null
      if (!fields.host && !fields.private_key && !fields.password) return null;
      return {
        primary: fields.private_key || fields.password || 'tcp-only',
        meta: { host: fields.host, port: fields.port || 22, user: fields.username, auth: fields.auth_method }
      };
    case 'ssh_private_key':
      return { primary: fields.key, meta: { auth: 'private_key' } };
    case 'cloudflare_token':
      return { primary: fields.api_token, meta: { account_id: fields.account_id } };
    case 'custom':
    default:
      // 兜底: 找第一个非空 string 字段
      for (const [k, v] of Object.entries(fields)) {
        if (typeof v === 'string' && v.length > 0) return { primary: v, meta: { field: k } };
      }
      return null;
  }
}

// ============================================================
// v3.1 M5.3: classifyError — 把网络/系统错误分类成 5 维 status 之一
// 返 { status, detail } (不含 latency_ms, 调用方自己加)
//
// unreachable (基础设施层, 用户改不了 ECS):
//   - ENOTFOUND / EAI_AGAIN / EAI_FAIL  → DNS 解析失败
//   - ECONNRESET                         → TCP 远端主动 RST (OpenAI 拒阿里云 IP 段典型表现)
//   - EHOSTUNREACH / ENETUNREACH         → 路由层不可达
//   - SSL_connect Connection reset       → TLS 层 RST
//
// misconfigured (配置错, 用户要改 broker.yaml 或 secrets/*.yaml):
//   - ECONNREFUSED                       → 端口没开 / ssh target 错
//   - ETIMEDOUT                          → TCP connect 远端不响应 (ssh target 错 / 防火墙 drop)
//   - "timeout after Xms"                → net.Socket 自身 timeout
//
// fail (兜底, 其它未知错误):
//   - 其它 code / message
// ============================================================
export function classifyError(e) {
  const code = e?.code || '';
  const msg = String(e?.message || '');

  // unreachable: 基础设施层
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_FAIL') {
    return { status: 'unreachable', detail: `DNS fail (${code}): ${msg.slice(0, 80)}` };
  }
  if (code === 'ECONNRESET') {
    return { status: 'unreachable', detail: `connection reset by peer (${code}) — service may block this IP range` };
  }
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return { status: 'unreachable', detail: `network unreachable (${code})` };
  }
  if (/SSL_connect.*Connection reset/i.test(msg) || /read ECONNRESET/i.test(msg)) {
    return { status: 'unreachable', detail: msg.slice(0, 100) };
  }

  // misconfigured: 配置错
  if (code === 'ECONNREFUSED') {
    return { status: 'misconfigured', detail: `connection refused (port may be closed or target wrong): ${msg.slice(0, 80)}` };
  }
  if (code === 'ETIMEDOUT') {
    return { status: 'misconfigured', detail: `connect timeout — target may be unreachable or behind firewall: ${msg.slice(0, 80)}` };
  }
  if (/timeout after \d+ms/i.test(msg)) {
    return { status: 'misconfigured', detail: msg.slice(0, 100) };
  }

  // 兜底
  return { status: 'fail', detail: msg.slice(0, 200) || `unknown error (code=${code || 'none'})` };
}

// ============================================================
// 单个 secret 检查
// signature: checkSecret(name, fields, type) → {status, detail, latency_ms}
// 公开 export 供 mcp-server 等外部进程复用 (无需 broker SECRET_CACHE)
// ============================================================
export async function checkSecret(secretName, fields, secretType) {
  const t0 = Date.now();
  const cred = pickCredential(secretType, fields);
  if (!cred || !cred.primary) {
    // pickCredential 返 null: type 不支持 或 fields 全空 (无任何凭据值)
    // 这是 "没有可检查的东西", 不是配置错. 保持 skipped
    return { status: 'skipped', detail: `no extractable credential for type=${secretType}`, latency_ms: 0 };
  }
  try {
    switch (secretType) {
      case 'github_pat':
      case 'gitlab_pat':
      case 'gitee_pat':
        return await checkGithubLike(cred.primary, secretType, t0);
      case 'aliyun_ak':
        return await checkAliyun(cred.primary, cred.meta, t0);
      case 'tencent_sk':
        return await checkTencent(cred.primary, cred.meta, t0);
      case 'aws_access_key':
        return await checkAws(cred.primary, cred.meta, t0);
      case 'openai_key':
      case 'anthropic_key':
      case 'google_ai_key':
      case 'mistral_key':
      case 'cohere_key':
      case 'deepseek_key':
        return await checkOpenAI(cred.primary, t0);
      case 'ssh_connection':
        return await checkSsh(cred.meta, t0);
      case 'cloudflare_token':
        return await checkCloudflare(cred.primary, t0);
      case 'ssh_private_key':
        // ssh_private_key 是 bare 凭据 (无 host), 需要 wrap 成 ssh_connection 才能验.
        // 如果用户只配 ssh_private_key 没配 ssh_connection, 是配置错不是 skipped.
        return { status: 'misconfigured', detail: 'ssh_private_key (bare) needs ssh_connection host/port wrapper', latency_ms: 0 };
      default:
        // type 不在支持列表, 不要假装能查. skipped.
        return { status: 'skipped', detail: 'no check for type=' + secretType, latency_ms: 0 };
    }
  } catch (e) {
    return { ...classifyError(e), latency_ms: Date.now() - t0 };
  }
}

function checkGithubLike(token, type, t0) {
  // github / gitlab.com / gitee 都接受 token 鉴权的 /user 端点
  const hostMap = { github_pat: 'api.github.com', gitlab_pat: 'gitlab.com', gitee_pat: 'gitee.com' };
  const pathMap = { github_pat: '/user', gitlab_pat: '/api/v4/user', gitee_pat: '/api/v5/user' };
  const headerMap = {
    github_pat: { 'Authorization': `token ${token}`, 'User-Agent': 'secret-broker-healthcheck' },
    gitlab_pat: { 'PRIVATE-TOKEN': token },
    gitee_pat:  { 'Authorization': `token ${token}` },
  };
  const host = hostMap[type] || 'api.github.com';
  const path = pathMap[type] || '/user';
  const headers = headerMap[type] || { 'Authorization': `token ${token}` };
  return new Promise((resolve) => {
    const req = httpsRequest({ host, port: 443, path, method: 'GET', headers, timeout: TIMEOUT_MS }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          let id = null;
          try { id = JSON.parse(d).login || JSON.parse(d).username || JSON.parse(d).name; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `user=${id || '?'}`, latency_ms: latency });
        } else if (res.statusCode === 401) {
          resolve({ status: 'expired', detail: '401 Bad credentials', latency_ms: latency });
        } else if (res.statusCode === 403) {
          resolve({ status: 'expired', detail: '403 Forbidden (token may be expired or scope insufficient)', latency_ms: latency });
        } else {
          resolve({ status: 'fail', detail: `HTTP ${res.statusCode}: ${d.slice(0, 100)}`, latency_ms: latency });
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout after ' + TIMEOUT_MS + 'ms')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

function checkOpenAI(apiKey, t0) {
  return new Promise((resolve) => {
    const req = httpsRequest({
      host: 'api.openai.com', port: 443, path: '/v1/models', method: 'GET',
      headers: { 'Authorization': `Bearer ${apiKey}` },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) resolve({ status: 'ok', detail: 'models accessible', latency_ms: latency });
        else if (res.statusCode === 401) resolve({ status: 'expired', detail: '401 invalid_api_key', latency_ms: latency });
        else resolve({ status: 'fail', detail: `HTTP ${res.statusCode}`, latency_ms: latency });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout after ' + TIMEOUT_MS + 'ms')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

function checkSsh(meta, t0) {
  // meta: { host, port, user, auth }
  // 缺 host 字段: 是配置错 (用户配了 ssh_connection 但没填 host), 不是 skipped
  if (!meta || !meta.host) {
    return Promise.resolve({ status: 'misconfigured', detail: 'ssh_connection missing host field', latency_ms: 0 });
  }
  return new Promise((resolve) => {
    const sock = netConnect(meta.port || 22, meta.host);
    const timer = setTimeout(() => {
      sock.destroy();
      // 10s timeout: 远端不响应, 通常是 ssh target 错 (防火墙 drop / 内网不可达)
      resolve({ status: 'misconfigured', detail: `connect timeout ${meta.host}:${meta.port || 22} — target may be unreachable or behind firewall`, latency_ms: Date.now() - t0 });
    }, TIMEOUT_MS);
    sock.on('connect', () => {
      clearTimeout(timer);
      sock.end();
      resolve({ status: 'ok', detail: `tcp ${meta.host}:${meta.port || 22} reachable (auth=${meta.auth || '?'})`, latency_ms: Date.now() - t0 });
    });
    sock.on('error', e => {
      clearTimeout(timer);
      // ECONNREFUSED → misconfigured (端口不开或目标错)
      // ECONNRESET / ENOTFOUND → unreachable (网络层)
      // 其它 → 走 classifyError 分类
      resolve({ ...classifyError(e), latency_ms: Date.now() - t0 });
    });
  });
}

function checkCloudflare(apiToken, t0) {
  // 调 GET /client/v4/user 验证 token 鉴权 (no-side-effect, 只读自己 user info)
  return new Promise((resolve) => {
    const req = httpsRequest({
      host: 'api.cloudflare.com', port: 443, path: '/client/v4/user', method: 'GET',
      headers: { 'Authorization': `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          let email = null;
          try { email = JSON.parse(d).result?.email; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `user=${email || '?'}`, latency_ms: latency });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          // 403 也可能是 token 失效或 scope 不足
          resolve({ status: 'expired', detail: `${res.statusCode} ${res.statusCode === 401 ? 'unauthorized' : 'forbidden'} (token may be expired or scope insufficient)`, latency_ms: latency });
        } else {
          resolve({ status: 'fail', detail: `HTTP ${res.statusCode}: ${d.slice(0, 100)}`, latency_ms: latency });
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

// ============================================================
// v3.0 M5.1: aliyun_ak v2 验签 (HMAC-SHA1 + base64 + RFC 3986)
// 调 https://ecs.aliyuncs.com/?Action=DescribeRegions 验证 ak
// 公共参数: AccessKeyId / SignatureMethod / SignatureVersion / Timestamp / SignatureNonce / Format
// 签名规范: https://help.aliyun.com/document_detail/315526.html
// ============================================================

// RFC 3986 编码 (跟 encodeURIComponent 区别: ! ~ * ' ( ) 保留原样, 空格变 %20)
function rfc3986(s) {
  return encodeURIComponent(s)
    .replace(/!/g, '%21')
    .replace(/\*/g, '%2A')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29');
}

// 纯函数: 给一组公共+业务参数, 计算 aliyun v2 signature + 完整 query string
// 入参: { action, accessKeyId, accessKeySecret, region?, timestamp?, nonce? }
// 返: { query: 'k1=v1&...&Signature=xxx', signature, stringToSign, canonical }
export function signAliyun({ action, accessKeyId, accessKeySecret, region = 'cn-hangzhou', timestamp, nonce }) {
  // 公共参数 + 业务参数
  const params = {
    AccessKeyId: accessKeyId,
    Action: action,
    Format: 'JSON',
    RegionId: region,
    SignatureMethod: 'HMAC-SHA1',
    SignatureNonce: nonce || (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now()),
    SignatureVersion: '1.0',
    Timestamp: timestamp || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),  // ISO 8601 UTC, 截 ms
    Version: '2014-05-26',
  };
  // 字典序排序
  const sortedKeys = Object.keys(params).sort();
  // 拼 canonicalized query string
  const canonical = sortedKeys
    .map(k => `${rfc3986(k)}=${rfc3986(params[k])}`)
    .join('&');
  // StringToSign: METHOD&%2F&URL-encoded-canonical
  const stringToSign = `GET&${rfc3986('/')}&${rfc3986(canonical)}`;
  // HMAC-SHA1(key = accessKeySecret + "&", data = stringToSign)
  const signature = createHmac('sha1', accessKeySecret + '&')
    .update(stringToSign)
    .digest('base64');
  // 最终 query
  const query = `${canonical}&Signature=${rfc3986(signature)}`;
  return { query, signature, stringToSign, canonical };
}

async function checkAliyun(accessKeyId, meta, t0) {
  // meta: { access_key_secret, region }
  // 缺 secret: 凭据字段不齐 = 配置错 (用户要补字段), 不是 skipped
  if (!accessKeyId || !meta?.access_key_secret) {
    const missing = !accessKeyId ? 'access_key_id' : 'access_key_secret';
    return { status: 'misconfigured', detail: `aliyun_ak missing ${missing}`, latency_ms: 0 };
  }
  // 签名 + 调 DescribeRegions
  const { query } = signAliyun({
    action: 'DescribeRegions',
    accessKeyId,
    accessKeySecret: meta.access_key_secret,
    region: meta.region || 'cn-hangzhou',
  });
  const path = `/?${query}`;
  // 允许测试用 env 切 host/port (默认 ecs.aliyuncs.com:443)
  const host = process.env.ALIYUN_HEALTHCHECK_HOST || 'ecs.aliyuncs.com';
  const port = Number(process.env.ALIYUN_HEALTHCHECK_PORT) || 443;
  // port=443 走 https, 其它 (test mock) 走 http
  const httpLib = port === 443 ? httpsRequest : (await import('node:http')).request;
  return new Promise((resolve) => {
    const req = httpLib({
      host, port, path, method: 'GET',
      headers: { 'Host': host, 'User-Agent': 'secret-broker-healthcheck' },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          // DescribeRegions 返 JSON, 列出 region 数量
          let regionCount = 0;
          try { regionCount = JSON.parse(d).Regions?.Region?.length || 0; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `DescribeRegions ok (${regionCount} regions accessible)`, latency_ms: latency });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          // aliyun 用 403 InvalidAccessKeyId / SignatureDoesNotMatch
          resolve({ status: 'expired', detail: `${res.statusCode} ${d.slice(0, 150).replace(/\s+/g, ' ').trim()}`, latency_ms: latency });
        } else {
          resolve({ status: 'fail', detail: `HTTP ${res.statusCode}: ${d.slice(0, 100)}`, latency_ms: latency });
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout after ' + TIMEOUT_MS + 'ms')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

// ============================================================
// v3.0 M5.2: tencent_sk TC3-HMAC-SHA256 验签
// 调 https://cvm.tencentcloudapi.com/?Action=DescribeRegions&Version=2017-03-12 验证 SK
// 签名规范: https://cloud.tencent.com/document/api/1727/8438
// ============================================================
function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}
function hmacSha256(key, data) {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

// 纯函数: tencent TC3-HMAC-SHA256 签名
// 入参: { action, version, secretId, secretKey, region?, host?, payload?, timestamp? }
// 返: { authorization, timestamp, canonicalRequest, stringToSign, signature }
export function signTencent({ action, version, secretId, secretKey, region = 'ap-guangzhou', host = 'cvm.tencentcloudapi.com', payload = '', timestamp }) {
  // 1. 时间戳 + 日期
  const ts = timestamp || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');  // YYYY-MM-DDTHH:mm:ssZ
  const date = ts.split('T')[0];  // YYYY-MM-DD
  const service = 'cvm';
  // 2. Canonical request = HTTP method + URI + sorted query + headers + signed headers
  // 这里只验 GET (DescribeRegions), body=空. payload 留给 POST/PUT
  const httpRequestMethod = payload ? 'POST' : 'GET';
  const canonicalUri = '/';
  const canonicalQueryString = `Action=${encodeURIComponent(action)}&Version=${encodeURIComponent(version)}`;
  const contentType = payload ? 'application/json; charset=utf-8' : 'application/x-www-form-urlencoded';
  const canonicalHeaders = `content-type:${contentType}\nhost:${host}\n`;
  const signedHeaders = 'content-type;host';
  const hashedRequestPayload = sha256Hex(payload);
  const canonicalRequest = [httpRequestMethod, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, hashedRequestPayload].join('\n');
  // 3. String to sign
  const credentialScope = `${date}/${service}/tc3_request`;
  const stringToSign = ['TC3-HMAC-SHA256', ts, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  // 4. 计算 signature (3 步 HMAC chain)
  const secretDate = hmacSha256('TC3' + secretKey, date);
  const secretService = hmacSha256(secretDate, service);
  const secretSigning = hmacSha256(secretService, 'tc3_request');
  const signature = createHmac('sha256', secretSigning).update(stringToSign, 'utf8').digest('hex');
  // 5. Authorization header
  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { authorization, timestamp: ts, canonicalRequest, stringToSign, signature, contentType };
}

async function checkTencent(secretId, meta, t0) {
  // meta: { secret_key, region }
  // 缺 secret: 配置错
  if (!secretId || !meta?.secret_key) {
    const missing = !secretId ? 'secret_id' : 'secret_key';
    return { status: 'misconfigured', detail: `tencent_sk missing ${missing}`, latency_ms: 0 };
  }
  const { authorization, contentType } = signTencent({
    action: 'DescribeRegions',
    version: '2017-03-12',
    secretId,
    secretKey: meta.secret_key,
    region: meta.region || 'ap-guangzhou',
  });
  const path = '/?Action=DescribeRegions&Version=2017-03-12';
  const host = process.env.TENCENT_HEALTHCHECK_HOST || 'cvm.tencentcloudapi.com';
  const port = Number(process.env.TENCENT_HEALTHCHECK_PORT) || 443;
  const httpLib = port === 443 ? httpsRequest : (await import('node:http')).request;
  return new Promise((resolve) => {
    const req = httpLib({
      host, port, path, method: 'GET',
      headers: {
        'Host': host,
        'Content-Type': contentType,
        'Authorization': authorization,
        'X-TC-Action': 'DescribeRegions',
        'X-TC-Version': '2017-03-12',
        'X-TC-Timestamp': new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        'X-TC-Region': meta.region || 'ap-guangzhou',
        'User-Agent': 'secret-broker-healthcheck',
      },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          let regionCount = 0;
          try { regionCount = JSON.parse(d).Response?.TotalCount || 0; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `DescribeRegions ok (${regionCount} regions accessible)`, latency_ms: latency });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          // tencent 用 401 SignatureFailure / 403 auth failure
          resolve({ status: 'expired', detail: `${res.statusCode} ${d.slice(0, 150).replace(/\s+/g, ' ').trim()}`, latency_ms: latency });
        } else {
          resolve({ status: 'fail', detail: `HTTP ${res.statusCode}: ${d.slice(0, 100)}`, latency_ms: latency });
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout after ' + TIMEOUT_MS + 'ms')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

// ============================================================
// v3.0 M5.2: aws_access_key SigV4 验签
// 调 https://sts.amazonaws.com/?Action=GetCallerIdentity 验证 AK
// 签名规范: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
// ============================================================
// 纯函数: aws SigV4 签名 (GET, 无 body, 单一 query Action=GetCallerIdentity)
// 入参: { accessKeyId, secretAccessKey, region, service, host, query?, amzDate? }
// 返: { authorization, amzDate, canonicalRequest, stringToSign, signature, signedHeaders }
export function signAws({ accessKeyId, secretAccessKey, region = 'us-east-1', service = 'sts', host, query = 'Action=GetCallerIdentity&Version=2011-06-15', amzDate }) {
  const _amzDate = amzDate || new Date().toISOString().replace(/[\-:]/g, '').replace(/\.\d{3}Z$/, 'Z');  // YYYYMMDDTHHmmssZ
  const dateStamp = _amzDate.split('T')[0];  // YYYYMMDD
  const _host = host || `${service}.${region}.amazonaws.com`;
  // 1. Canonical request
  const httpRequestMethod = 'GET';
  const canonicalUri = '/';
  // sorted query: Action, Version
  const canonicalQueryString = query.split('&').sort().join('&');
  const canonicalHeaders = `host:${_host}\nx-amz-date:${_amzDate}\n`;
  const signedHeaders = 'host;x-amz-date';
  const payloadHash = sha256Hex('');  // GET 无 body
  const canonicalRequest = [httpRequestMethod, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  // 2. String to sign
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', _amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  // 3. 计算 signature (4 步 HMAC chain)
  const kDate = hmacSha256('AWS4' + secretAccessKey, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');
  // 4. Authorization header
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { authorization, amzDate: _amzDate, canonicalRequest, stringToSign, signature, signedHeaders, host: _host };
}

async function checkAws(accessKeyId, meta, t0) {
  // meta: { secret_access_key, region }
  // 缺 secret: 配置错
  if (!accessKeyId || !meta?.secret_access_key) {
    const missing = !accessKeyId ? 'access_key_id' : 'secret_access_key';
    return { status: 'misconfigured', detail: `aws_access_key missing ${missing}`, latency_ms: 0 };
  }
  const { authorization, amzDate, host, signedHeaders } = signAws({
    accessKeyId,
    secretAccessKey: meta.secret_access_key,
    region: meta.region || 'us-east-1',
    service: 'sts',
  });
  const path = '/?Action=GetCallerIdentity&Version=2011-06-15';
  const _host = process.env.AWS_HEALTHCHECK_HOST || host;
  const port = Number(process.env.AWS_HEALTHCHECK_PORT) || 443;
  const httpLib = port === 443 ? httpsRequest : (await import('node:http')).request;
  return new Promise((resolve) => {
    const req = httpLib({
      host: _host, port, path, method: 'GET',
      headers: {
        'Host': _host,
        'Authorization': authorization,
        'X-Amz-Date': amzDate,
        'User-Agent': 'secret-broker-healthcheck',
      },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          // GetCallerIdentity 返 XML, 含 <Arn>
          let arn = null;
          try { arn = d.match(/<Arn>(.*?)<\/Arn>/)?.[1]; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `GetCallerIdentity ok (arn=${arn || '?'})`, latency_ms: latency });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          // aws 用 403 InvalidClientTokenId / SignatureDoesNotMatch
          resolve({ status: 'expired', detail: `${res.statusCode} ${d.slice(0, 150).replace(/\s+/g, ' ').trim()}`, latency_ms: latency });
        } else {
          resolve({ status: 'fail', detail: `HTTP ${res.statusCode}: ${d.slice(0, 100)}`, latency_ms: latency });
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout after ' + TIMEOUT_MS + 'ms')); });
    req.on('error', e => resolve({ ...classifyError(e), latency_ms: Date.now() - t0 }));
    req.end();
  });
}

// ============================================================
// 批量检查
// getSecrets 返: { name: { type, fields, description } }
// ============================================================
export async function runAll(getSecrets) {
  loadState();
  loadAlertHistory();
  const t0 = Date.now();
  // v3.1 M5.3: 5 维 status (M4 4 维 + unreachable / misconfigured)
  const summary = { ok: 0, expired: 0, unreachable: 0, misconfigured: 0, fail: 0, skipped: 0, total: 0 };
  const checks = {};
  for (const [name, entry] of Object.entries(getSecrets())) {
    summary.total++;
    const r = await checkSecret(name, entry.fields || {}, entry.type);
    checks[name] = { ...r, type: entry.type, ts: new Date().toISOString() };
    summary[r.status] = (summary[r.status] || 0) + 1;
  }
  // last_status: ok 当且仅当 5 个非 ok 维度全为 0
  const allPass = summary.expired === 0 && summary.unreachable === 0
    && summary.misconfigured === 0 && summary.fail === 0;
  // v3.1.1 M5.6: 检测状态变化 (跟上次 status 比)
  const changes = detectChanges(checks);
  const newState = {
    last_run_at: new Date().toISOString(),
    last_status: allPass ? 'ok' : 'degraded',
    duration_ms: Date.now() - t0,
    summary,
    checks,
  };
  state = newState;
  saveState();
  // M5.6: 状态变化时落 alert_history + emit status_change
  if (Object.keys(changes).length > 0) {
    const alertEntry = {
      ts: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      summary,
      changes,
    };
    alertHistory.push(alertEntry);
    saveAlertHistory();
    HEALTHCHECK_BUS.emit('status_change', alertEntry);
  }
  HEALTHCHECK_BUS.emit('run_complete', newState);
  return newState;
}

// ============================================================
// v3.0 M5: 调 mcp-server 跑 healthcheck (broker 不出网时由 mcp-server 走 client.mavis cert 出网)
// v3.1.1 M5.6: 跟 broker runAll 一样检测状态变化 + 落 alert_history + emit status_change
// 返: { last_status, last_run_at, duration_ms, summary, checks, _source: 'mcp_server' }
// ============================================================
export async function runAllViaMcp(mcpServerUrl) {
  loadState();
  loadAlertHistory();
  const t0 = Date.now();
  // 调 mcp-server /mcp tools/call run_healthcheck (JSON-RPC 2.0)
  const req = await import('node:http');
  // mcp-server 在 localhost, 用 http (不走 mTLS, 不暴露外网)
  const url = new URL('/mcp', mcpServerUrl);
  const body = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'run_healthcheck', arguments: {} },
  });
  const result = await new Promise((resolve, reject) => {
    const r = req.request({
      host: url.hostname,
      port: url.port || 3001,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 60_000,  // healthcheck 跑 5 secrets ~12s, 给 60s
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`mcp-server HTTP ${res.statusCode}: ${d.slice(0, 200)}`));
        }
        try {
          const json = JSON.parse(d);
          if (json.error) return reject(new Error(`mcp-server RPC error: ${json.error.message}`));
          const text = json.result?.content?.[0]?.text;
          if (!text) return reject(new Error('mcp-server 返空 result'));
          resolve(JSON.parse(text));
        } catch (e) { reject(new Error(`mcp-server 返非 JSON: ${e.message}`)); }
      });
    });
    r.on('timeout', () => r.destroy(new Error('mcp-server timeout 60s')));
    r.on('error', reject);
    r.write(body);
    r.end();
  });
  // 写 broker state (跟 broker runAll 同一格式)
  const newState = {
    last_run_at: new Date().toISOString(),
    last_status: result.last_status || 'unknown',
    duration_ms: result.duration_ms || (Date.now() - t0),
    // v3.1 M5.3: summary 5 维兜底 (M4 4 维 + unreachable / misconfigured)
    summary: result.summary || { ok: 0, expired: 0, unreachable: 0, misconfigured: 0, fail: 0, skipped: 0, total: 0 },
    checks: result.checks || {},
    _source: 'mcp_server',  // 标记这次跑来自 mcp-server
  };
  // M5.6: 状态变化检测
  const changes = detectChanges(newState.checks);
  state = newState;
  saveState();
  if (Object.keys(changes).length > 0) {
    const alertEntry = {
      ts: new Date().toISOString(),
      duration_ms: newState.duration_ms,
      summary: newState.summary,
      changes,
      _source: 'mcp_server',
    };
    alertHistory.push(alertEntry);
    saveAlertHistory();
    HEALTHCHECK_BUS.emit('status_change', alertEntry);
  }
  HEALTHCHECK_BUS.emit('run_complete', newState);
  return newState;
}

// ============================================================
// 状态查询 (供 /api/v1/healthcheck/status 用)
// ============================================================
export function getStatus() {
  loadState();
  return state;
}

export function getSecretStatus(name) {
  loadState();
  return state.checks?.[name] || null;
}

// ============================================================
// v3.1.1 M5.6: alert_history 查询 (供 /api/v1/admin/alerts/history 用)
// 返最近 N 条状态变化. 不传 N 返全部 (已 trim 到 ALERT_HISTORY_MAX)
// ============================================================
export function getAlertHistory(limit) {
  loadAlertHistory();
  if (typeof limit === 'number' && limit > 0) {
    return alertHistory.slice(-limit);
  }
  return alertHistory.slice();
}
