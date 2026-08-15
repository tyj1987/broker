// broker/healthcheck.js — v3.0 M4 凭据自检引擎
// 每日 04:00 cron 触发 (broker/cron-tasks.js)
// 对每个 secret: dry_run = true, 调上游 no-side-effect API, 验凭据
// 失败: 写 audit + 推 SSE + dashboard 红色 stat
//
// 设计:
// - secret.type → 抽 fields (按 type-schemas 字段名)
// - 结果写 broker/audit/audit-<date>.jsonl (action: 'healthcheck', status: 'ok'|'fail'|'expired')
// - 同时推 HEALTHCHECK_BUS (EventEmitter)
// - 持久化最新状态到 secrets/healthcheck-state.json (writable; secrets/ 在 ReadWritePaths 里)
//
// 不在 v3.0 范围: SMS / Email / Webhook 外发 (留 v3.1), 凭据零接触
//
// 烟雾测试 (no-side-effect):
// - github_pat:   GET https://api.github.com/user
// - aliyun_ak:    https://ecs.aliyuncs.com/?Action=DescribeRegions (skipped M4 — 需 broker proxy v2 签名, 留 M4.5)
// - openai_key:   GET https://api.openai.com/v1/models
// - ssh_connection: TCP connect <host>:<port> (用 net.Socket, 不开 shell)
// - 其他 type: 返回 status='skipped' (don't fail healthcheck just because we don't have a check)

import { request as httpsRequest } from 'node:https';
import { connect as netConnect } from 'node:net';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';

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
    case 'tencent_sk':
    case 'aws_access_key':
      // 两个字段都需要 (id+secret 配对), 但 healthcheck 暂跳过 (走 broker proxy 完整签名)
      return { primary: fields.access_key_id || fields.secret_id, meta: { pair: true } };
    case 'ssh_connection':
      return {
        primary: fields.private_key || fields.password || '',
        meta: { host: fields.host, port: fields.port || 22, user: fields.username, auth: fields.auth_method }
      };
    case 'ssh_private_key':
      return { primary: fields.key, meta: { auth: 'private_key' } };
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
// 单个 secret 检查
// signature: checkSecret(name, fields, type)
// ============================================================
async function checkSecret(secretName, fields, secretType) {
  const t0 = Date.now();
  const cred = pickCredential(secretType, fields);
  if (!cred || !cred.primary) {
    return { status: 'skipped', detail: `no extractable credential for type=${secretType}`, latency_ms: 0 };
  }
  try {
    switch (secretType) {
      case 'github_pat':
      case 'gitlab_pat':
      case 'gitee_pat':
        return await checkGithubLike(cred.primary, secretType, t0);
      case 'aliyun_ak':
      case 'tencent_sk':
      case 'aws_access_key':
        // M4: 跳过云厂商 — 完整 v2/v4 签名要 broker proxy 配合, 走 M4.5
        return { status: 'skipped', detail: `${secretType} check requires broker proxy (TODO: M4.5)`, latency_ms: 0 };
      case 'openai_key':
      case 'anthropic_key':
      case 'google_ai_key':
      case 'mistral_key':
      case 'cohere_key':
      case 'deepseek_key':
        return await checkOpenAI(cred.primary, t0);
      case 'ssh_connection':
        return await checkSsh(cred.meta, t0);
      case 'ssh_private_key':
        return { status: 'skipped', detail: 'ssh_private_key (bare) needs ssh_connection host/port — skipped', latency_ms: 0 };
      default:
        return { status: 'skipped', detail: 'no check for type=' + secretType, latency_ms: 0 };
    }
  } catch (e) {
    return { status: 'fail', detail: e.message.slice(0, 200), latency_ms: Date.now() - t0 };
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
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
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
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
    req.end();
  });
}

function checkSsh(meta, t0) {
  // meta: { host, port, user, auth }
  return new Promise((resolve) => {
    if (!meta || !meta.host) {
      return resolve({ status: 'skipped', detail: 'ssh_connection missing host field', latency_ms: 0 });
    }
    const sock = netConnect(meta.port || 22, meta.host);
    const timer = setTimeout(() => {
      sock.destroy();
      resolve({ status: 'fail', detail: `connect timeout ${meta.host}:${meta.port || 22}`, latency_ms: Date.now() - t0 });
    }, TIMEOUT_MS);
    sock.on('connect', () => {
      clearTimeout(timer);
      sock.end();
      resolve({ status: 'ok', detail: `tcp ${meta.host}:${meta.port || 22} reachable (auth=${meta.auth || '?'})`, latency_ms: Date.now() - t0 });
    });
    sock.on('error', e => {
      clearTimeout(timer);
      // ECONNREFUSED 也算"fail" — 凭据未过期但服务挂
      resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 });
    });
  });
}

// ============================================================
// 批量检查
// getSecrets 返: { name: { type, fields, description } }
// ============================================================
export async function runAll(getSecrets) {
  loadState();
  const t0 = Date.now();
  const summary = { ok: 0, expired: 0, fail: 0, skipped: 0, total: 0 };
  const checks = {};
  for (const [name, entry] of Object.entries(getSecrets())) {
    summary.total++;
    const r = await checkSecret(name, entry.fields || {}, entry.type);
    checks[name] = { ...r, type: entry.type, ts: new Date().toISOString() };
    summary[r.status] = (summary[r.status] || 0) + 1;
  }
  const allPass = summary.expired === 0 && summary.fail === 0;
  const newState = {
    last_run_at: new Date().toISOString(),
    last_status: allPass ? 'ok' : 'degraded',
    duration_ms: Date.now() - t0,
    summary,
    checks,
  };
  state = newState;
  saveState();
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
