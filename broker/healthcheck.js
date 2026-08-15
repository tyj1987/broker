// broker/healthcheck.js — v3.0 M4 凭据自检引擎
// 每日 04:00 cron 触发 (broker/cron-tasks.js)
// 对每个 secret: dry_run = true, 调上游 no-side-effect API, 验凭据
// 失败: 写 audit + 推 SSE + dashboard 红色 stat
//
// 设计:
// - secret.type → checkSecret (switch)
// - 结果写 broker/audit/audit-<date>.jsonl (action: 'healthcheck', status: 'ok'|'fail'|'expired')
// - 同时推 ALERT_BUS (server.js 已有 EventEmitter)
// - 持久化最新状态到 broker/healthcheck-state.json (broker 进程内 + 磁盘兜底, 公网可查)
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
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Config
// ============================================================
const STATE_PATH = join(__dirname, 'healthcheck-state.json');
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
  if (existsSync(STATE_PATH)) {
    try { state = JSON.parse(readFileSync(STATE_PATH, 'utf-8')); } catch { /* ignore */ }
  }
  return state;
}

function saveState() {
  try {
    writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
  } catch (e) {
    console.error('[healthcheck] state save failed:', e.message);
  }
}

// ============================================================
// 单个 secret 检查
// ============================================================
async function checkSecret(secretName, secretValue, secretType) {
  const t0 = Date.now();
  try {
    switch (secretType) {
      case 'github_pat':  return await checkGithub(secretValue, t0);
      case 'aliyun_ak':   return await checkAliyun(secretValue, t0);
      case 'openai_key':  return await checkOpenAI(secretValue, t0);
      case 'ssh_connection': return await checkSsh(secretValue, t0);
      default: return { status: 'skipped', detail: 'no check for type=' + secretType, latency_ms: 0 };
    }
  } catch (e) {
    return { status: 'fail', detail: e.message.slice(0, 200), latency_ms: Date.now() - t0 };
  }
}

function checkGithub(pat, t0) {
  return new Promise((resolve) => {
    const req = httpsRequest({
      host: 'api.github.com', port: 443, path: '/user', method: 'GET',
      headers: { 'Authorization': `token ${pat}`, 'User-Agent': 'secret-broker-healthcheck' },
      timeout: TIMEOUT_MS,
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const latency = Date.now() - t0;
        if (res.statusCode === 200) {
          // 解析 login 字段
          let login = null;
          try { login = JSON.parse(d).login; } catch { /* ignore */ }
          resolve({ status: 'ok', detail: `user=${login || '?'}`, latency_ms: latency });
        } else if (res.statusCode === 401) {
          resolve({ status: 'expired', detail: '401 Bad credentials', latency_ms: latency });
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

export function checkAliyun(ak, t0) {
  // DescribeRegions 是 no-side-effect API, 只要 AK 有访问 ECS 权限就 200
  // 凭据格式: { access_key_id, access_key_secret, ... } (从 sops decrypt 拿到的结构)
  // 这里 ak 是整个 object (从 SECRET_CACHE 反序列化)
  // 简化: 假定 secretValue 是 { access_key_id, access_key_secret } 或 string (raw AK)
  // 实际 broker/server.js 的 SECRET_CACHE 是从 secrets-detail.json 读, 可能是 object
  // 通用做法: 调 /?Action=DescribeRegions 看是否 200
  return new Promise((resolve) => {
    // 真实环境会调 v2 签名, 这里只做 raw 探测 (简化)
    // 注: 完整 v2 签名调用 aliyun_v2 service proxy 实现, 但 healthcheck 走 dry-run
    //     应该走 broker 自己的 proxy 而不是直接调 aliyun, 避免重复逻辑
    //     但 broker proxy 需要 mTLS, 简化起见这里跳过 aliyun 检查 (后续扩展)
    resolve({ status: 'skipped', detail: 'aliyun_ak check requires broker proxy (TODO: M4.5)', latency_ms: 0 });
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

function checkSsh(connection, t0) {
  // connection: { host, port, user, ... } 或 string "user@host:port"
  return new Promise((resolve) => {
    let host, port;
    if (typeof connection === 'string') {
      const m = connection.match(/^(?:[^@]+@)?([^:]+):(\d+)$/);
      if (!m) return resolve({ status: 'fail', detail: 'bad ssh_connection format (expected user@host:port)', latency_ms: 0 });
      host = m[1]; port = parseInt(m[2], 10);
    } else {
      host = connection.host; port = connection.port || 22;
    }
    const sock = netConnect(port, host);
    const timer = setTimeout(() => { sock.destroy(); resolve({ status: 'fail', detail: `connect timeout ${host}:${port}`, latency_ms: Date.now() - t0 }); }, TIMEOUT_MS);
    sock.on('connect', () => { clearTimeout(timer); sock.end(); resolve({ status: 'ok', detail: `tcp ${host}:${port} reachable`, latency_ms: Date.now() - t0 }); });
    sock.on('error', e => { clearTimeout(timer); resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }); });
  });
}

// ============================================================
// 批量检查
// ============================================================
export async function runAll(getSecrets) {
  loadState();
  const t0 = Date.now();
  const summary = { ok: 0, expired: 0, fail: 0, skipped: 0, total: 0 };
  const checks = {};
  for (const [name, entry] of Object.entries(getSecrets())) {
    summary.total++;
    const r = await checkSecret(name, entry.value, entry.type);
    checks[name] = { ...r, type: entry.type, ts: new Date().toISOString() };
    summary[r.status]++;
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
