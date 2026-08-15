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
      return {
        primary: fields.private_key || fields.password || '',
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
// 单个 secret 检查
// signature: checkSecret(name, fields, type) → {status, detail, latency_ms}
// 公开 export 供 mcp-server 等外部进程复用 (无需 broker SECRET_CACHE)
// ============================================================
export async function checkSecret(secretName, fields, secretType) {
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
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
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
  if (!accessKeyId || !meta?.access_key_secret) {
    return { status: 'skipped', detail: 'aliyun_ak missing access_key_id or access_key_secret', latency_ms: 0 };
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
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
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
  if (!secretId || !meta?.secret_key) {
    return { status: 'skipped', detail: 'tencent_sk missing secret_id or secret_key', latency_ms: 0 };
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
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
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
  if (!accessKeyId || !meta?.secret_access_key) {
    return { status: 'skipped', detail: 'aws_access_key missing access_key_id or secret_access_key', latency_ms: 0 };
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
    req.on('error', e => resolve({ status: 'fail', detail: e.message, latency_ms: Date.now() - t0 }));
    req.end();
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
// v3.0 M5: 调 mcp-server 跑 healthcheck (broker 不出网时由 mcp-server 走 client.mavis cert 出网)
// 返: { last_status, last_run_at, duration_ms, summary, checks, _source: 'mcp_server' }
// ============================================================
export async function runAllViaMcp(mcpServerUrl) {
  loadState();
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
    summary: result.summary || { ok: 0, expired: 0, fail: 0, skipped: 0, total: 0 },
    checks: result.checks || {},
    _source: 'mcp_server',  // 标记这次跑来自 mcp-server
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
