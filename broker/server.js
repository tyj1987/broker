// server.js
// Secret Broker 服务端入口
// 监听 mTLS HTTPS，SOPS 解密配置，代理模式转发外部 API
//
// Usage:
//   node server.js
//   PORT=8443 CONFIG_PATH=/opt/broker/secrets/broker.yaml AGE_KEY_FILE=/opt/broker/pki/age.key node server.js

import { createServer as createHttpsServer } from 'node:https';
import { readFileSync, existsSync, appendFileSync, mkdirSync, statSync, readdirSync, unlinkSync, renameSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { parse as parseYaml } from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Config & env
// ============================================================
const PORT           = parseInt(process.env.PORT || '8443', 10);
const HOST           = process.env.HOST || '0.0.0.0';
const CONFIG_PATH    = process.env.CONFIG_PATH || resolvePath(__dirname, '../secrets/broker.yaml');
const SECRETS_PATH   = process.env.SECRETS_PATH || resolvePath(__dirname, '../secrets/common.env');
const PKI_DIR        = process.env.PKI_DIR || resolvePath(__dirname, '../pki');
const AGE_KEY_FILE   = process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE;
const AUDIT_DIR      = process.env.AUDIT_DIR || resolvePath(__dirname, '../audit');
const TLS_CERT       = process.env.TLS_CERT || join(PKI_DIR, 'server/server.crt');
const TLS_KEY        = process.env.TLS_KEY  || join(PKI_DIR, 'server/server.key');
const TLS_CA         = process.env.TLS_CA   || join(PKI_DIR, 'ca/ca.crt');
const TLS_CRL        = process.env.TLS_CRL  || join(PKI_DIR, 'ca/crl.pem');
const RELOAD_TOKEN   = process.env.RELOAD_TOKEN || randomUUID();

console.log('============================================');
console.log('  Secret Broker v2.0');
console.log('  mTLS Secret Broker for AI clients');
console.log('============================================');
console.log(`  Port:           ${PORT}`);
console.log(`  Config:         ${CONFIG_PATH}`);
console.log(`  Secrets:        ${SECRETS_PATH}`);
console.log(`  PKI dir:        ${PKI_DIR}`);
console.log(`  TLS cert:       ${TLS_CERT}`);
console.log(`  CA:             ${TLS_CA}`);
console.log(`  Audit dir:      ${AUDIT_DIR}`);
console.log(`  Age key:        ${AGE_KEY_FILE || '(not set)'}`);
console.log('============================================');

// ============================================================
// Sops loader: spawn sops --decrypt
// ============================================================
function sopsDecrypt(filePath) {
  return new Promise((resolve, reject) => {
    if (!existsSync(filePath)) {
      return reject(new Error(`File not found: ${filePath}`));
    }
    const env = { ...process.env };
    if (AGE_KEY_FILE) env.SOPS_AGE_KEY_FILE = AGE_KEY_FILE;

    // If a .sops.yaml is co-located, sops will use it. Otherwise we pass --age explicitly.
    // Detect by looking for .sops.yaml in the file's directory or parents (up to repo root).
    let dir = dirname(filePath);
    const stops = [resolvePath(__dirname, '..'), resolvePath('/')];
    let sopsConfigExists = false;
    while (true) {
      if (existsSync(join(dir, '.sops.yaml'))) { sopsConfigExists = true; break; }
      if (stops.includes(dir) || dir === dirname(dir)) break;
      dir = dirname(dir);
    }

    const args = ['--decrypt'];
    // Always pass --age public key for resilience. SOPS will use whichever
    // private key in SOPS_AGE_KEY_FILE matches. This avoids depending on
    // .sops.yaml path_regex matching broker.yaml.
    if (existsSync(AGE_KEY_FILE)) {
      const pub = readFileSync(AGE_KEY_FILE, 'utf8').match(/public key: (\S+)/)?.[1];
      if (pub) args.push('--age', pub);
    }
    args.push(filePath);

    const child = spawn('sops', args, { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '', err = '';
    child.stdout.on('data', d => out += d.toString());
    child.stderr.on('data', d => err += d.toString());
    child.on('error', e => reject(new Error(`sops spawn failed: ${e.message}. Is sops installed?`)));
    child.on('close', code => {
      if (code !== 0) return reject(new Error(`sops decrypt failed (code ${code}): ${err}`));
      resolve(out);
    });
  });
}

// ============================================================
// Config loader
// ============================================================
let CONFIG = null;
let SECRET_CACHE = new Map();  // name -> plaintext

async function loadConfig() {
  console.log('[config] Decrypting broker.yaml via SOPS...');
  const yamlText = await sopsDecrypt(CONFIG_PATH);
  const cfg = parseYaml(yamlText);
  if (!cfg || typeof cfg !== 'object') throw new Error('Invalid broker.yaml');
  cfg.services = cfg.services || {};
  cfg.clients = cfg.clients || {};
  CONFIG = cfg;
  console.log(`[config] Loaded: ${Object.keys(CONFIG.services).length} services, ${Object.keys(CONFIG.clients).length} clients`);
}

async function loadSecrets() {
  console.log('[secrets] Decrypting secrets/common.env via SOPS...');
  const text = await sopsDecrypt(SECRETS_PATH);
  SECRET_CACHE.clear();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_][A-Z0-9_.]*)\s*=\s*(.*)$/);
    if (m) {
      let v = m[2].trim();
      // strip surrounding quotes
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      SECRET_CACHE.set(m[1], v);
    }
  }
  console.log(`[secrets] Loaded ${SECRET_CACHE.size} secret entries`);
  if (process.env.SOPS_DEBUG) {
    console.log(`[secrets] Keys: ${[...SECRET_CACHE.keys()].join(', ')}`);
  }
}

function getSecret(name) {
  return SECRET_CACHE.get(name);
}

// ============================================================
// Audit log
// ============================================================
if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

function auditFilePath() {
  const d = new Date().toISOString().slice(0, 10);
  return join(AUDIT_DIR, `audit-${d}.jsonl`);
}

let auditBytes = 0;
function audit(event) {
  const e = {
    ts: new Date().toISOString(),
    id: randomUUID(),
    ...event,
  };
  const line = JSON.stringify(e) + '\n';
  try {
    appendFileSync(auditFilePath(), line, { encoding: 'utf8' });
    auditBytes += Buffer.byteLength(line, 'utf8');
    // rotate at 50MB
    if (auditBytes > 50 * 1024 * 1024) {
      const old = auditFilePath();
      const rotated = old + '.1';
      if (existsSync(rotated)) unlinkSync(rotated);
      renameSync(old, rotated);
      auditBytes = 0;
    }
  } catch (err) {
    console.error('[audit] write failed:', err.message);
  }
  return e;
}

function readAudit({ since, limit = 100 } = {}) {
  const files = readdirSync(AUDIT_DIR)
    .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
    .sort()
    .reverse();
  const out = [];
  for (const f of files) {
    if (out.length >= limit) break;
    const content = readFileSync(join(AUDIT_DIR, f), 'utf8');
    for (const line of content.split('\n').reverse()) {
      if (!line) continue;
      try {
        const e = JSON.parse(line);
        if (since && e.ts < since) continue;
        out.push(e);
        if (out.length >= limit) break;
      } catch {}
    }
  }
  return out;
}

// ============================================================
// Session tokens (for dashboard / browser usage; mTLS is still supported)
// ============================================================
const SESSIONS = new Map();  // token -> { cn, fp, role, clientName, expiresAt }
const SESSION_TTL_MS = 30 * 60 * 1000;  // 30 min
const SESSION_HEADER = 'x-auth-token';

function makeSession(ctx) {
  const token = randomUUID();
  SESSIONS.set(token, {
    cn: ctx.cn,
    fp: ctx.fp,
    role: ctx.client.role,
    clientName: ctx.clientName,
    cert: ctx.cert,
    client: ctx.client,
    expiresAt: Date.now() + SESSION_TTL_MS,
    createdAt: Date.now(),
  });
  return token;
}

function getSession(req) {
  const t = req.headers[SESSION_HEADER];
  if (!t) return null;
  const s = SESSIONS.get(t);
  if (!s) return null;
  if (Date.now() > s.expiresAt) {
    SESSIONS.delete(t);
    return null;
  }
  // sliding expiration
  s.expiresAt = Date.now() + SESSION_TTL_MS;
  return s;
}

function deleteSession(token) {
  if (token) SESSIONS.delete(token);
}

// Login brute-force protection (per client + auth mode)
const LOGIN_ATTEMPTS = new Map();  // `${clientName}|${mode}` -> { fails, lockedUntil }
const MAX_LOGIN_FAILS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

function checkLoginLock(key) {
  const a = LOGIN_ATTEMPTS.get(key);
  if (!a) return true;
  // lockedUntil === 0 means "no lock armed yet"; only block while armed
  if (a.lockedUntil && Date.now() < a.lockedUntil) return false;
  return true;
}

function recordLoginFail(key) {
  const a = LOGIN_ATTEMPTS.get(key) || { fails: 0, lockedUntil: 0 };
  // if a previous lockout expired, start the counter over
  if (a.lockedUntil && Date.now() >= a.lockedUntil) {
    a.fails = 0;
    a.lockedUntil = 0;
  }
  a.fails += 1;
  if (a.fails >= MAX_LOGIN_FAILS) a.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
  LOGIN_ATTEMPTS.set(key, a);
}

function clearLoginLock(key) {
  LOGIN_ATTEMPTS.delete(key);
}


function getClientContext(socket) {
  // Kept for back-compat with places that still pass req.socket.
  // New code should use getIdentity(req) which handles both mTLS and session.
  return getIdentity({ socket });
}

function checkPathAllowed(pattern, path) {
  if (!pattern) return true;
  if (Array.isArray(pattern)) {
    return pattern.some(p => checkPathAllowed(p, path));
  }
  try {
    return new RegExp(pattern).test(path);
  } catch {
    return false;
  }
}

function canResolve(ctx, secretName) {
  if (!ctx.client) return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_resolve || [];
  return checkPathAllowed(allow, secretName);
}

function canProxy(ctx, serviceName, path) {
  if (!ctx.client) return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  // allow can be a list of objects: { service, paths }
  for (const rule of allow) {
    if (rule === '*' || rule === '.*') return true;
    if (typeof rule === 'string' && rule === serviceName) return true;
    if (typeof rule === 'object' && rule.service === serviceName) {
      if (!rule.paths) return true;
      return checkPathAllowed(rule.paths, path);
    }
  }
  return false;
}

// Does the client have ANY access to a service at all (for the dashboard badge)?
function isServiceAllowed(ctx, serviceName) {
  if (!ctx.client) return false;
  if (ctx.client.role === 'admin') return true;
  const allow = ctx.client.allowed_proxy || [];
  for (const rule of allow) {
    if (rule === '*' || rule === '.*') return true;
    if (typeof rule === 'string' && rule === serviceName) return true;
    if (typeof rule === 'object' && rule.service === serviceName) return true;
  }
  return false;
}

// ============================================================
// Rate limit (in-memory, per-fingerprint)
// ============================================================
const RATE_BUCKETS = new Map();

// timing-safe string compare (for password check)
async function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // still consume time on the longest length to avoid early-reject timing leak
    let dummy = 0;
    for (let i = 0; i < Math.max(a.length, b.length); i++) dummy |= 0;
    return false;
  }
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function rateLimit(ctx) {
  if (!ctx.client) return true;  // fail at canResolve/canProxy later
  const limit = ctx.client.rate_limit || '100/hour';
  if (limit === 'unlimited') return true;
  const m = limit.match(/^(\d+)\/(hour|minute|day)$/);
  if (!m) return true;
  const max = parseInt(m[1], 10);
  const windowMs = m[2] === 'minute' ? 60_000 : m[2] === 'day' ? 86_400_000 : 3_600_000;
  const key = ctx.fp;
  const now = Date.now();
  const bucket = RATE_BUCKETS.get(key) || [];
  const fresh = bucket.filter(t => now - t < windowMs);
  if (fresh.length >= max) {
    RATE_BUCKETS.set(key, fresh);
    return false;
  }
  fresh.push(now);
  RATE_BUCKETS.set(key, fresh);
  return true;
}

// ============================================================
// HTTP helpers
// ============================================================
function send(res, status, body, extraHeaders = {}) {
  const isJson = typeof body === 'object';
  const payload = isJson ? JSON.stringify(body) : body;
  res.writeHead(status, {
    'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload, 'utf8'),
    'X-Broker-Version': '2.0.0',
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const MAX = 1024 * 1024;  // 1MB
    req.on('data', c => {
      size += c.length;
      if (size > MAX) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks).toString('utf8');
      if (!buf) return resolve(null);
      try { resolve(JSON.parse(buf)); }
      catch { resolve({ _raw: buf }); }
    });
    req.on('error', reject);
  });
}

function jsonError(res, status, msg) {
  return send(res, status, { error: msg, status });
}

// ============================================================
// Aliyun / Tencent IMDS + STS token (no long-lived AK needed)
// ============================================================
const IMDS_TIMEOUT_MS = 2000;
const STS_CACHE = new Map();  // roleName -> { token, expiresAt }

async function _imdsFetch(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), IMDS_TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: ctl.signal });
    if (!r.ok) throw new Error(`IMDS ${r.status}`);
    return r;
  } finally { clearTimeout(t); }
}

// Try to get the instance-attached RAM role name. Returns null if not on ECS.
async function getAliyunRamRole() {
  try {
    const r = await _imdsFetch('http://100.100.100.200/latest/meta-data/ram/security-credentials/');
    const txt = (await r.text()).trim();
    if (!txt || txt === 'Not Found' || txt.startsWith('<!')) return null;
    // IMDS sometimes returns the role name directly, sometimes JSON-wrapped.
    return txt.replace(/^"|"$/g, '');
  } catch (e) {
    return null;
  }
}

// Get STS credentials (cached until near expiry)
async function getAliyunStsToken(roleName) {
  const cached = STS_CACHE.get(roleName);
  if (cached && Date.now() < cached.expiresAt - 60_000) return cached;
  const r = await _imdsFetch(`http://100.100.100.200/latest/meta-data/ram/security-credentials/${encodeURIComponent(roleName)}`);
  const j = await r.json();
  if (j.Code && j.Code !== 'Success') throw new Error(`STS failed: ${j.Code} ${j.Message}`);
  const token = {
    accessKeyId: j.AccessKeyId,
    accessKeySecret: j.AccessKeySecret,
    securityToken: j.SecurityToken,
    expiresAt: new Date(j.Expiration).getTime(),
    code: j.Code,
  };
  STS_CACHE.set(roleName, token);
  return token;
}

async function getAliyunCreds(credentialSource) {
  // credentialSource: "imds" | "sops" (default sops)
  if (credentialSource === 'imds') {
    const role = await getAliyunRamRole();
    if (!role) throw new Error('IMDS: no RAM role attached to this instance. Run on ECS with instance profile.');
    return await getAliyunStsToken(role);
  }
  // SOPS-based: just return the AK/SK from the secret cache
  return null;  // caller will fall back to getSecret()
}

// ============================================================
// Aliyun OpenAPI v2 signature
// https://help.aliyun.com/document_detail/315526.htm
// ============================================================
import { createHmac } from 'node:crypto';

function aliyunPercentEncode(s) {
  // Aliyun encoding: encodeURIComponent then replace !*()' with their hex
  return encodeURIComponent(s)
    .replace(/\+/g, '%20')
    .replace(/\*/g, '%2A')
    .replace(/%7E/g, '~');  // ~ 已经是 %7E 了，encodeURIComponent 会编码为 %7E
}

function aliyunV2Sign(method, params, accessKeySecret) {
  // 1. Sort params by key
  const sortedKeys = Object.keys(params).sort();
  // 2. Build canonicalized query string
  const canonical = sortedKeys
    .map(k => `${aliyunPercentEncode(k)}=${aliyunPercentEncode(params[k])}`)
    .join('&');
  // 3. StringToSign
  const stringToSign = `${method}&${aliyunPercentEncode('/')}&${aliyunPercentEncode(canonical)}`;
  // 4. Sign
  const signature = createHmac('sha1', `${accessKeySecret}&`)
    .update(stringToSign)
    .digest('base64');
  return signature;
}

// Build a signed aliyun_v2 URL (query params merged with Signature etc.)
function buildAliyunSignedUrl(upstream, action, query, region, creds) {
  const params = {
    Format: 'JSON',
    Version: '2014-05-26',
    AccessKeyId: creds.accessKeyId,
    SignatureMethod: 'HMAC-SHA1',
    Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    SignatureVersion: '1.0',
    SignatureNonce: randomUUID(),
    Action: action,
    ...(region ? { RegionId: region } : {}),
    ...(query || {}),
  };
  // Some OpenAPIs also want ServiceCode/Product. Caller can set Service param.
  // Aliyun requires "Signature" param without signing itself
  const sig = aliyunV2Sign('GET', params, creds.accessKeySecret);
  const url = new URL('/', upstream);
  // add all params
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined) url.searchParams.set(k, String(v));
  }
  url.searchParams.set('Signature', sig);
  // IMDS-style STS also requires SecurityToken
  if (creds.securityToken) {
    url.searchParams.set('SecurityToken', creds.securityToken);
  }
  return url;
}

// Extract Aliyun Action from a path like "/?Action=DescribeInstances"
// or "/DescribeInstances" (for ECS-style), or from the request query.
// The broker.yaml maps service→Action via `action` field; if not set,
// the path query or the proxy request query is used.
function getAliyunAction(path, serviceCfg, query) {
  if (serviceCfg.action) return serviceCfg.action;
  // try to extract from query string
  try {
    const u = new URL(path, 'http://x/');
    if (u.searchParams.get('Action')) return u.searchParams.get('Action');
  } catch {}
  if (query && query.Action) return String(query.Action);
  return null;
}


async function callUpstream(serviceCfg, method, path, query, headers, body) {
  // Resolve all secrets used by this service
  const injectHeaders = { ...(serviceCfg.inject_headers || {}) };
  let url = null;

  if (serviceCfg.type === 'bearer' || serviceCfg.type === 'github_token' || serviceCfg.type === 'header') {
    // Simple bearer/header auth: resolve a single secret and inject as header
    if (!serviceCfg.token_secret) throw new Error(`Service ${serviceCfg.name || '?'} missing token_secret`);
    const token = getSecret(serviceCfg.token_secret);
    if (!token) throw new Error(`Secret ${serviceCfg.token_secret} not loaded`);
    if (serviceCfg.type === 'bearer') {
      injectHeaders['Authorization'] = `Bearer ${token}`;
    } else if (serviceCfg.type === 'github_token') {
      injectHeaders['Authorization'] = `token ${token}`;
    } else if (serviceCfg.type === 'header') {
      const tpl = serviceCfg.header_value_template || 'Bearer {{secret}}';
      injectHeaders[serviceCfg.header_name || 'Authorization'] = tpl.replace('{{secret}}', token);
    }
    // Build URL: caller-provided path + query against upstream
    url = new URL(path, serviceCfg.upstream);
    if (query && typeof query === 'object') {
      for (const [k, v] of Object.entries(query)) {
        if (v !== null && v !== undefined) url.searchParams.set(k, String(v));
      }
    }
  } else if (serviceCfg.type === 'aliyun_v2') {
    // Aliyun OpenAPI v2: pull creds from IMDS (preferred) or SOPS, then sign
    let creds = null;
    if (serviceCfg.credential_source === 'imds') {
      creds = await getAliyunCreds('imds');
    } else {
      // sops-based
      const ak = getSecret(serviceCfg.access_key_secret);
      const sk = getSecret(serviceCfg.access_secret_secret);
      if (!ak || !sk) throw new Error('Aliyun access_key or access_secret not loaded');
      creds = { accessKeyId: ak, accessKeySecret: sk };
    }
    const action = getAliyunAction(path, serviceCfg, query);
    if (!action) throw new Error('aliyun_v2 requires Action (set serviceCfg.action or pass ?Action=...)');
    url = buildAliyunSignedUrl(serviceCfg.upstream, action, query, serviceCfg.region, creds);
  } else {
    throw new Error(`Unsupported service type: ${serviceCfg.type}`);
  }

  // Build outgoing request
  const outHeaders = {
    'User-Agent': 'secret-broker/2.0',
    ...injectHeaders,
    ...(headers || {}),
  };
  // Host header 必须用 upstream 的 host，否则 upstream 验签会失败
  outHeaders['Host'] = url.host;

  const fetchOpts = {
    method: method || 'GET',
    headers: outHeaders,
    redirect: 'manual',
  };
  if (body !== null && body !== undefined && method !== 'GET' && method !== 'HEAD') {
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
      fetchOpts.body = body;
    } else {
      fetchOpts.body = JSON.stringify(body);
      if (!outHeaders['Content-Type']) outHeaders['Content-Type'] = 'application/json';
    }
  }

  const start = Date.now();
  const upstreamResp = await fetch(url, fetchOpts);
  const latency = Date.now() - start;

  // Read response
  const respHeaders = {};
  upstreamResp.headers.forEach((v, k) => { respHeaders[k] = v; });
  // strip hop-by-hop
  delete respHeaders['transfer-encoding'];
  delete respHeaders['connection'];
  delete respHeaders['keep-alive'];
  delete respHeaders['content-encoding'];  // 避免 content-length mismatch

  const respBuf = Buffer.from(await upstreamResp.arrayBuffer());
  return {
    status: upstreamResp.status,
    headers: respHeaders,
    body: respBuf,
    latency,
  };
}

// ============================================================
// Route handler
// ============================================================
async function handle(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const m = req.method;
  const p = url.pathname;
  const t0 = Date.now();

  // ----- Public: /health -----
  if (m === 'GET' && p === '/health') {
    return send(res, 200, {
      status: 'ok',
      version: '2.0.0',
      sops_loaded: SECRET_CACHE.size > 0,
      services: Object.keys(CONFIG.services),
      uptime_seconds: Math.floor(process.uptime()),
    });
  }

  // ----- Public: static dashboard assets (the login page must load without a client cert) -----
  if (m === 'GET' && (p === '/' || p === '/index.html' || p === '/app.js' || p === '/style.css')) {
    const map = { '/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css' };
    const f = join(__dirname, 'dashboard', map[p]);
    if (existsSync(f)) {
      const body = readFileSync(f);
      const ct = p.endsWith('.js') ? 'application/javascript; charset=utf-8'
               : p.endsWith('.css') ? 'text/css; charset=utf-8'
               : 'text/html; charset=utf-8';
      res.writeHead(200, { 'Content-Type': ct });
      return res.end(body);
    }
  }

  // ----- POST /api/v1/login: mTLS cert OR allow_password_login client -> session token -----
  // Login must work from a browser that may not have a client cert installed.
  // Security: password-only login requires the client to be explicitly marked
  // `allow_password_login: true` in broker.yaml AND is protected by a
  // per-client lockout (5 fails -> 15 min). mTLS remains the strong default.
  if (m === 'POST' && p === '/api/v1/login') {
    const body = await readBody(req) || {};
    const password = body.password;
    if (!password) return jsonError(res, 400, 'Missing {password}');
    const ctx0 = getIdentity(req);
    let targetClient = null, targetName = null, lockKey = null, via = 'mtls';
    if (ctx0 && ctx0.via === 'mtls') {
      if (!ctx0.client.password) return jsonError(res, 403, 'No password configured for this client');
      targetClient = ctx0.client;
      targetName = ctx0.clientName;
      lockKey = `${targetName}|mtls`;
    } else {
      // password-only login: client name is required and must opt in
      const clientName = (body.client || '').trim();
      const c = clientName ? CONFIG.clients[clientName] : null;
      if (!c || !c.allow_password_login) {
        audit({ action: 'login', status: 'denied', reason: 'password_login_not_allowed', client: clientName || '(none)' });
        return jsonError(res, 401, 'mTLS client certificate required; or pass {client} with allow_password_login: true');
      }
      targetClient = c;
      targetName = clientName;
      lockKey = `${clientName}|pw`;
      via = 'password';
    }
    if (!checkLoginLock(lockKey)) {
      audit({ action: 'login', status: 'denied', reason: 'lockout', client: lockKey });
      return jsonError(res, 429, 'Too many failed login attempts. Locked until later.');
    }
    const ok = await timingSafeEqual(password, targetClient.password);
    if (!ok) {
      recordLoginFail(lockKey);
      audit({ action: 'login', status: 'denied', reason: 'bad_password', client: lockKey });
      return jsonError(res, 401, 'Bad password');
    }
    clearLoginLock(lockKey);
    const cn = ctx0 ? ctx0.cn : `${targetName}@web`;
    const fp = ctx0 ? ctx0.fp : null;
    const token = makeSession({ cn, fp, role: targetClient.role, clientName: targetName, cert: { subject: { CN: cn } }, client: targetClient });
    audit({ action: 'login', status: 'ok', cn, client: targetName, via });
    res.setHeader('Set-Cookie', `broker_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
    return send(res, 200, {
      token,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      cn,
      role: targetClient.role,
      via,
    });
  }

  // ----- POST /api/v1/logout (drop session token) -----
  if (m === 'POST' && p === '/api/v1/logout') {
    const token = req.headers[SESSION_HEADER] || (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
    if (token) {
      const s = SESSIONS.get(token);
      if (s) audit({ action: 'logout', cn: s.cn, fp: s.fp, status: 'ok' });
      deleteSession(token);
    }
    res.setHeader('Set-Cookie', 'broker_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return send(res, 200, { logged_out: true });
  }

  // ----- Everything below needs auth (mTLS cert or session token) -----
  const ctx = getIdentity(req);
  if (!ctx || !ctx.certSubject) {
    audit({ action: 'connect', status: 'denied', reason: 'no_client_cert', remote: req.socket.remoteAddress });
    return jsonError(res, 401, 'mTLS client certificate required');
  }
  if (!ctx.client) {
    audit({ action: 'connect', status: 'denied', reason: 'cert_not_registered', cn: ctx.cn, fp: ctx.fp, remote: req.socket.remoteAddress });
    return jsonError(res, 403, `Client certificate not registered. CN=${ctx.cn} fp=${ctx.fp}`);
  }
  if (!rateLimit(ctx)) {
    audit({ action: 'connect', status: 'denied', reason: 'rate_limit', cn: ctx.cn, fp: ctx.fp });
    return jsonError(res, 429, 'Rate limit exceeded');
  }

  // ----- GET /api/v1/identity -----
  if (m === 'GET' && p === '/api/v1/identity') {
    return send(res, 200, {
      cn: ctx.cn,
      fingerprint_sha256: ctx.fp,
      role: ctx.client.role,
      client_name: ctx.clientName,
      cert_subject: ctx.certSubject,
      via: ctx.via,
    });
  }

  // ----- GET /api/v1/services (dashboard "AI Actions" view; never leaks secrets) -----
  if (m === 'GET' && p === '/api/v1/services') {
    const services = [];
    for (const [name, svc] of Object.entries(CONFIG.services)) {
      services.push({
        name,
        type: svc.type || 'unknown',
        description: svc.description || '',
        upstream: svc.upstream || '',
        region: svc.region || '',
        action: svc.action || '',
        allowed: isServiceAllowed(ctx, name),
        actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
      });
    }
    audit({ action: 'list_services', cn: ctx.cn, fp: ctx.fp, count: services.length });
    return send(res, 200, { services });
  }

  // ----- GET /api/v1/secrets -----
  if (m === 'GET' && p === '/api/v1/secrets') {
    const allow = ctx.client.allowed_resolve || [];
    const all = Array.from(SECRET_CACHE.keys());
    let visible;
    if (ctx.client.role === 'admin') visible = all;
    else if (allow.includes('.*') || allow.includes('*')) visible = all;
    else visible = all.filter(n => checkPathAllowed(allow, n));
    audit({ action: 'list', cn: ctx.cn, fp: ctx.fp, count: visible.length });
    return send(res, 200, { secrets: visible });
  }

  // ----- POST /api/v1/secrets/resolve -----
  if (m === 'POST' && p === '/api/v1/secrets/resolve') {
    const body = await readBody(req);
    if (!body || !body.name) return jsonError(res, 400, 'Missing {name}');
    if (!canResolve(ctx, body.name)) {
      audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, status: 'denied' });
      return jsonError(res, 403, 'Not allowed to resolve this secret');
    }
    const v = getSecret(body.name);
    if (!v) {
      audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, status: 'not_found' });
      return jsonError(res, 404, `Secret ${body.name} not loaded`);
    }
    audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, status: 'ok' });
    return send(res, 200, { name: body.name, value: v });
  }

  // ----- POST /api/v1/proxy/:service -----
  const proxyMatch = p.match(/^\/api\/v1\/proxy\/([a-z0-9_-]+)$/);
  if (m === 'POST' && proxyMatch) {
    const serviceName = proxyMatch[1];
    const svc = CONFIG.services[serviceName];
    if (!svc) {
      audit({ action: 'proxy', cn: ctx.cn, fp: ctx.fp, service: serviceName, status: 'unknown_service' });
      return jsonError(res, 404, `Unknown service: ${serviceName}`);
    }
    const body = await readBody(req) || {};
    const method = body.method || 'GET';
    const path = body.path || '/';
    if (!canProxy(ctx, serviceName, path)) {
      audit({ action: 'proxy', cn: ctx.cn, fp: ctx.fp, service: serviceName, method, path, status: 'denied' });
      return jsonError(res, 403, `Not allowed to proxy ${serviceName}${path}`);
    }
    try {
      const r = await callUpstream(svc, method, path, body.query, body.headers, body.body);
      audit({
        action: 'proxy',
        cn: ctx.cn,
        fp: ctx.fp,
        service: serviceName,
        method,
        path,
        upstream_status: r.status,
        latency_ms: r.latency,
        status: r.status >= 200 && r.status < 400 ? 'ok' : 'error',
      });
      // forward response
      res.writeHead(r.status, { ...r.headers, 'X-Broker-Latency-Ms': String(r.latency), 'X-Broker-Version': '2.0.0' });
      return res.end(r.body);
    } catch (err) {
      audit({ action: 'proxy', cn: ctx.cn, fp: ctx.fp, service: serviceName, method, path, status: 'error', error: err.message });
      return jsonError(res, 502, `Upstream error: ${err.message}`);
    }
  }

  // ----- GET /api/v1/audit -----
  if (m === 'GET' && p === '/api/v1/audit') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    const since = url.searchParams.get('since');
    const limit = parseInt(url.searchParams.get('limit') || '100', 10);
    return send(res, 200, { events: readAudit({ since, limit }) });
  }

  // ----- POST /api/v1/reload (admin only) -----
  if (m === 'POST' && p === '/api/v1/reload') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    const tok = url.searchParams.get('token') || req.headers['x-reload-token'];
    if (tok !== RELOAD_TOKEN) return jsonError(res, 401, 'Bad reload token');
    try {
      await loadConfig();
      await loadSecrets();
      audit({ action: 'reload', cn: ctx.cn, fp: ctx.fp, status: 'ok' });
      return send(res, 200, { reloaded: true, services: Object.keys(CONFIG.services), secrets: SECRET_CACHE.size });
    } catch (err) {
      audit({ action: 'reload', cn: ctx.cn, fp: ctx.fp, status: 'error', error: err.message });
      return jsonError(res, 500, err.message);
    }
  }

  // ----- POST /api/v1/rotate/:name -----
  const rotMatch = p.match(/^\/api\/v1\/rotate\/([a-zA-Z0-9_.-]+)$/);
  if (m === 'POST' && rotMatch) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    // 简化版：仅记审计 + 返回"see RUNBOOK"
    audit({ action: 'rotate', cn: ctx.cn, fp: ctx.fp, secret: rotMatch[1], status: 'triggered' });
    return send(res, 202, {
      rotated: rotMatch[1],
      note: 'See RUNBOOK.md to complete rotation. Broker does not auto-call provider APIs.',
    });
  }

  // 404
  audit({ action: 'unknown', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: '404' });
  return jsonError(res, 404, `Not found: ${m} ${p}`);
}

// ============================================================
// Identity: try session token first (for dashboard / browser), then mTLS
// ============================================================
function getIdentity(req) {
  // 1. session token (from dashboard / browser)
  const session = getSession(req);
  if (session) {
    return {
      cn: session.cn,
      fp: session.fp,
      client: session.client,
      clientName: session.clientName,
      certSubject: session.cert?.subject || { CN: session.cn },
      via: 'session',
    };
  }
  // 2. mTLS client cert (from CLI / scripts)
  const peer = req.socket.peerCertificate;
  let cert = null;
  if (typeof req.socket.getPeerCertificate === 'function') {
    cert = req.socket.getPeerCertificate(true);
  } else if (peer) {
    cert = peer;
  }
  if (!cert || !cert.subject) return null;
  const cn = cert.subject.CN;
  const fp = cert.fingerprint256;
  if (!cn || !fp) return null;
  let matched = null, matchedBy = null;
  for (const [name, c] of Object.entries(CONFIG.clients)) {
    if (c.cert_fingerprint_sha256 && c.cert_fingerprint_sha256.toUpperCase() === fp.toUpperCase()) {
      matched = c; matchedBy = name; break;
    }
  }
  if (!matched) return null;
  return {
    cn, fp, client: matched, clientName: matchedBy,
    certSubject: cert.subject,
    via: 'mtls',
  };
}

// ============================================================
// TLS server
// ============================================================
function start() {
  const tlsOpts = {
    cert: readFileSync(TLS_CERT),
    key: readFileSync(TLS_KEY),
    ca: readFileSync(TLS_CA),
    // requestCert: 客户端必须发证书 (TLS 握手时)
    // rejectUnauthorized: false 因为 /health 允许无证书；其他路由在 handle() 里
    // 检查 ctx.client 是否存在来决定 401
    requestCert: true,
    rejectUnauthorized: false,
    minVersion: 'TLSv1.3',
  };
  if (existsSync(TLS_CRL)) {
    tlsOpts.crl = readFileSync(TLS_CRL);
  }

  const server = createHttpsServer(tlsOpts, handle);

  server.on('tlsClientError', (err, tlsSocket) => {
    console.warn('[tls] client error:', err.message, 'from', tlsSocket.remoteAddress);
  });

  server.on('secureConnection', (tlsSocket) => {
    const cert = tlsSocket.getPeerCertificate(true);
    if (cert && cert.subject) {
      console.log(`[tls] client connected: CN=${cert.subject.CN} fp=${cert.fingerprint256}`);
    } else {
      console.log(`[tls] client connected WITHOUT client cert from ${tlsSocket.remoteAddress}`);
    }
  });

  server.listen(PORT, HOST, () => {
    console.log(`[broker] mTLS HTTPS listening on https://${HOST}:${PORT}`);
    console.log(`[broker] reload token: ${RELOAD_TOKEN}`);
  });

  process.on('SIGINT',  () => { console.log('\n[broker] shutting down'); server.close(); process.exit(0); });
  process.on('SIGTERM', () => { server.close(); process.exit(0); });
}

// ============================================================
// Bootstrap
// ============================================================
(async () => {
  try {
    await loadConfig();
    await loadSecrets();
    start();
  } catch (err) {
    console.error('[bootstrap] failed:', err.message);
    process.exit(1);
  }
})();
