// server.js
// Secret Broker 服务端入口
// 监听 mTLS HTTPS，SOPS 解密配置，代理模式转发外部 API
//
// Usage:
//   node server.js
//   PORT=8443 CONFIG_PATH=/opt/broker/secrets/broker.yaml AGE_KEY_FILE=/opt/broker/pki/age.key node server.js

import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { readFileSync, writeFileSync, existsSync, appendFileSync, mkdirSync, statSync, readdirSync, unlinkSync, renameSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
// v3.0: 强认证 (TOTP + MFA 状态机)
import {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  verifyMfaCode,
  isMfaRequired,
  MFA_TOKEN_TTL_MS,
} from './auth-flow.js';
// v3.0: 密码 hash + TOTP + 恢复码
import {
  verifyPassword as totpVerifyPassword,
  verify as verifyTotpFn,
  generateSecret,
  generateRecoveryCodes,
  hashRecoveryCode,
  hashPassword,
  buildOtpauthURL,
} from './totp.js';
// v3.0 M2: API Key 管理 + Bearer 鉴权
import {
  createApiKey as createApiKeyFn,
  revokeApiKey as revokeApiKeyFn,
  listApiKeys as listApiKeysFn,
  publicView as publicViewFn,
  findApiKey,
  parseBearer,
  canResolveSecret,
  canProxyService,
  recordUse,
  DEFAULT_TTL_MS as API_KEY_DEFAULT_TTL_MS,
  generateMasterKey,
  createChildKey,
  canCreateChild,
} from './api-keys.js';
// v3.0: schema migration (in start())
import { EventEmitter } from 'node:events';
import { setServers as dnsSetServers, lookup as dnsLookup, resolve4 as dnsResolve4 } from 'node:dns';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { TYPE_SCHEMAS, getTypeSchema, defaultFieldsFor, validateFields } from './type-schemas.js';
import { SERVICE_TEMPLATES, publicTemplateList } from './service-templates.js';
import {
  issueClientCert, certFingerprint, readClientCertPem, readClientKeyPem,
  deleteClientCertFiles, readCaCertPem, paths as certPaths,
} from './cert-issuer.js';

// Re-export the clients dir for the writable-probe helper.
const CLIENTS_DIR = certPaths.CLIENTS_DIR;

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Config & env
// ============================================================
const PORT           = parseInt(process.env.PORT || '8443', 10);
const HOST           = process.env.HOST || '0.0.0.0';
const CONFIG_PATH    = process.env.CONFIG_PATH || resolvePath(__dirname, '../secrets/broker.yaml');
const SECRETS_PATH   = process.env.SECRETS_PATH || resolvePath(__dirname, '../secrets/common.env');
// Phase 1.1.1: structured secrets (multi-field support). If this file doesn't
// exist, broker auto-migrates from common.env on first start and writes here.
const SECRETS_DETAIL_PATH = process.env.SECRETS_DETAIL_PATH || resolvePath(__dirname, '../secrets/secrets-detail.json');
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

// Atomic SOPS encrypt: write plaintext to .tmp, sops --encrypt --in-place, then rename.
// Returns when the file is durably encrypted. If any step fails, the .tmp is left
// on disk for forensics and the original file is untouched.
//
// IMPORTANT: tmp file must keep the same extension as the target (.env, .yaml, .json)
// so .sops.yaml path_regex rules still match during the sops encrypt call.
function sopsEncryptAtomic(targetPath, plaintext) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (AGE_KEY_FILE) env.SOPS_AGE_KEY_FILE = AGE_KEY_FILE;
    // Build tmp path: /opt/x/common.env  ->  /opt/x/.common.env.tmp.123.456
    // (dot-prefix + insert before extension so SOPS still sees the same extension)
    const dir = dirname(targetPath);
    const base = targetPath.slice(dir.length + 1);  // e.g. "common.env"
    const dot = base.lastIndexOf('.');
    const stem = dot > 0 ? base.slice(0, dot) : base;
    const ext = dot > 0 ? base.slice(dot) : '';
    const tmpPath = join(dir, `.${stem}.tmp.${process.pid}.${Date.now()}${ext}`);
    try {
      writeFileSync(tmpPath, plaintext, { encoding: 'utf8', mode: 0o600 });
    } catch (e) {
      return reject(new Error(`write tmp failed: ${e.message}`));
    }
    const args = ['--encrypt', '--in-place', tmpPath];
    if (existsSync(AGE_KEY_FILE)) {
      const pub = readFileSync(AGE_KEY_FILE, 'utf8').match(/public key: (\S+)/)?.[1];
      if (pub) args.unshift('--age', pub);
    }
    const child = spawn('sops', args, { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let err = '';
    child.stderr.on('data', d => err += d.toString());
    child.on('error', e => reject(new Error(`sops spawn failed: ${e.message}. Is sops installed?`)));
    child.on('close', code => {
      if (code !== 0) {
        // leave tmp for forensics, but DON'T touch the original file
        try { unlinkSync(tmpPath); } catch {}
        return reject(new Error(`sops encrypt failed (code ${code}): ${err}; tmp cleaned at ${tmpPath}`));
      }
      try {
        renameSync(tmpPath, targetPath);
        resolve();
      } catch (e) {
        try { unlinkSync(tmpPath); } catch {}
        reject(new Error(`rename tmp to target failed: ${e.message}; tmp cleaned`));
      }
    });
  });
}

// ============================================================
// Config loader
// ============================================================
let CONFIG = null;
// Phase 1.1.1: structured secrets. Each entry is:
//   { type, description, fields: { [fieldName]: value }, created_at, updated_at, updated_by }
// `type` is a key in type-schemas.js. `fields` is dynamic per type.
// The legacy `common.env` is read-only on startup; writes go to secrets-detail.json.
let SECRET_CACHE = new Map();

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
  // 1. Try new structured store first
  if (existsSync(SECRETS_DETAIL_PATH)) {
    try {
      const text = await sopsDecrypt(SECRETS_DETAIL_PATH);
      const obj = JSON.parse(text);
      SECRET_CACHE.clear();
      for (const [name, entry] of Object.entries(obj.secrets || {})) {
        SECRET_CACHE.set(name, normalizeSecretEntry(name, entry));
      }
      console.log(`[secrets] Loaded ${SECRET_CACHE.size} structured secrets from ${SECRETS_DETAIL_PATH}`);
      return;
    } catch (e) {
      console.error(`[secrets] Failed to load ${SECRETS_DETAIL_PATH}: ${e.message}`);
      // fall through to migration
    }
  }
  // 2. Migrate from legacy common.env (one-time)
  if (existsSync(SECRETS_PATH)) {
    console.log(`[secrets] ${SECRETS_DETAIL_PATH} not found; migrating from ${SECRETS_PATH}...`);
    const migrated = await migrateFromCommonEnv();
    SECRET_CACHE.clear();
    for (const [name, entry] of Object.entries(migrated)) {
      SECRET_CACHE.set(name, entry);
    }
    console.log(`[secrets] Migrated ${SECRET_CACHE.size} secrets; persisting to ${SECRETS_DETAIL_PATH}`);
    await persistSecretsDetail();
    return;
  }
  // 3. Nothing to load
  SECRET_CACHE.clear();
  console.log('[secrets] No secrets found (neither structured nor legacy)');
}

function normalizeSecretEntry(name, entry) {
  // Defensive: accept both new structured form and legacy {type, description, value}
  const out = {
    type: entry.type || 'custom',
    description: entry.description || '',
    fields: {},
    created_at: entry.created_at || new Date().toISOString(),
    updated_at: entry.updated_at || new Date().toISOString(),
    updated_by: entry.updated_by || 'system',
  };
  if (entry.fields && typeof entry.fields === 'object') {
    out.fields = { ...entry.fields };
  } else if (typeof entry.value === 'string') {
    // Legacy: { value: "..." } → wrap in single field
    out.fields = { value: entry.value };
  }
  return out;
}

// Heuristic migration: read each KEY=value from common.env, infer type from name,
// combine Aliyun AK pairs, save as structured JSON.
async function migrateFromCommonEnv() {
  const text = await sopsDecrypt(SECRETS_PATH);
  const entries = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_][A-Z0-9_.]*)\s*=\s*(.*)$/);
    if (m) {
      let v = m[2].trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      entries[m[1]] = v;
    }
  }
  const secrets = {};
  const consumed = new Set();
  const now = new Date().toISOString();

  // 1) Aliyun AK pairs: *_ACCESS_KEY + *_ACCESS_SECRET → one aliyun_ak secret
  for (const name of Object.keys(entries)) {
    if (consumed.has(name)) continue;
    if (/_ACCESS_KEY(?:_ID)?$/.test(name) || name === 'ALIYUN_ACCESS_KEY') {
      const skName = name.replace(/_ACCESS_KEY(?:_ID)?$/, '') + '_ACCESS_SECRET';
      if (entries[skName] && !consumed.has(skName)) {
        secrets[name] = {
          type: 'aliyun_ak',
          description: '(migrated from common.env; please review)',
          fields: { access_key_id: entries[name], access_key_secret: entries[skName] },
          created_at: now, updated_at: now, updated_by: 'migration',
        };
        consumed.add(name); consumed.add(skName);
      } else if (name === 'ALIYUN_ACCESS_KEY_ID' || name.endsWith('_ACCESS_KEY_ID')) {
        // ID without paired SECRET — treat as plain custom
        secrets[name] = {
          type: 'custom', description: '(migrated)',
          fields: { value: entries[name] },
          created_at: now, updated_at: now, updated_by: 'migration',
        };
        consumed.add(name);
      }
    }
  }
  // 2) Other keys: best-effort type guess
  for (const name of Object.keys(entries)) {
    if (consumed.has(name)) continue;
    let type = 'custom', fieldKey = 'value';
    if (/GITHUB/.test(name) || /_PAT$/.test(name)) { type = 'github_pat'; fieldKey = 'token'; }
    else if (/OPENAI/.test(name)) { type = 'openai_key'; fieldKey = 'api_key'; }
    else if (/JWT_SECRET$/.test(name)) { type = 'jwt_secret'; fieldKey = 'value'; }
    else if (/_WEBHOOK$/.test(name)) {
      if (/SLACK/.test(name)) type = 'slack_webhook';
      else if (/DISCORD/.test(name)) type = 'discord_webhook';
      else if (/FEISHU|LARK/.test(name)) type = 'feishu_webhook';
      else if (/DINGTALK/.test(name)) type = 'dingtalk_webhook';
      fieldKey = 'url';
    } else if (/SENTRY/.test(name)) { type = 'sentry_dsn'; fieldKey = 'dsn'; }
    secrets[name] = {
      type, description: '(migrated; please re-categorize via admin UI)',
      fields: { [fieldKey]: entries[name] },
      created_at: now, updated_at: now, updated_by: 'migration',
    };
  }
  return secrets;
}

async function persistSecretsDetail() {
  const obj = { version: 1, secrets: Object.fromEntries(SECRET_CACHE) };
  const text = JSON.stringify(obj, null, 2) + '\n';
  await sopsEncryptAtomic(SECRETS_DETAIL_PATH, text);
}

// Phase 1.2: persist broker.yaml (services + clients section) to disk.
// The yaml MUST round-trip through SOPS (atomic write) and reloadConfig() so
// the running process picks up the change without restart.
async function persistConfig() {
  if (!CONFIG) throw new Error('CONFIG not loaded yet');
  // Re-emit the whole config (not just `services`) to preserve any extra fields
  // the operator may have set by hand. Order: services, clients.
  const out = {};
  if (CONFIG.services) out.services = CONFIG.services;
  if (CONFIG.clients)  out.clients  = CONFIG.clients;
  // Carry through any other top-level keys (version, etc.)
  for (const k of Object.keys(CONFIG)) {
    if (k === 'services' || k === 'clients') continue;
    out[k] = CONFIG[k];
  }
  let text = stringifyYaml(out, { lineWidth: 0, sortMapEntries: false }) + '\n';
  text = quoteYamlAmbiguousScalars(text);
  await sopsEncryptAtomic(CONFIG_PATH, text);
}

// Post-process yaml text: if a scalar value looks like a YAML 1.1 special type
// (date YYYY-MM-DD, time HH:MM:SS, timestamp) that we'd then want to read back
// as a plain string, wrap it in double quotes. This is the cheapest way to
// keep the round-trip stable without forcing every string to be quoted (which
// would make broker.yaml unreadable to humans).
function quoteYamlAmbiguousScalars(text) {
  return text
    // `key: 2025-08-12` (bare date) → `key: "2025-08-12"`
    .replace(/^(\s*[\w.-]+\s*:\s+)(\d{4}-\d{2}-\d{2})(\s*$)/gm, '$1"$2"$3')
    // `key: 12:34:56` (bare time) → `key: "12:34:56"`
    .replace(/^(\s*[\w.-]+\s*:\s+)(\d{1,2}:\d{2}:\d{2})(\s*$)/gm, '$1"$2"$3')
    // `key: 2025-08-12T10:00:00Z` (timestamp) → `key: "..."`
    .replace(/^(\s*[\w.-]+\s*:\s+)(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(\s*$)/gm, '$1"$2"$3');
}

// ============================================================
// Phase 1.3: Client lifecycle
// ============================================================
// We support 2 enrollment modes:
//   (a) Admin signs cert directly via /:name/enrollment → returns cert + key
//       in the response (one-time secret). The admin can then hand-deliver
//       the zip bundle (or re-issue via /:name/bundle).
//   (b) Admin calls POST /:name to create the client (no cert), then the
//       client-side CLI does `secret-broker enroll --token=xxx` to submit a
//       CSR. We sign it and return the cert. This is the "real" workflow
//       but is more complex; for now we ship (a) only and keep the door open
//       for (b) via a future /:name/sign-csr endpoint.

const ENROLLMENT_TTL_MS = 5 * 60 * 1000;  // 5 min
const ENROLLMENTS = new Map();  // token -> { clientName, expiresAt, signed? }

// Client name rule: same shape as services (URL path component) but allow
// dots for legacy `client.foo` style names.
const CLIENT_NAME_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
function isValidClientName(name) {
  return typeof name === 'string' && CLIENT_NAME_RE.test(name);
}

// Whitelist of client config fields the admin can set via the API. Cert
// fingerprint is set by the enrollment flow, never by the API.
function normalizeClientConfig(body) {
  if (!body || typeof body !== 'object') return null;
  const out = {};
  if (body.password !== undefined) out.password = String(body.password);
  if (body.password === null || body.password === '') delete out.password;  // explicit clear
  if (body.allow_password_login !== undefined) out.allow_password_login = !!body.allow_password_login;
  if (body.role !== undefined) {
    if (!['admin', 'developer', 'readonly'].includes(String(body.role))) {
      throw new Error(`Invalid role: ${body.role}`);
    }
    out.role = String(body.role);
  }
  if (body.allowed_resolve !== undefined) {
    out.allowed_resolve = Array.isArray(body.allowed_resolve) ? body.allowed_resolve.map(String) : [];
  }
  if (body.allowed_proxy !== undefined) {
    out.allowed_proxy = Array.isArray(body.allowed_proxy) ? body.allowed_proxy : [];
  }
  if (body.rate_limit !== undefined) out.rate_limit = String(body.rate_limit);
  if (body.description !== undefined) out.description = String(body.description);
  return out;
}

// Server-side last-seen timestamps. Not part of broker.yaml because it
// changes on every connect (would force a write per request). Map name → ms.
const LAST_SEEN = new Map();

// Hook called by getIdentity on successful mTLS handshake. Bumps a counter
// in memory; the admin UI can show "last seen 3m ago" without a write storm.
export function recordClientSeen(name) {
  if (name) LAST_SEEN.set(name, Date.now());
}
function lastSeenAgo(name) {
  const t = LAST_SEEN.get(name);
  if (!t) return null;
  return Date.now() - t;
}

// Service name rule: lowercase letters / digits / underscore / hyphen. Must
// start with a letter. Max 64 chars (shorter than secrets because services
// are referenced in URL paths like /api/v1/proxy/:name).
const SERVICE_NAME_RE = /^[a-z][a-z0-9_-]{0,63}$/;
function isValidServiceName(name) {
  return typeof name === 'string' && SERVICE_NAME_RE.test(name);
}

// Sanitize a service config that came from the API. We never accept `secret`
// from the API — only `token_secret` (the name reference), so the API can
// never leak a stored secret value into another service. Also drops unknown
// fields, coerces inject_headers to {string: string}, etc.
function normalizeServiceConfig(body) {
  if (!body || typeof body !== 'object') return null;
  const out = {};
  // Required
  if (body.type) out.type = String(body.type);
  if (body.upstream !== undefined) out.upstream = String(body.upstream);
  // Optional metadata
  if (body.description !== undefined) out.description = String(body.description);
  if (body.region !== undefined) out.region = String(body.region);
  if (body.action !== undefined) out.action = String(body.action);
  // Token reference: just the name of the secret; never the value
  if (body.token_secret !== undefined) out.token_secret = String(body.token_secret);
  // inject_headers: must be a flat string->string map
  if (body.inject_headers && typeof body.inject_headers === 'object') {
    const h = {};
    for (const [k, v] of Object.entries(body.inject_headers)) {
      if (v == null) continue;
      h[String(k)] = String(v);
    }
    if (Object.keys(h).length > 0) out.inject_headers = h;
  }
  // For type: header — extra fields
  if (body.header_name !== undefined) out.header_name = String(body.header_name);
  if (body.header_value_template !== undefined) out.header_value_template = String(body.header_value_template);
  // allow_paths: array of regex strings
  if (Array.isArray(body.allow_paths)) {
    out.allow_paths = body.allow_paths.map(s => String(s));
  }
  // dashboard_actions: array of {label, method, path, query?}
  if (Array.isArray(body.dashboard_actions)) {
    out.dashboard_actions = body.dashboard_actions
      .filter(a => a && typeof a === 'object' && a.label && a.method && a.path)
      .map(a => ({
        label: String(a.label),
        method: String(a.method).toUpperCase(),
        path: String(a.path),
        ...(a.query && typeof a.query === 'object' ? { query: a.query } : {}),
      }));
  }
  return out;
}

// Validate a normalized service config. Returns array of error strings (empty
// if valid). Used on POST and PUT.
function validateServiceConfig(name, cfg) {
  const errs = [];
  if (!isValidServiceName(name)) {
    errs.push('Invalid service name. Use [a-z][a-z0-9_-]{0,63}.');
  }
  if (!cfg) { errs.push('Missing config body'); return errs; }
  if (!cfg.type) errs.push('Missing type');
  else {
    // Allow any type we have callUpstream support for. (We don't restrict to
    // a known set because Phase 3 may add more.)
    const supported = new Set(['github_token', 'bearer', 'header', 'aliyun_v2', 'ssh_proxy']);
    if (!supported.has(cfg.type)) errs.push(`Unknown service type: ${cfg.type}`);
  }
  if (!cfg.upstream && cfg.type !== 'ssh_proxy') errs.push('Missing upstream URL');
  if (cfg.upstream) {
    try { new URL(cfg.upstream); } catch (e) { errs.push('upstream is not a valid URL'); }
  }
  if (cfg.type === 'header' && !cfg.header_value_template) {
    errs.push('type=header requires header_value_template (e.g. "Bearer {{secret.X.value}}")');
  }
  if (cfg.type === 'aliyun_v2' && !cfg.region) {
    errs.push('type=aliyun_v2 requires region');
  }
  if (cfg.token_secret && !isValidSecretName(cfg.token_secret)) {
    errs.push(`token_secret "${cfg.token_secret}" is not a valid secret name`);
  }
  return errs;
}

// Get a secret by name. Returns the full entry {type, fields, ...} or null.
function getSecret(name) {
  return SECRET_CACHE.get(name) || null;
}

// Get a specific field from a secret. Returns the value or undefined.
// Falls back to 'value' field if no field specified AND no other field is populated.
function getSecretField(name, fieldName) {
  const s = getSecret(name);
  if (!s) return undefined;
  if (fieldName && s.fields[fieldName] !== undefined && s.fields[fieldName] !== '') {
    return s.fields[fieldName];
  }
  if (s.fields.value !== undefined) return s.fields.value;
  // last resort: return first non-empty field
  for (const v of Object.values(s.fields)) {
    if (v !== '' && v !== null && v !== undefined) return v;
  }
  return undefined;
}

// ============================================================
// Secret name validation
// Allow: A-Z a-z 0-9 _ . -
// First char must be letter, digit, or underscore (no leading dot/dash)
// Max 128 chars
// ============================================================
const SECRET_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$/;
function isValidSecretName(name) {
  return typeof name === 'string' && SECRET_NAME_RE.test(name);
}

// Whitelisted secret types — comes from type-schemas.js
const ALLOWED_SECRET_TYPES = new Set(Object.keys(TYPE_SCHEMAS));

// ============================================================
// Audit log
// ============================================================
if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

// Phase 1.4: an in-process pub/sub for live audit events. The SSE endpoint
// subscribes; every `audit(...)` call also emits here. Restart the broker
// drops all subscribers (clients will reconnect on next page load).
const AUDIT_BUS = new EventEmitter();
AUDIT_BUS.setMaxListeners(0);  // unbounded; one listener per SSE connection

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
  // Broadcast to any live SSE subscribers. setImmediate keeps the audit
  // call non-blocking even if a subscriber is slow.
  setImmediate(() => AUDIT_BUS.emit('event', e));
  return e;
}

// Phase 1.4: filtered audit read.
// Filters: client (cn substring), service, action, status, since, until.
// Returns up to `limit` events (default 100, max 5000).
function readAuditFiltered({ client, service, action, status, since, until, limit = 100 } = {}) {
  const files = readdirSync(AUDIT_DIR)
    .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
    .sort()
    .reverse();
  const out = [];
  const maxLimit = Math.min(Math.max(1, limit), 5000);
  // Pre-lowercase substring matches
  const cnL     = client  ? String(client).toLowerCase()  : null;
  const svcL    = service ? String(service).toLowerCase() : null;
  const actL    = action  ? String(action).toLowerCase()  : null;
  const stL     = status  ? String(status).toLowerCase()  : null;
  for (const f of files) {
    if (out.length >= maxLimit) break;
    const content = readFileSync(join(AUDIT_DIR, f), 'utf8');
    for (const line of content.split('\n').reverse()) {
      if (!line) continue;
      let e;
      try { e = JSON.parse(line); } catch { continue; }
      if (since && e.ts < since) continue;
      if (until && e.ts > until) continue;
      if (cnL  && !(e.cn  || '').toLowerCase().includes(cnL))  continue;
      if (svcL && !(e.service || '').toLowerCase().includes(svcL)) continue;
      if (actL && !(e.action  || '').toLowerCase().includes(actL)) continue;
      if (stL  && !(e.status  || '').toLowerCase().includes(stL))  continue;
      out.push(e);
      if (out.length >= maxLimit) break;
    }
  }
  return out;
}

// Kept for backwards compat: simple {since, limit} read (used by /api/v1/audit).
function readAudit({ since, limit = 100 } = {}) {
  return readAuditFiltered({ since, limit });
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
  const t = req.headers[SESSION_HEADER]
    || (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
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

// Phase 1.2: list client names that have access to a given service. Used by
// the admin Services UI to show the permission matrix.
function clientNamesAllowedFor(serviceName) {
  const out = [];
  for (const [cname, c] of Object.entries(CONFIG.clients || {})) {
    if (c.role === 'admin') { out.push(cname); continue; }
    const allow = c.allowed_proxy || [];
    for (const rule of allow) {
      if (rule === '*' || rule === '.*') { out.push(cname); break; }
      if (typeof rule === 'string' && rule === serviceName) { out.push(cname); break; }
      if (typeof rule === 'object' && rule.service === serviceName) { out.push(cname); break; }
    }
  }
  return out;
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

// v3.0: 密码验证智能 wrapper — 检测 stored 是否 hash，自动选 verify 函数
// 兼容：plaintext / scrypt$... 两种格式
function verifyClientPassword(plaintext, stored) {
  if (!stored) return false;
  if (stored.startsWith('scrypt$')) {
    return totpVerifyPassword(plaintext, stored);
  }
  // legacy: plaintext (v2.x 兼容)
  return timingSafeEqual(plaintext, stored);
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

// Phase 1.3: minimal store-only zip writer (no compression). Used for the
// client cert bundle. Avoids pulling in archiver / jszip as a new dep.
// Format reference: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
//   local file header: 30 bytes + name + extra
//   central dir entry: 46 bytes + name + extra + comment
//   EOCD record:       22 bytes + comment
function buildZip(files) {
  const enc = (s) => Buffer.from(s, 'binary');
  const now = new Date();
  const dosTime = ((now.getHours() & 0x1f) << 11) | ((now.getMinutes() & 0x3f) << 5) | (Math.floor(now.getSeconds() / 2) & 0x1f);
  const dosDate = (((now.getFullYear() - 1980) & 0x7f) << 9) | (((now.getMonth() + 1) & 0xf) << 5) | (now.getDate() & 0x1f);
  let offset = 0;
  const localParts = [];
  const centralParts = [];
  for (const f of files) {
    const nameBuf = enc(f.name);
    const dataBuf = Buffer.from(f.data, 'utf8');
    const crc = computeCrc32(dataBuf);
    // Local file header (30 bytes)
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);   // signature
    lh.writeUInt16LE(20, 4);           // version needed
    lh.writeUInt16LE(0, 6);            // flags
    lh.writeUInt16LE(0, 8);            // method (0 = stored)
    lh.writeUInt16LE(dosTime, 10);
    lh.writeUInt16LE(dosDate, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(dataBuf.length, 18);  // compressed size
    lh.writeUInt32LE(dataBuf.length, 22);  // uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);           // extra
    localParts.push(lh, nameBuf, dataBuf);
    // Central dir entry (46 bytes)
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);   // signature
    cd.writeUInt16LE(20, 4);           // version made by
    cd.writeUInt16LE(20, 6);           // version needed
    cd.writeUInt16LE(0, 8);            // flags
    cd.writeUInt16LE(0, 10);           // method
    cd.writeUInt16LE(dosTime, 12);
    cd.writeUInt16LE(dosDate, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(dataBuf.length, 20);
    cd.writeUInt32LE(dataBuf.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);           // extra
    cd.writeUInt16LE(0, 32);           // comment
    cd.writeUInt16LE(0, 34);           // disk
    cd.writeUInt16LE(0, 36);           // internal attrs
    cd.writeUInt32LE(0o100644, 38);   // external attrs (regular file, 0644)
    cd.writeUInt32LE(offset, 42);      // local header offset
    centralParts.push(cd, nameBuf);
    offset += lh.length + nameBuf.length + dataBuf.length;
  }
  const local = Buffer.concat(localParts);
  const central = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(local.length, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([local, central, eocd]);
}

// Manual CRC32 (small tables; zlib.crc32 is in 22+). Only used as fallback.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function computeCrc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
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

// DNS-over-HTTPS pre-resolver. ECS outbound UDP/53 to public DNS is
// blocked; c-ares fails with ENOTFOUND. We use alidns DoH (TCP 443) to
// resolve and cache the result. Falls back to Cloudflare DoH if alidns
// itself is unreachable.
const _dohCache = new Map();  // hostname -> { ip, expiresAt }
const _dohInFlight = new Map();  // hostname -> Promise (de-dup concurrent)
const DOH_TTL_MS = 5 * 60 * 1000;

async function resolveHostnameDoH(hostname) {
  // If already an IP literal, return as-is.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;
  const cached = _dohCache.get(hostname);
  if (cached && cached.expiresAt > Date.now()) return cached.ip;
  if (_dohInFlight.has(hostname)) return _dohInFlight.get(hostname);
  const p = (async () => {
    // Use HTTPS DoH endpoints whose hostnames are already known IPs so we
    // don't recurse the DoH-via-DoH problem. alidns public IP + Cloudflare.
    const dohEndpoints = [
      { url: `https://dns.alidns.com/resolve?name=${encodeURIComponent(hostname)}&type=A`, ip: '223.5.5.5' },
      { url: `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`, ip: '1.1.1.1' },
    ];
    for (const { url, ip } of dohEndpoints) {
      try {
        const u = new URL(url);
        // Connect to the literal IP, but use the original hostname for SNI/Host.
        const r = await new Promise((resolve, reject) => {
          const req = httpsRequest({
            hostname: ip,
            port: 443,
            path: u.pathname + u.search,
            method: 'GET',
            headers: { 'Host': u.host, 'Accept': 'application/dns-json' },
            timeout: 5000,
          }, resolve);
          req.on('error', reject);
          req.on('timeout', () => req.destroy(new Error('DoH timeout')));
          req.end();
        });
        if (r.statusCode !== 200) { r.resume(); continue; }
        const chunks = [];
        for await (const c of r) chunks.push(c);
        const j = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const answer = j?.Answer?.find(a => a.type === 1)?.data;
        if (answer) {
          _dohCache.set(hostname, { ip: answer, expiresAt: Date.now() + DOH_TTL_MS });
          return answer;
        }
      } catch {}
    }
    throw new Error(`DoH resolve failed for ${hostname}`);
  })();
  _dohInFlight.set(hostname, p);
  try { return await p; } finally { _dohInFlight.delete(hostname); }
}

// Extract Aliyun Action from a path like "/?Action=DescribeInstances"
// or "/DescribeInstances" (for ECS-style), or from the request query.
// The broker.yaml maps service→Action via `action` field; if not set,
// the path query or the proxy request query is used.
function getAliyunAction(path, serviceCfg, query) {
  if (serviceCfg.action) return serviceCfg.action;
  try {
    const u = new URL(path, 'http://x/');
    if (u.searchParams.get('Action')) return u.searchParams.get('Action');
  } catch {}
  if (query && query.Action) return String(query.Action);
  return null;
}


async function callUpstream(serviceCfg, method, path, query, headers, body, opts = {}) {
  // Resolve all secrets used by this service
  const injectHeaders = { ...(serviceCfg.inject_headers || {}) };
  let url = null;

  if (serviceCfg.type === 'bearer' || serviceCfg.type === 'github_token' || serviceCfg.type === 'header') {
    // Simple bearer/header auth: resolve a single secret and inject as header.
    // `name` is added by the admin service test endpoint; fall back to the
    // route-level name (passed via opts) for clarity in error messages.
    const svcNameForErr = serviceCfg.name || opts?.serviceName || '?';
    if (!serviceCfg.token_secret) throw new Error(`Service ${svcNameForErr} missing token_secret`);
    const token = getSecretField(serviceCfg.token_secret, serviceCfg.token_field);
    if (!token) throw new Error(`Secret ${serviceCfg.token_secret} field=${serviceCfg.token_field || '(default)'} not loaded`);
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
      // sops-based: prefer one structured secret (aliyun_ak type) with two fields;
      // fall back to two separate legacy secrets (access_key_secret + access_secret_secret).
      if (serviceCfg.ak_secret) {
        const ak = getSecretField(serviceCfg.ak_secret, serviceCfg.ak_id_field || 'access_key_id');
        const sk = getSecretField(serviceCfg.ak_secret, serviceCfg.ak_secret_field || 'access_key_secret');
        if (!ak || !sk) throw new Error(`Aliyun secret ${serviceCfg.ak_secret} missing required fields`);
        creds = { accessKeyId: ak, accessKeySecret: sk };
      } else {
        const ak = getSecretField(serviceCfg.access_key_secret, 'value');
        const sk = getSecretField(serviceCfg.access_secret_secret, 'value');
        if (!ak || !sk) throw new Error('Aliyun access_key or access_secret not loaded');
        creds = { accessKeyId: ak, accessKeySecret: sk };
      }
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
  // Workaround for ECS environments where outbound UDP/53 to public DNS
  // is blocked (c-ares fails with ENOTFOUND). Pre-resolve via DNS-over-HTTPS
  // (which goes over TCP 443) and connect to the IP directly.
  const ip = url.protocol === 'https:' ? await resolveHostnameDoH(url.hostname) : url.hostname;
  const isHttps = url.protocol === 'https:';
  const requestLib = isHttps ? httpsRequest : httpRequest;
  const upstreamResp = await new Promise((resolve, reject) => {
    const req = requestLib({
      protocol: url.protocol,
      hostname: ip,
      port: url.port || (isHttps ? 443 : 80),
      method: method || 'GET',
      path: url.pathname + url.search,
      headers: outHeaders,  // Host: url.host set above
      timeout: 15000,
    }, resolve);
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Upstream timeout')));
    if (fetchOpts.body) req.write(fetchOpts.body);
    req.end();
  });
  const latency = Date.now() - start;

  // Read response (https.request returns IncomingMessage with plain headers object)
  const respHeaders = {};
  for (const [k, v] of Object.entries(upstreamResp.headers)) {
    respHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
  }
  // strip hop-by-hop
  delete respHeaders['transfer-encoding'];
  delete respHeaders['connection'];
  delete respHeaders['keep-alive'];
  delete respHeaders['content-encoding'];  // 避免 content-length mismatch

  // IncomingMessage has no .arrayBuffer(); collect from 'data' events.
  const chunks = [];
  for await (const chunk of upstreamResp) chunks.push(chunk);
  const respBuf = Buffer.concat(chunks);
  return {
    status: upstreamResp.statusCode,
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
  // Whitelist explicit files; do NOT serve arbitrary paths to keep the attack surface tight.
  if (m === 'GET' && (
    p === '/' || p === '/index.html' || p === '/app.js' || p === '/style.css' || p === '/home.js' ||
    p === '/me.html' || p === '/me.js' ||
    p === '/api-keys.html' || p === '/api-keys.js' ||
    p === '/admin/secrets.js' || p === '/admin/services.js' || p === '/admin/clients.js' ||
    p === '/admin/audit.js'
  )) {
    const map = {
      '/': 'index.html',
      '/index.html': 'index.html',
      '/app.js': 'app.js',
      '/style.css': 'style.css',
      '/home.js': 'home.js',
      '/me.html': 'me.html',
      '/me.js': 'me.js',
      '/api-keys.html': 'api-keys.html',
      '/api-keys.js': 'api-keys.js',
      '/admin/secrets.js': 'admin/secrets.js',
      '/admin/services.js': 'admin/services.js',
      '/admin/clients.js': 'admin/clients.js',
      '/admin/audit.js': 'admin/audit.js',
    };
    const f = join(__dirname, 'dashboard', map[p]);
    if (existsSync(f)) {
      const body = readFileSync(f);
      const ct = p.endsWith('.js') ? 'application/javascript; charset=utf-8'
               : p.endsWith('.css') ? 'text/css; charset=utf-8'
               : 'text/html; charset=utf-8';
      res.writeHead(200, {
        'Content-Type': ct,
        // dashboard 是动态产物，禁止 CDN/浏览器缓存，避免更新后拿到旧版
        'Cache-Control': 'no-cache, must-revalidate',
      });
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
    const ok = await verifyClientPassword(password, targetClient.password);
    if (!ok) {
      recordLoginFail(lockKey);
      audit({ action: 'login', status: 'denied', reason: 'bad_password', client: lockKey });
      return jsonError(res, 401, 'Bad password');
    }
    clearLoginLock(lockKey);

    // v3.0: MFA 状态机 — 启 TOTP 的 client 必须二次验证
    const fp = ctx0 ? ctx0.fp : null;
    if (isMfaRequired(targetClient, via)) {
      const mfaToken = createMfaPending(targetName, fp);
      audit({ action: 'login', status: 'mfa_required', client: targetName, via });
      return send(res, 200, {
        ok: false,
        mfa_required: true,
        mfa_token: mfaToken,
        expires_in: MFA_TOKEN_TTL_MS / 1000,
        method: via,
      });
    }

    const cn = ctx0 ? ctx0.cn : `${targetName}@web`;
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

  // ----- POST /api/v1/login/mfa: 提交 TOTP code 完成登录 -----
  if (m === 'POST' && p === '/api/v1/login/mfa') {
    const body = await readBody(req) || {};
    const { mfa_token: mfaToken, code } = body;
    if (!mfaToken || !code) return jsonError(res, 400, 'Missing {mfa_token, code}');
    const pending = getMfaPending(mfaToken);
    if (!pending) {
      audit({ action: 'login_mfa', status: 'denied', reason: 'invalid_token' });
      return jsonError(res, 401, 'Invalid or expired mfa_token');
    }
    const targetClient = CONFIG.clients[pending.clientName];
    if (!targetClient) {
      consumeMfaPending(mfaToken);
      audit({ action: 'login_mfa', status: 'denied', reason: 'client_gone', client: pending.clientName });
      return jsonError(res, 404, 'Client no longer exists');
    }
    const mfaResult = verifyMfaCode(targetClient, code);
    if (!mfaResult.ok) {
      audit({ action: 'login_mfa', status: 'denied', reason: 'bad_code', client: pending.clientName });
      return jsonError(res, 401, 'Bad TOTP code or recovery code');
    }
    consumeMfaPending(mfaToken);
    const cn = pending.fp ? `${pending.clientName}@mtls` : `${pending.clientName}@web`;
    const token = makeSession({ cn, fp: pending.fp, role: targetClient.role, clientName: pending.clientName, cert: { subject: { CN: cn } }, client: targetClient });
    audit({ action: 'login', status: 'ok', cn, client: pending.clientName, via: 'mfa', mfa_method: mfaResult.method });
    res.setHeader('Set-Cookie', `broker_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
    return send(res, 200, {
      token,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      cn,
      role: targetClient.role,
      via: 'mfa',
      mfa_method: mfaResult.method,
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

  // ============================================================
  // v3.0: Self-service (我的资料) — 任何已登录 client 都能用
  // ============================================================
  // GET    /api/v1/me                      — 我的资料
  // POST   /api/v1/me/change-password     — 改密码
  // POST   /api/v1/me/rotate-cert          — 重发我的 cert
  // GET    /api/v1/me/audit                — 我的活动 (audit log)
  // POST   /api/v1/me/totp/setup           — 启 TOTP, 返回 otpauth + 10 个恢复码
  // POST   /api/v1/me/totp/verify          — 验证 TOTP 正确性（setup 完必走）
  // POST   /api/v1/me/totp/disable         — 关 TOTP
  // GET    /api/v1/me/recovery-codes/remaining — 看还剩几个恢复码

  // ----- GET /api/v1/me -----
  if (m === 'GET' && p === '/api/v1/me') {
    const c = ctx.client;
    const cp = certPaths.clientPaths(ctx.clientName);
    const certOnDisk = existsSync(cp.crt) && existsSync(cp.key);
    return send(res, 200, {
      name: ctx.clientName,
      cn: ctx.cn,
      role: c.role,
      description: c.description || '',
      allow_password_login: !!c.allow_password_login,
      has_password: !!c.password,
      password_set_at: c.password_set_at || null,
      password_expires_at: c.password_expires_at || null,
      totp_enabled: !!c.totp_secret,
      totp_enabled_at: c.totp_enabled_at || null,
      totp_recovery_codes_remaining: (c.totp_recovery_codes_hash || []).length,
      preferred_2fa: c.preferred_2fa || (c.totp_secret ? 'totp' : 'none'),
      cert_fingerprint_sha256: c.cert_fingerprint_sha256 || null,
      cert_present_on_disk: certOnDisk,
      cert_expires_at: c.cert_expires_at || null,
      last_password_change: c.last_password_change || null,
      last_cert_rotation: c.last_cert_rotation || null,
      rate_limit: c.rate_limit || '100/hour',
    });
  }

  // ----- POST /api/v1/me/change-password -----
  if (m === 'POST' && p === '/api/v1/me/change-password') {
    const body = await readBody(req) || {};
    const { old_password: oldPwd, new_password: newPwd } = body;
    if (!oldPwd || !newPwd) return jsonError(res, 400, 'Missing {old_password, new_password}');
    if (newPwd.length < 12) return jsonError(res, 400, 'new_password too short (min 12 chars)');
    const c = ctx.client;
    if (!c.password) return jsonError(res, 400, 'No password set for this client');
    const oldOk = verifyClientPassword(oldPwd, c.password);
    if (!oldOk) {
      audit({ action: 'me_change_password', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_old' });
      return jsonError(res, 401, 'Old password incorrect');
    }
    c.password = hashPassword(newPwd);
    c.password_set_at = new Date().toISOString();
    c.last_password_change = c.password_set_at;
    try {
      await persistConfig();
    } catch (e) {
      audit({ action: 'me_change_password', cn: ctx.cn, fp: ctx.fp, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'me_change_password', cn: ctx.cn, fp: ctx.fp, status: 'ok' });
    return send(res, 200, { ok: true, password_set_at: c.password_set_at });
  }

  // ----- POST /api/v1/me/rotate-cert -----
  // v3.0: 重发自己的 cert（要当前 TOTP 验证或密码）
  if (m === 'POST' && p === '/api/v1/me/rotate-cert') {
    const body = await readBody(req) || {};
    const verify = body.verify;  // TOTP code 或 密码
    if (!verify) return jsonError(res, 400, 'Missing {verify}');
    const c = ctx.client;
    // 验证：TOTP 优先，fallback 密码
    let verified = false;
    if (/^\d{6}$/.test(verify) && c.totp_secret) {
      const mfaResult = verifyMfaCode(c, verify);
      if (mfaResult.ok) verified = true;
    }
    if (!verified && c.password) {
      verified = verifyClientPassword(verify, c.password);
    }
    if (!verified) {
      audit({ action: 'me_rotate_cert', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_verify' });
      return jsonError(res, 401, 'Invalid TOTP code or password');
    }
    if (!clientsDirWritable()) {
      return jsonError(res, 503, 'pki/clients/ is not writable; issue cert out-of-band');
    }
    let cert;
    try { cert = await issueAndPersist(ctx.clientName); }
    catch (e) {
      audit({ action: 'me_rotate_cert', cn: ctx.cn, fp: ctx.fp, status: 'error', error: e.message });
      return jsonError(res, 500, `Issue failed: ${e.message}`);
    }
    c.cert_expires_at = new Date(Date.now() + 90 * 86400 * 1000).toISOString();  // 90 天
    c.last_cert_rotation = c.cert_expires_at;
    try { await persistConfig(); } catch (e) { /* cert 已在 issueAndPersist 持久化了 */ }
    audit({ action: 'me_rotate_cert', cn: ctx.cn, fp: ctx.fp, status: 'ok' });
    return send(res, 200, {
      ok: true,
      name: ctx.clientName,
      fingerprint_sha256: cert.fingerprint_sha256,
      cert_pem: cert.cert_pem,
      key_pem: cert.key_pem,
      cert_expires_at: c.cert_expires_at,
      warning: 'key_pem is a SECRET. Save it now — broker will not return it again.',
    });
  }

  // ----- GET /api/v1/me/audit -----
  if (m === 'GET' && p === '/api/v1/me/audit') {
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 1000);
    const since = url.searchParams.get('since');
    const lines = readAuditFiltered({ fp: ctx.fp, since, limit });
    return send(res, 200, { events: lines, count: lines.length, fp: ctx.fp });
  }

  // ----- POST /api/v1/me/totp/setup -----
  // 启 TOTP: 要当前密码 (一次性验证)，返 otpauth URL + 10 个恢复码
  // 进入"待激活"状态，必须 /totp/verify 一次正确码才正式启用
  if (m === 'POST' && p === '/api/v1/me/totp/setup') {
    const body = await readBody(req) || {};
    const { password } = body;
    if (!password) return jsonError(res, 400, 'Missing {password}');
    const c = ctx.client;
    if (!c.password) return jsonError(res, 400, 'No password set; cannot setup TOTP');
    if (!verifyClientPassword(password, c.password)) {
      audit({ action: 'me_totp_setup', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_password' });
      return jsonError(res, 401, 'Password incorrect');
    }
    if (c.totp_secret) {
      return jsonError(res, 409, 'TOTP already enabled; disable first');
    }
    const secret = generateSecret();
    const recoveryCodes = generateRecoveryCodes();
    const recoveryHashes = recoveryCodes.map(hashRecoveryCode);
    // 暂存到"待激活"字段（不写入 totp_secret 主字段，直到 verify 成功）
    c._pending_totp = {
      secret,
      recovery_hashes: recoveryHashes,
      recovery_codes_plain: recoveryCodes,  // 只这一次返给用户
      setup_at: new Date().toISOString(),
    };
    audit({ action: 'me_totp_setup', cn: ctx.cn, fp: ctx.fp, status: 'pending' });
    return send(res, 200, {
      ok: true,
      otpauth_url: buildOtpauthURL(ctx.clientName, 'SecretBroker', secret),
      secret,  // 让用户能手动输入 (无 App 也能登)
      recovery_codes: recoveryCodes,  // 仅此一次
      recovery_codes_remaining: recoveryCodes.length,
      next_step: 'POST /api/v1/me/totp/verify with a TOTP code to activate',
    });
  }

  // ----- POST /api/v1/me/totp/verify -----
  // setup 后必须 verify 一次才正式启用
  if (m === 'POST' && p === '/api/v1/me/totp/verify') {
    const body = await readBody(req) || {};
    const { code } = body;
    if (!code) return jsonError(res, 400, 'Missing {code}');
    const c = ctx.client;
    if (!c._pending_totp) return jsonError(res, 400, 'No pending TOTP setup; call /totp/setup first');
    const ok = verifyTotpFn(c._pending_totp.secret, code);
    if (!ok) {
      audit({ action: 'me_totp_verify', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_code' });
      return jsonError(res, 401, 'TOTP code does not match');
    }
    // 激活：pending → 正式字段
    c.totp_secret = c._pending_totp.secret;
    c.totp_enabled_at = new Date().toISOString();
    c.totp_recovery_codes_hash = c._pending_totp.recovery_hashes;
    c.preferred_2fa = 'totp';
    delete c._pending_totp;
    try { await persistConfig(); }
    catch (e) {
      audit({ action: 'me_totp_verify', cn: ctx.cn, fp: ctx.fp, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'me_totp_verify', cn: ctx.cn, fp: ctx.fp, status: 'ok' });
    return send(res, 200, {
      ok: true,
      totp_enabled_at: c.totp_enabled_at,
      recovery_codes_remaining: c.totp_recovery_codes_hash.length,
    });
  }

  // ----- POST /api/v1/me/totp/disable -----
  // 关 TOTP 要当前 TOTP code 或 恢复码
  if (m === 'POST' && p === '/api/v1/me/totp/disable') {
    const body = await readBody(req) || {};
    const { code } = body;
    if (!code) return jsonError(res, 400, 'Missing {code}');
    const c = ctx.client;
    if (!c.totp_secret) return jsonError(res, 400, 'TOTP not enabled');
    const mfaResult = verifyMfaCode(c, code);
    if (!mfaResult.ok) {
      audit({ action: 'me_totp_disable', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_code' });
      return jsonError(res, 401, 'TOTP code or recovery code invalid');
    }
    delete c.totp_secret;
    delete c.totp_enabled_at;
    delete c.totp_recovery_codes_hash;
    c.preferred_2fa = 'none';
    try { await persistConfig(); }
    catch (e) {
      audit({ action: 'me_totp_disable', cn: ctx.cn, fp: ctx.fp, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'me_totp_disable', cn: ctx.cn, fp: ctx.fp, status: 'ok', mfa_method: mfaResult.method });
    return send(res, 200, { ok: true, totp_disabled: true });
  }

  // ----- GET /api/v1/me/recovery-codes/remaining -----
  if (m === 'GET' && p === '/api/v1/me/recovery-codes/remaining') {
    const c = ctx.client;
    return send(res, 200, {
      remaining: (c.totp_recovery_codes_hash || []).length,
      warning: c.totp_recovery_codes_hash && c.totp_recovery_codes_hash.length < 3
        ? 'Few recovery codes left. Consider re-setup.'
        : undefined,
    });
  }

  // ============================================================
  // v3.0 M2: API Key 管理 (admin + self)
  // ============================================================
  // GET    /api/v1/api-keys                 — 列表 (admin: 全部; self: 自己的)
  // POST   /api/v1/api-keys                 — 创建 (需 TOTP, admin 或 self)
  // GET    /api/v1/api-keys/:id             — 详情
  // DELETE /api/v1/api-keys/:id            — 撤销 (需 TOTP)
  // GET    /api/v1/api-keys/:id/usage       — 最近 100 次使用 (admin only)
  //
  // 静态路由必须先于动态路由

  // ----- GET /api/v1/api-keys -----
  if (m === 'GET' && p === '/api/v1/api-keys') {
    const opts = ctx.client.role === 'admin' ? {} : { clientOnly: ctx.clientName };
    return send(res, 200, { keys: listApiKeysFn(CONFIG.api_keys, opts) });
  }

  // ----- POST /api/v1/api-keys -----
  if (m === 'POST' && p === '/api/v1/api-keys') {
    const body = await readBody(req) || {};
    const name = (body.name || '').trim();
    if (!name) return jsonError(res, 400, 'Missing {name}');
    // 创建者 = 自己 (admin 可指定 client)
    const targetClient = body.client && ctx.client.role === 'admin'
      ? body.client : ctx.clientName;
    if (!CONFIG.clients[targetClient]) {
      return jsonError(res, 400, `Unknown client: ${targetClient}`);
    }
    // 二次验证: 当前 TOTP code (强制)
    const verifyCode = body.verify;
    if (!verifyCode) return jsonError(res, 400, 'Missing {verify} (TOTP code)');
    // self 验证: 自己的 totp
    let verified = false;
    if (/^\d{6}$/.test(verifyCode) && ctx.client.totp_secret) {
      const mfaR = verifyMfaCode(ctx.client, verifyCode);
      if (mfaR.ok) verified = true;
    }
    // admin 没 TOTP 时允许用密码
    if (!verified && ctx.client.role === 'admin' && ctx.client.password) {
      verified = verifyClientPassword(verifyCode, ctx.client.password);
    }
    if (!verified) {
      audit({ action: 'api_key_create', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: 'bad_verify' });
      return jsonError(res, 401, 'Invalid TOTP code or password');
    }
    const opts = {
      scopes: Array.isArray(body.scopes) ? body.scopes : undefined,
      allowed_secrets: Array.isArray(body.allowed_secrets) ? body.allowed_secrets : undefined,
      allowed_services: Array.isArray(body.allowed_services) ? body.allowed_services : undefined,
      rate_limit: body.rate_limit,
      ip_whitelist: Array.isArray(body.ip_whitelist) ? body.ip_whitelist : null,
      ttl_ms: body.ttl_seconds ? body.ttl_seconds * 1000 : undefined,
      created_by: ctx.clientName,
    };
    const r = createApiKeyFn(CONFIG.api_keys, name, targetClient, opts);
    try { await persistConfig(); } catch (e) {
      // 回滚
      const idx = CONFIG.api_keys.findIndex(k => k.id === r.key_obj.id);
      if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
      audit({ action: 'api_key_create', cn: ctx.cn, fp: ctx.fp, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'api_key_create', cn: ctx.cn, fp: ctx.fp, name, client: targetClient, status: 'ok' });
    return send(res, 200, {
      ok: true,
      key: r.key_obj,    // public view
      secret: r.secret,  // 仅此一次返回
      warning: 'secret will not be shown again. Save it now.',
    });
  }

  // ----- GET /api/v1/api-keys/:id (静态优先, 必须在 :id/usage 之前) -----
  const apiKeyMatch = p.match(/^\/api\/v1\/api-keys\/([a-z0-9]{16})$/);
  const apiKeyUsageMatch = p.match(/^\/api\/v1\/api-keys\/([a-z0-9]{16})\/usage$/);
  if (m === 'GET' && apiKeyMatch && apiKeyMatch[1]) {
    const id = apiKeyMatch[1];
    const k = CONFIG.api_keys.find(x => x.id === id);
    if (!k) return jsonError(res, 404, `API key ${id} not found`);
    if (ctx.client.role !== 'admin' && k.client !== ctx.clientName) {
      return jsonError(res, 403, 'Not your API key');
    }
    return send(res, 200, { key: publicViewFn(k) });
  }

  // ----- DELETE /api/v1/api-keys/:id -----
  if (m === 'DELETE' && apiKeyMatch && apiKeyMatch[1]) {
    const id = apiKeyMatch[1];
    const k = CONFIG.api_keys.find(x => x.id === id);
    if (!k) return jsonError(res, 404, `API key ${id} not found`);
    if (ctx.client.role !== 'admin' && k.client !== ctx.clientName) {
      return jsonError(res, 403, 'Not your API key');
    }
    const body = await readBody(req) || {};
    const verifyCode = body.verify;
    if (!verifyCode) return jsonError(res, 400, 'Missing {verify}');
    let verified = false;
    if (/^\d{6}$/.test(verifyCode) && ctx.client.totp_secret) {
      const mfaR = verifyMfaCode(ctx.client, verifyCode);
      if (mfaR.ok) verified = true;
    }
    if (!verified && ctx.client.role === 'admin' && ctx.client.password) {
      verified = verifyClientPassword(verifyCode, ctx.client.password);
    }
    if (!verified) {
      audit({ action: 'api_key_revoke', cn: ctx.cn, fp: ctx.fp, name: k.name, status: 'denied', reason: 'bad_verify' });
      return jsonError(res, 401, 'Invalid TOTP code or password');
    }
    const r = revokeApiKeyFn(CONFIG.api_keys, id, ctx.clientName);
    if (!r.ok) {
      return jsonError(res, 400, r.reason);
    }
    try { await persistConfig(); } catch (e) {
      audit({ action: 'api_key_revoke', cn: ctx.cn, fp: ctx.fp, name: k.name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'api_key_revoke', cn: ctx.cn, fp: ctx.fp, name: k.name, status: 'ok' });
    return send(res, 200, { ok: true, id, revoked_at: k.revoked_at });
  }

  // ----- GET /api/v1/api-keys/:id/usage -----
  if (m === 'GET' && apiKeyUsageMatch && apiKeyUsageMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    const id = apiKeyUsageMatch[1];
    const k = CONFIG.api_keys.find(x => x.id === id);
    if (!k) return jsonError(res, 404, `API key ${id} not found`);
    // 查 audit log 按 cn=clientName + action=proxy 过滤
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 1000);
    const lines = readAuditFiltered({ fp: k.id ? `apikey:${k.id}` : null, since: null, limit });
    return send(res, 200, { id, name: k.name, use_count: k.use_count, last_used_at: k.last_used_at, events: lines });
  }

  // ============================================================
  // v3.0 M3.3: Master Key (给 MCP Server / OpenClaw auto-refresh 用)
  // ============================================================
  // POST /api/v1/api-keys/master          — 创建 master key (admin + TOTP)
  // GET  /api/v1/api-keys/master          — 列出所有 master key (admin)
  // POST /api/v1/api-keys/issue-child     — 用 master key 创建子 key (api_key with can_create_child)

  // ----- POST /api/v1/api-keys/master -----
  if (m === 'POST' && p === '/api/v1/api-keys/master') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    const body = await readBody(req) || {};
    const name = (body.name || '').trim();
    if (!name) return jsonError(res, 400, 'Missing {name}');
    // TOTP 强制
    const verifyCode = body.verify;
    if (!verifyCode) return jsonError(res, 400, 'Missing {verify} (TOTP code)');
    let verified = false;
    if (/^\d{6}$/.test(verifyCode) && ctx.client.totp_secret) {
      if (verifyMfaCode(ctx.client, verifyCode).ok) verified = true;
    }
    if (!verified && ctx.client.password) {
      verified = verifyClientPassword(verifyCode, ctx.client.password);
    }
    if (!verified) {
      audit({ action: 'master_key_create', cn: ctx.cn, fp: ctx.fp, name, status: 'denied', reason: 'bad_verify' });
      return jsonError(res, 401, 'Invalid TOTP code or password');
    }
    const { id, secret, key_obj } = generateMasterKey(name, ctx.clientName, {
      default_child_ttl_seconds: body.default_child_ttl_seconds,
      child_scopes: Array.isArray(body.child_scopes) ? body.child_scopes : undefined,
      rate_limit: body.rate_limit,
      ip_whitelist: Array.isArray(body.ip_whitelist) ? body.ip_whitelist : null,
      ttl_ms: body.ttl_ms,
      created_by: ctx.clientName,
    });
    CONFIG.api_keys.push(key_obj);
    try { await persistConfig(); } catch (e) {
      const idx = CONFIG.api_keys.findIndex(x => x.id === id);
      if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
      audit({ action: 'master_key_create', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'master_key_create', cn: ctx.cn, fp: ctx.fp, name, status: 'ok', id });
    return send(res, 200, {
      ok: true,
      key: publicViewFn(key_obj),
      secret,
      warning: 'Master key will not be shown again. Save it now. Use POST /api/v1/api-keys/issue-child to mint short-lived child keys.',
    });
  }

  // ----- GET /api/v1/api-keys/master -----
  if (m === 'GET' && p === '/api/v1/api-keys/master') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    const masters = (CONFIG.api_keys || []).filter(k => k.is_master);
    return send(res, 200, { keys: masters.map(publicViewFn) });
  }

  // ----- POST /api/v1/api-keys/issue-child -----
  if (m === 'POST' && p === '/api/v1/api-keys/issue-child') {
    // 必须用 API Key (Bearer) + is_master + can_create_child
    if (ctx.via !== 'api_key') {
      return jsonError(res, 401, 'This endpoint requires Master API Key (Authorization: Bearer ...)');
    }
    const master = ctx.apiKey;
    const check = canCreateChild(master);
    if (!check.ok) {
      audit({ action: 'issue_child', cn: ctx.cn, fp: ctx.fp, status: 'denied', reason: check.reason });
      return jsonError(res, 403, `Master key cannot create child: ${check.reason}`);
    }
    const body = await readBody(req) || {};
    const name = (body.name || '').trim() || `child-${Date.now()}`;
    const r = createChildKey(CONFIG.api_keys, master, name, {
      scopes: Array.isArray(body.scopes) ? body.scopes : undefined,
      allowed_secrets: Array.isArray(body.allowed_secrets) ? body.allowed_secrets : undefined,
      allowed_services: Array.isArray(body.allowed_services) ? body.allowed_services : undefined,
      rate_limit: body.rate_limit,
      ip_whitelist: Array.isArray(body.ip_whitelist) ? body.ip_whitelist : undefined,
      ttl_seconds: body.ttl_seconds ? parseInt(body.ttl_seconds, 10) : undefined,
    });
    if (!r.ok) {
      audit({ action: 'issue_child', cn: ctx.cn, fp: ctx.fp, name, status: 'error', reason: r.reason });
      return jsonError(res, 400, `Cannot create child: ${r.reason}`);
    }
    try { await persistConfig(); } catch (e) {
      const idx = CONFIG.api_keys.findIndex(x => x.id === r.key_obj.id);
      if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
      audit({ action: 'issue_child', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'issue_child', cn: ctx.cn, fp: ctx.fp, name, child_id: r.key_obj.id, status: 'ok' });
    return send(res, 200, {
      ok: true,
      key: r.key_obj,
      secret: r.secret,
      warning: 'Child key will not be shown again. It will expire in ttl_seconds.',
      parent_master_id: master.id,
    });
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
    // For admin, return full secret metadata (type, description, rotation info).
    // For non-admin, return only names (legacy behavior).
    if (ctx.client.role === 'admin') {
      const out = visible.map(name => {
        const meta = SECRET_CACHE.get(name);
        if (!meta) return { name };
        return {
          name,
          type: meta.type,
          description: meta.description,
          created_at: meta.created_at,
          updated_at: meta.updated_at,
          last_rotated_at: meta.last_rotated_at || meta.updated_at,
          rotation_policy_days: meta.rotation_policy_days,
          updated_by: meta.updated_by,
        };
      });
      return send(res, 200, { secrets: out });
    }
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
    const entry = getSecret(body.name);
    if (!entry) {
      audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, status: 'not_found' });
      return jsonError(res, 404, `Secret ${body.name} not loaded`);
    }
    const field = body.field;
    if (field) {
      const v = entry.fields?.[field];
      if (v === undefined) {
        return jsonError(res, 404, `Field ${field} not found in secret ${body.name}`);
      }
      audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, field, status: 'ok' });
      return send(res, 200, { name: body.name, field, value: v, type: entry.type });
    }
    // No field specified: return a `value` that's always a non-empty string for backward compat.
    // - single field (named "value" or any single field): return that value
    // - multi-field: return JSON of all fields
    // Plus always include `fields` for apps that want structured access.
    const fieldNames = Object.keys(entry.fields || {});
    let value = '';
    if (fieldNames.length === 1) {
      const v = entry.fields[fieldNames[0]];
      value = v === null || v === undefined ? '' : String(v);
    } else if (fieldNames.length > 1) {
      // multi-field: serialize as JSON for the legacy `value` consumers (e.g. old CLI `get`)
      value = JSON.stringify(entry.fields);
    }
    audit({ action: 'resolve', cn: ctx.cn, fp: ctx.fp, secret: body.name, status: 'ok' });
    return send(res, 200, { name: body.name, type: entry.type, value, fields: entry.fields });
  }

  // ============================================================
  // Admin: Secrets CRUD (Phase 1.1.1)
  // All endpoints below require admin role.
  // Storage: secrets-detail.json (SOPS-encrypted JSON, structured per-type)
  // Body shapes:
  //   POST: { name, type, description?, fields: { ... } }
  //   PUT:  { type?, description?, fields?: { ... } }
  //   GET:  returns full entry { name, type, description, fields, created_at, ... }
  // ============================================================

  // ----- GET /api/v1/admin/secrets -----
  if (m === 'GET' && p === '/api/v1/admin/secrets') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const out = [];
    for (const [name, entry] of SECRET_CACHE.entries()) {
      out.push({
        name,
        type: entry.type || 'custom',
        description: entry.description || '',
        fields: entry.fields || {},
        created_at: entry.created_at || null,
        updated_at: entry.updated_at || null,
        updated_by: entry.updated_by || null,
        last_rotated_at: entry.last_rotated_at || entry.updated_at || null,
        rotation_policy_days: entry.rotation_policy_days || null,
      });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    audit({ action: 'admin_secrets_list', cn: ctx.cn, fp: ctx.fp, count: out.length });
    return send(res, 200, { secrets: out });
  }

  // ----- GET /api/v1/admin/types : return type schemas (so UI can render form dynamically) -----
  if (m === 'GET' && p === '/api/v1/admin/types') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const out = {};
    for (const [id, schema] of Object.entries(TYPE_SCHEMAS)) {
      out[id] = { label: schema.label, description: schema.description, fields: schema.fields };
    }
    return send(res, 200, { types: out });
  }

  // ----- POST /api/v1/admin/secrets (create) -----
  if (m === 'POST' && p === '/api/v1/admin/secrets') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const body = await readBody(req) || {};
    const { name, type, description, fields } = body;
    if (!isValidSecretName(name)) {
      return jsonError(res, 400, 'Invalid secret name. Use [A-Za-z0-9_.-], must start with letter/digit/underscore, max 128 chars.');
    }
    if (!type || !ALLOWED_SECRET_TYPES.has(type)) {
      return jsonError(res, 400, `Unknown type: ${type}`);
    }
    if (!fields || typeof fields !== 'object') {
      return jsonError(res, 400, 'Missing {fields: object}');
    }
    const errs = validateFields(type, fields);
    if (errs.length > 0) {
      return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
    }
    if (SECRET_CACHE.has(name)) {
      audit({ action: 'admin_secrets_create', cn: ctx.cn, fp: ctx.fp, name, status: 'denied', reason: 'already_exists' });
      return jsonError(res, 409, `Secret ${name} already exists. Use PUT to update.`);
    }
    const now = new Date().toISOString();
    const who = ctx.cn || 'admin';
    SECRET_CACHE.set(name, {
      type, description: description || '', fields,
      created_at: now, updated_at: now, updated_by: who,
    });
    try {
      await persistSecretsDetail();
    } catch (e) {
      SECRET_CACHE.delete(name);
      audit({ action: 'admin_secrets_create', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_secrets_create', cn: ctx.cn, fp: ctx.fp, name, type, status: 'ok' });
    return send(res, 200, { ok: true, name, type });
  }

  // ----- PUT /api/v1/admin/secrets/:name (update) -----
  // Match the create endpoint's SECRET_NAME_RE exactly, so any name POST accepts
  // is also routable via PUT/DELETE. The previous hard-coded `[A-Za-z0-9_.]+`
  // silently 404'd for names containing hyphens (e.g. `aliyun-1786567607488`).
  const updateMatch = p.match(/^\/api\/v1\/admin\/secrets\/([A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})$/);
  if (m === 'PUT' && updateMatch && updateMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = updateMatch[1];
    const existing = SECRET_CACHE.get(name);
    if (!existing) return jsonError(res, 404, `Secret ${name} not found`);
    const body = await readBody(req) || {};
    const updated = { ...existing };
    if (body.type !== undefined) {
      if (!ALLOWED_SECRET_TYPES.has(body.type)) return jsonError(res, 400, `Unknown type: ${body.type}`);
      updated.type = body.type;
    }
    if (body.description !== undefined) {
      updated.description = String(body.description);
    }
    if (body.fields !== undefined) {
      if (typeof body.fields !== 'object') return jsonError(res, 400, '{fields} must be an object');
      // Merge: client may send partial fields (e.g. only one field in a multi-field secret)
      updated.fields = { ...existing.fields, ...body.fields };
    }
    // Re-validate after merge
    const errs = validateFields(updated.type, updated.fields);
    if (errs.length > 0) {
      return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
    }
    updated.updated_at = new Date().toISOString();
    updated.updated_by = ctx.cn || 'admin';
    const prevSnapshot = JSON.parse(JSON.stringify(existing));
    SECRET_CACHE.set(name, updated);
    try {
      await persistSecretsDetail();
    } catch (e) {
      SECRET_CACHE.set(name, prevSnapshot);
      audit({ action: 'admin_secrets_update', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_secrets_update', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ----- DELETE /api/v1/admin/secrets/:name -----
  if (m === 'DELETE' && updateMatch && updateMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = updateMatch[1];
    const existing = SECRET_CACHE.get(name);
    if (!existing) return jsonError(res, 404, `Secret ${name} not found`);
    SECRET_CACHE.delete(name);
    try {
      await persistSecretsDetail();
    } catch (e) {
      // best-effort rollback
      SECRET_CACHE.set(name, existing);
      audit({ action: 'admin_secrets_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_secrets_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ============================================================
  // Phase 1.2: Services CRUD (admin only)
  // ============================================================
  // GET    /api/v1/admin/services             — list all (admin)
  // GET    /api/v1/admin/services/:name       — read one (admin)
  // POST   /api/v1/admin/services             — create
  // PUT    /api/v1/admin/services/:name       — update (full replace of mutable fields)
  // DELETE /api/v1/admin/services/:name       — delete
  // POST   /api/v1/admin/services/:name/test  — trigger one call to verify wiring
  // GET    /api/v1/admin/service-templates    — list 6 built-in templates

  // ----- GET /api/v1/admin/service-templates -----
  if (m === 'GET' && p === '/api/v1/admin/service-templates') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    return send(res, 200, { templates: publicTemplateList() });
  }

  // ----- GET /api/v1/admin/services -----
  if (m === 'GET' && p === '/api/v1/admin/services') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const out = [];
    for (const [name, svc] of Object.entries(CONFIG.services || {})) {
      out.push({
        name,
        type: svc.type || 'unknown',
        description: svc.description || '',
        upstream: svc.upstream || '',
        region: svc.region || '',
        action: svc.action || '',
        token_secret: svc.token_secret || null,
        inject_headers: svc.inject_headers || {},
        header_name: svc.header_name || null,
        header_value_template: svc.header_value_template || null,
        allow_paths: svc.allow_paths || null,
        dashboard_actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
        allowed_clients: clientNamesAllowedFor(name),
        action_count: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions.length : 0,
      });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    audit({ action: 'admin_services_list', cn: ctx.cn, fp: ctx.fp, count: out.length });
    return send(res, 200, { services: out });
  }

  // ----- /api/v1/admin/services/:name + /test routing -----
  // Note: /test has a sub-path, so we match it first. We accept the same
  // SERVICE_NAME_RE for the name segment to stay consistent with POST.
  const svcTestMatch = p.match(/^\/api\/v1\/admin\/services\/([a-z][a-z0-9_-]{0,63})\/test$/);
  const svcMatch     = p.match(/^\/api\/v1\/admin\/services\/([a-z][a-z0-9_-]{0,63})$/);

  // ----- GET /api/v1/admin/services/:name -----
  if (m === 'GET' && svcMatch && svcMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = svcMatch[1];
    const svc = CONFIG.services[name];
    if (!svc) return jsonError(res, 404, `Service ${name} not found`);
    return send(res, 200, {
      name,
      type: svc.type || 'unknown',
      description: svc.description || '',
      upstream: svc.upstream || '',
      region: svc.region || '',
      action: svc.action || '',
      token_secret: svc.token_secret || null,
      inject_headers: svc.inject_headers || {},
      header_name: svc.header_name || null,
      header_value_template: svc.header_value_template || null,
      allow_paths: svc.allow_paths || null,
      dashboard_actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
      allowed_clients: clientNamesAllowedFor(name),
    });
  }

  // ----- POST /api/v1/admin/services (create) -----
  if (m === 'POST' && p === '/api/v1/admin/services') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const body = await readBody(req) || {};
    const name = body.name;
    const cfg = normalizeServiceConfig(body);
    const errs = validateServiceConfig(name, cfg);
    if (errs.length > 0) {
      audit({ action: 'admin_services_create', cn: ctx.cn, fp: ctx.fp, name, status: 'denied', reason: 'validation', errs });
      return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
    }
    if (CONFIG.services[name]) {
      audit({ action: 'admin_services_create', cn: ctx.cn, fp: ctx.fp, name, status: 'denied', reason: 'already_exists' });
      return jsonError(res, 409, `Service ${name} already exists. Use PUT to update.`);
    }
    CONFIG.services[name] = cfg;
    try {
      await persistConfig();
    } catch (e) {
      delete CONFIG.services[name];
      audit({ action: 'admin_services_create', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_services_create', cn: ctx.cn, fp: ctx.fp, name, type: cfg.type, status: 'ok' });
    return send(res, 200, { ok: true, name, type: cfg.type });
  }

  // ----- PUT /api/v1/admin/services/:name (update, PARTIAL) -----
  // PUT semantics here: client sends only the fields they want to change.
  // Fields NOT in the body are preserved from `existing`. This matches the
  // PATCH-like behavior the UI relies on (e.g. "edit description" sends only
  // {description, type, upstream} and expects token_secret / inject_headers
  // to be kept as-is).
  if (m === 'PUT' && svcMatch && svcMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = svcMatch[1];
    const existing = CONFIG.services[name];
    if (!existing) return jsonError(res, 404, `Service ${name} not found`);
    const body = await readBody(req) || {};
    const patch = normalizeServiceConfig(body);
    // Build the next config: existing first, then patch overrides. For
    // array fields, if the client sent an array (even empty), use it as-is;
    // if they sent nothing, preserve the existing array.
    const next = { ...existing, ...patch };
    // Special case: allow_resolve / allowed_proxy as arrays
    if (body.allowed_resolve !== undefined) next.allowed_resolve = patch.allowed_resolve || [];
    if (body.allowed_proxy !== undefined) next.allowed_proxy = patch.allowed_proxy || [];
    if (body.dashboard_actions !== undefined) next.dashboard_actions = patch.dashboard_actions || [];
    if (body.inject_headers !== undefined) next.inject_headers = patch.inject_headers || {};
    // Name is immutable via PUT — keep the URL's name.
    const errs = validateServiceConfig(name, next);
    if (errs.length > 0) {
      audit({ action: 'admin_services_update', cn: ctx.cn, fp: ctx.fp, name, status: 'denied', reason: 'validation', errs });
      return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
    }
    const prev = { ...existing };
    CONFIG.services[name] = next;
    try {
      await persistConfig();
    } catch (e) {
      CONFIG.services[name] = prev;
      audit({ action: 'admin_services_update', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_services_update', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ----- DELETE /api/v1/admin/services/:name -----
  if (m === 'DELETE' && svcMatch && svcMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = svcMatch[1];
    const existing = CONFIG.services[name];
    if (!existing) return jsonError(res, 404, `Service ${name} not found`);
    delete CONFIG.services[name];
    try {
      await persistConfig();
    } catch (e) {
      CONFIG.services[name] = existing;
      audit({ action: 'admin_services_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_services_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ----- POST /api/v1/admin/services/:name/test -----
  // Triggers one read-only call to verify the wiring (upstream reachable,
  // secret loaded, headers injected). Never mutates state.
  if (m === 'POST' && svcTestMatch && svcTestMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = svcTestMatch[1];
    const svc = CONFIG.services[name];
    if (!svc) return jsonError(res, 404, `Service ${name} not found`);
    const body = await readBody(req) || {};
    const method = (body.method || (svc.dashboard_actions && svc.dashboard_actions[0] && svc.dashboard_actions[0].method) || 'GET');
    const path = (body.path || (svc.dashboard_actions && svc.dashboard_actions[0] && svc.dashboard_actions[0].path) || '/');
    const start = Date.now();
    try {
      // Pass the service name so callUpstream's error messages are useful.
      const r = await callUpstream({ ...svc, name }, method, path, body.query, body.headers, body.body, { serviceName: name });
      audit({ action: 'admin_services_test', cn: ctx.cn, fp: ctx.fp, service: name, method, path, upstream_status: r.status, latency_ms: r.latency, status: r.status >= 200 && r.status < 400 ? 'ok' : 'error' });
      return send(res, 200, {
        ok: r.status >= 200 && r.status < 400,
        upstream_status: r.status,
        latency_ms: r.latency,
        body_preview: r.body ? r.body.toString('utf8').slice(0, 500) : '',
      });
    } catch (err) {
      audit({ action: 'admin_services_test', cn: ctx.cn, fp: ctx.fp, service: name, method, path, status: 'error', error: err.message });
      return send(res, 502, { ok: false, error: err.message, latency_ms: Date.now() - start });
    }
  }

  // ============================================================
  // Phase 1.3: Clients CRUD + certificate lifecycle
  // ============================================================
  // GET    /api/v1/admin/clients             — list all
  // GET    /api/v1/admin/clients/:name       — read one
  // POST   /api/v1/admin/clients             — create (no cert yet)
  // PUT    /api/v1/admin/clients/:name       — update config
  // DELETE /api/v1/admin/clients/:name       — delete client (also cert files)
  // POST   /api/v1/admin/clients/:name/enrollment — issue cert, return cert+key
  // POST   /api/v1/admin/clients/:name/rotate     — re-issue cert, return new cert+key
  // POST   /api/v1/admin/clients/:name/revoke    — remove fingerprint from config
  // GET    /api/v1/admin/clients/:name/bundle     — download zip (cert+key+ca+install)

  const clientMatch = p.match(/^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})$/);
  const clientEnrollMatch = p.match(/^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/enrollment$/);
  const clientRotateMatch = p.match(/^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/rotate$/);
  const clientRevokeMatch = p.match(/^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/revoke$/);
  const clientBundleMatch = p.match(/^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/bundle$/);

  // ----- GET /api/v1/admin/clients -----
  if (m === 'GET' && p === '/api/v1/admin/clients') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const writable = clientsDirWritable();  // probe once per list
    const out = [];
    for (const [name, c] of Object.entries(CONFIG.clients || {})) {
      out.push({
        name,
        role: c.role || 'developer',
        description: c.description || '',
        allow_password_login: !!c.allow_password_login,
        has_password: !!c.password,
        cert_fingerprint_sha256: c.cert_fingerprint_sha256 || null,
        cert_present_on_disk: existsSync(certPaths.clientPaths(name).crt),
        cert_key_present_on_disk: existsSync(certPaths.clientPaths(name).key),
        rate_limit: c.rate_limit || '100/hour',
        allowed_resolve: c.allowed_resolve || [],
        allowed_proxy: c.allowed_proxy || [],
        last_seen_ms_ago: lastSeenAgo(name),
      });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    audit({ action: 'admin_clients_list', cn: ctx.cn, fp: ctx.fp, count: out.length });
    return send(res, 200, { clients: out, pki_writable: writable });
  }

  // ----- GET /api/v1/admin/clients/:name -----
  if (m === 'GET' && clientMatch && clientMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientMatch[1];
    const c = CONFIG.clients[name];
    if (!c) return jsonError(res, 404, `Client ${name} not found`);
    return send(res, 200, {
      name,
      role: c.role || 'developer',
      description: c.description || '',
      allow_password_login: !!c.allow_password_login,
      has_password: !!c.password,
      cert_fingerprint_sha256: c.cert_fingerprint_sha256 || null,
      cert_present_on_disk: existsSync(certPaths.clientPaths(name).crt),
      cert_key_present_on_disk: existsSync(certPaths.clientPaths(name).key),
      rate_limit: c.rate_limit || '100/hour',
      allowed_resolve: c.allowed_resolve || [],
      allowed_proxy: c.allowed_proxy || [],
      last_seen_ms_ago: lastSeenAgo(name),
    });
  }

  // ----- POST /api/v1/admin/clients (create) -----
  if (m === 'POST' && p === '/api/v1/admin/clients') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const body = await readBody(req) || {};
    const name = body.name;
    if (!isValidClientName(name)) {
      return jsonError(res, 400, 'Invalid client name. Use [a-z][a-z0-9_.-]{0,63}.');
    }
    if (CONFIG.clients[name]) {
      return jsonError(res, 409, `Client ${name} already exists.`);
    }
    let cfg;
    try { cfg = normalizeClientConfig(body); } catch (e) { return jsonError(res, 400, e.message); }
    const prev = CONFIG.clients[name];
    CONFIG.clients[name] = cfg;
    try {
      await persistConfig();
    } catch (e) {
      delete CONFIG.clients[name];
      audit({ action: 'admin_clients_create', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_create', cn: ctx.cn, fp: ctx.fp, name, role: cfg.role, status: 'ok' });
    return send(res, 200, { ok: true, name, role: cfg.role });
  }

  // ----- PUT /api/v1/admin/clients/:name (update) -----
  if (m === 'PUT' && clientMatch && clientMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientMatch[1];
    const existing = CONFIG.clients[name];
    if (!existing) return jsonError(res, 404, `Client ${name} not found`);
    const body = await readBody(req) || {};
    let patch;
    try { patch = normalizeClientConfig(body); } catch (e) { return jsonError(res, 400, e.message); }
    // Apply patch over existing (don't touch cert_fingerprint_sha256; that's
    // owned by the enrollment flow).
    const prev = { ...existing };
    const next = { ...existing, ...patch };
    if (patch && Object.prototype.hasOwnProperty.call(patch, 'password') && !patch.password) {
      delete next.password;
    }
    CONFIG.clients[name] = next;
    try {
      await persistConfig();
    } catch (e) {
      CONFIG.clients[name] = prev;
      audit({ action: 'admin_clients_update', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_update', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ----- DELETE /api/v1/admin/clients/:name -----
  if (m === 'DELETE' && clientMatch && clientMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientMatch[1];
    const existing = CONFIG.clients[name];
    if (!existing) return jsonError(res, 404, `Client ${name} not found`);
    delete CONFIG.clients[name];
    // Best-effort: also remove cert files (revoke the cert material).
    try { deleteClientCertFiles(name); } catch {}
    try {
      await persistConfig();
    } catch (e) {
      CONFIG.clients[name] = existing;
      audit({ action: 'admin_clients_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Persist failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_delete', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // Helper: issue a cert, persist fingerprint, return cert+key.
  async function issueAndPersist(name) {
    const cert = await issueClientCert(name, { days: 365 });
    const c = CONFIG.clients[name];
    if (!c) throw new Error(`Client ${name} disappeared mid-enrollment`);
    const prev = { ...c };
    c.cert_fingerprint_sha256 = cert.fingerprint_sha256;
    try {
      await persistConfig();
    } catch (e) {
      // Roll back the in-memory change; cert files stay (operator can re-try).
      CONFIG.clients[name] = prev;
      throw e;
    }
    return cert;
  }

  // Helper: is the clients dir writable? On most prod setups pki/ is mounted
  // read-only (cert files are pre-issued and distributed out-of-band via
  // scripts/issue-client-cert.sh). We probe once per request — cheap.
  function clientsDirWritable() {
    try {
      const probe = join(CLIENTS_DIR, `.write-probe-${randomUUID()}`);
      writeFileSync(probe, 'ok');
      unlinkSync(probe);
      return true;
    } catch (e) { return false; }
  }
  // ----- POST /api/v1/admin/clients/:name/enrollment -----
  // Issue a fresh cert for the client. Returns the cert PEM and key PEM
  // directly in the response (one-time). For a real production system
  // you'd want an out-of-band delivery channel (e.g. the user polls
  // /enrollment?token=xxx). For Phase 1.3 we keep it simple.
  if (m === 'POST' && clientEnrollMatch && clientEnrollMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientEnrollMatch[1];
    if (!CONFIG.clients[name]) return jsonError(res, 404, `Client ${name} not found`);
    if (!clientsDirWritable()) {
      return jsonError(res, 503, 'pki/clients/ is not writable on this server. ' +
        'On production setups the PKI dir is mounted read-only; issue certs out-of-band via scripts/issue-client-cert.sh.');
    }
    let cert;
    try { cert = await issueAndPersist(name); } catch (e) {
      audit({ action: 'admin_clients_enroll', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Issue failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_enroll', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, {
      ok: true,
      name,
      fingerprint_sha256: cert.fingerprint_sha256,
      cert_pem: cert.cert_pem,
      key_pem: cert.key_pem,
      warning: 'key_pem is a SECRET. Deliver it to the client device out-of-band; do not paste it into chat or commit it to git.',
    });
  }

  // ----- POST /api/v1/admin/clients/:name/rotate -----
  if (m === 'POST' && clientRotateMatch && clientRotateMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientRotateMatch[1];
    if (!CONFIG.clients[name]) return jsonError(res, 404, `Client ${name} not found`);
    if (!clientsDirWritable()) {
      return jsonError(res, 503, 'pki/clients/ is not writable on this server. ' +
        'On production setups the PKI dir is mounted read-only; issue certs out-of-band via scripts/issue-client-cert.sh.');
    }
    let cert;
    try { cert = await issueAndPersist(name); } catch (e) {
      audit({ action: 'admin_clients_rotate', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Rotate failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_rotate', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, {
      ok: true,
      name,
      fingerprint_sha256: cert.fingerprint_sha256,
      cert_pem: cert.cert_pem,
      key_pem: cert.key_pem,
      warning: 'key_pem is a SECRET. The OLD cert is still on disk but its fingerprint has been replaced; broker will accept only the new one.',
    });
  }

  // ----- POST /api/v1/admin/clients/:name/revoke -----
  // Removes the fingerprint from broker.yaml so the cert is no longer
  // accepted (broker rejects on next connect). Cert files are kept on disk
  // for forensics; /delete wipes them.
  if (m === 'POST' && clientRevokeMatch && clientRevokeMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientRevokeMatch[1];
    const c = CONFIG.clients[name];
    if (!c) return jsonError(res, 404, `Client ${name} not found`);
    if (!c.cert_fingerprint_sha256) {
      return send(res, 200, { ok: true, name, already_revoked: true });
    }
    const prev = { ...c };
    delete c.cert_fingerprint_sha256;
    try {
      await persistConfig();
    } catch (e) {
      CONFIG.clients[name] = prev;
      audit({ action: 'admin_clients_revoke', cn: ctx.cn, fp: ctx.fp, name, status: 'error', error: e.message });
      return jsonError(res, 500, `Revoke failed: ${e.message}`);
    }
    audit({ action: 'admin_clients_revoke', cn: ctx.cn, fp: ctx.fp, name, status: 'ok' });
    return send(res, 200, { ok: true, name });
  }

  // ----- GET /api/v1/admin/clients/:name/bundle -----
  // Returns a zip with ca.crt, client.crt, client.key, and a tiny
  // connect-client.sh helper. Note: contains the SECRET key, so the
  // zip itself must be delivered out-of-band.
  if (m === 'GET' && clientBundleMatch && clientBundleMatch[1]) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const name = clientBundleMatch[1];
    const c = CONFIG.clients[name];
    if (!c) return jsonError(res, 404, `Client ${name} not found`);
    let certPem, keyPem, caPem;
    try {
      certPem = readClientCertPem(name);
      keyPem  = readClientKeyPem(name);
      caPem   = readCaCertPem();
    } catch (e) {
      return jsonError(res, 409, `Cert files missing for ${name}: ${e.message}. Run /enrollment first.`);
    }
    const installSh = [
      '#!/bin/sh',
      `# install.sh for ${name} — Secret Broker client bundle`,
      '# Usage:  sh install.sh /opt/secret-broker/pki/clients',
      '#         (creates ${name}.crt ${name}.key ca.crt with 0600 perms)',
      '',
      'set -e',
      'DEST="${1:-/opt/secret-broker/pki/clients}"',
      'mkdir -p "$DEST"',
      `cat > "$DEST/${name}.crt" <<'CERT_EOF'`,
      certPem,
      'CERT_EOF',
      `cat > "$DEST/${name}.key" <<'KEY_EOF'`,
      keyPem,
      'KEY_EOF',
      'cat > "$DEST/ca.crt" <<\'CA_EOF\'',
      caPem,
      'CA_EOF',
      `chmod 600 "$DEST/${name}.key"`,
      'echo "Installed to $DEST"',
      '',
    ].join('\n');
    // Build a minimal in-memory zip (no extra deps). Each entry: local
    // file header (0x04034b50) + data + central dir + EOCD.
    const files = [
      { name: `${name}.crt`, data: certPem },
      { name: `${name}.key`, data: keyPem },
      { name: 'ca.crt',      data: caPem },
      { name: 'install.sh',  data: installSh },
    ];
    const zip = buildZip(files);
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${name}-bundle.zip"`,
      'X-Broker-Version': '2.0.0',
    });
    return res.end(zip);
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
      // Pass the service name so callUpstream's error messages are useful.
      const r = await callUpstream({ ...svc, name: serviceName }, method, path, body.query, body.headers, body.body, { serviceName });
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

  // ============================================================
  // Phase 1.4: Audit enhancements
  //   - filtered list (client/service/action/status/since/until)
  //   - SSE real-time stream
  //   - JSON / CSV export
  // ============================================================
  const auditFilterMatch = p.match(/^\/api\/v1\/admin\/audit\/export\.(json|csv)$/);
  if (m === 'GET' && auditFilterMatch) {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const fmt = auditFilterMatch[1];
    const params = {
      client:  url.searchParams.get('client'),
      service: url.searchParams.get('service'),
      action:  url.searchParams.get('action'),
      status:  url.searchParams.get('status'),
      since:   url.searchParams.get('since'),
      until:   url.searchParams.get('until'),
      limit:   parseInt(url.searchParams.get('limit') || '5000', 10),
    };
    const events = readAuditFiltered(params);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    if (fmt === 'json') {
      const body = JSON.stringify({ exported_at: new Date().toISOString(), count: events.length, events }, null, 2);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="audit-${stamp}.json"`,
        'X-Broker-Version': '2.0.0',
      });
      return res.end(body);
    } else { // csv
      // Columns: ts, action, status, cn, fp, service, method, path, error, name, field, reason
      const cols = ['ts','action','status','cn','fp','service','method','path','error','name','field','reason','latency_ms','upstream_status'];
      const escape = (v) => {
        if (v == null) return '';
        const s = String(v);
        return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      };
      const lines = [cols.join(',')];
      for (const e of events) lines.push(cols.map(c => escape(e[c])).join(','));
      const body = lines.join('\n') + '\n';
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="audit-${stamp}.csv"`,
        'X-Broker-Version': '2.0.0',
      });
      return res.end(body);
    }
  }

  // ----- GET /api/v1/admin/audit (filtered list) -----
  if (m === 'GET' && p === '/api/v1/admin/audit') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
    const params = {
      client:  url.searchParams.get('client'),
      service: url.searchParams.get('service'),
      action:  url.searchParams.get('action'),
      status:  url.searchParams.get('status'),
      since:   url.searchParams.get('since'),
      until:   url.searchParams.get('until'),
      limit:   parseInt(url.searchParams.get('limit') || '200', 10),
    };
    const events = readAuditFiltered(params);
    return send(res, 200, { events });
  }

  // ----- GET /api/v1/admin/audit/stream (SSE) -----
  // Server-Sent Events: streams new audit events to the admin UI live.
  // Browser opens via `new EventSource('/api/v1/admin/audit/stream')`.
  // Sends a hello ping, then `event: <name>\ndata: <json>\n\n` for each event.
  // Closes after 30 minutes (clients can reconnect).
  if (m === 'GET' && p === '/api/v1/admin/audit/stream') {
    if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',  // disable buffering under nginx
      'X-Broker-Version': '2.0.0',
    });
    res.write(': hello\n\n');
    res.write('event: ready\ndata: {"ok":true}\n\n');
    const onEvent = (e) => {
      try {
        res.write(`event: audit\ndata: ${JSON.stringify(e)}\n\n`);
      } catch (e) { /* socket closed */ }
    };
    AUDIT_BUS.on('event', onEvent);
    // Keep-alive comment every 25s (so proxies don't kill idle conns)
    const ka = setInterval(() => { try { res.write(': ka\n\n'); } catch {} }, 25_000);
    // Auto-close after 30 min
    const closeTimer = setTimeout(() => { try { res.end(); } catch {} }, 30 * 60 * 1000);
    req.on('close', () => {
      clearInterval(ka);
      clearTimeout(closeTimer);
      AUDIT_BUS.off('event', onEvent);
    });
    return;  // keep connection open
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
  // 0. v3.0 M2: API Key Bearer 鉴权 (无 mTLS, 给 Web 端 AI 用)
  const apiKeyCtx = getApiKeyIdentity(req);
  if (apiKeyCtx) {
    if (apiKeyCtx.rate_limited) {
      audit({ action: 'connect', status: 'denied', reason: 'api_key_rate_limit', cn: apiKeyCtx.clientName });
      return null;  // 让外层返 429
    }
    return {
      cn: `apikey:${apiKeyCtx.apiKey.id}`,
      fp: apiKeyCtx.apiKey.id,
      client: apiKeyCtx.client,
      clientName: apiKeyCtx.clientName,
      certSubject: { CN: `apikey:${apiKeyCtx.apiKey.id}`, O: 'api_key' },  // 占位让 ctx.certSubject truthy
      via: 'api_key',
      apiKey: apiKeyCtx.apiKey,
    };
  }
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
  recordClientSeen(matchedBy);
  return {
    cn, fp, client: matched, clientName: matchedBy,
    certSubject: cert.subject,
    via: 'mtls',
  };
}

// v3.0 M2: API Key Bearer 鉴权 (无 mTLS, 给 Web 端 AI 用)
// 独立函数, 走 ctx.apiKey 字段
function getApiKeyIdentity(req) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  const secret = parseBearer(authHeader);
  if (!secret) return null;
  const k = findApiKey(CONFIG.api_keys, secret);
  if (!k) return null;
  // 找到归属 client
  const owner = CONFIG.clients[k.client];
  if (!owner) return null;
  // 限速 (per api key)
  if (!rateLimitApiKey(k)) {
    return { apiKey: k, client: owner, clientName: k.client, via: 'api_key', rate_limited: true };
  }
  recordUse(k);
  return { apiKey: k, client: owner, clientName: k.client, via: 'api_key' };
}

// v3.0 M2: API Key 限速 (用 k.id 作 bucket key)
const API_KEY_BUCKETS = new Map();
function rateLimitApiKey(k) {
  if (!k) return true;
  const limit = k.rate_limit || '100/hour';
  if (limit === 'unlimited') return true;
  const m = limit.match(/^(\d+)\/(hour|minute|day)$/);
  if (!m) return true;
  const max = parseInt(m[1], 10);
  const windowMs = m[2] === 'minute' ? 60_000 : m[2] === 'day' ? 86_400_000 : 3_600_000;
  const key = 'apikey:' + k.id;
  const now = Date.now();
  const bucket = API_KEY_BUCKETS.get(key) || [];
  const fresh = bucket.filter(t => now - t < windowMs);
  if (fresh.length >= max) {
    API_KEY_BUCKETS.set(key, fresh);
    return false;
  }
  fresh.push(now);
  API_KEY_BUCKETS.set(key, fresh);
  return true;
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
    // Some systemd environments (Aliyun ECS) block outbound UDP/53 to
    // public DNS. c-ares inside undici (and node:dns) only does UDP, so
    // /etc/resolv.conf nameservers fail with ENOTFOUND even though TCP/443
    // to api.github.com / ecs.aliyuncs.com works fine. We work around by
    // setting up DoT (DNS-over-TLS via Cloudflare 1.1.1.1:853) — but that
    // requires tls module work. Simpler: pre-resolve any *upstream hostname
    // we route to, then re-issue the call. See `resolveHostname()` below.
    await loadConfig();
    await loadSecrets();
    // v3.0: 启动时跑一次 schema 迁移（幂等）
    try {
      const { migrateV2ToV3 } = await import('./migrate-v2-to-v3.js');
      const migPath = dirname(fileURLToPath(import.meta.url));
      const clientsDir = join(migPath, '..', 'pki', 'clients');
      const { changed, changes } = await migrateV2ToV3(
        CONFIG, clientsDir, audit, persistConfig
      );
      if (changed) {
        console.log(`[migrate v2->v3] applied ${changes.length} change(s):`);
        changes.forEach(c => console.log('  -', c));
      } else {
        console.log('[migrate v2->v3] already at v3, no changes');
      }
    } catch (e) {
      console.warn('[migrate v2->v3] skipped:', e.message);
    }
    start();
  } catch (err) {
    console.error('[bootstrap] failed:', err.message);
    process.exit(1);
  }
})();
