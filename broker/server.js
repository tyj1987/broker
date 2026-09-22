// server.js
// Secret Broker 服务端入口
// 监听 mTLS HTTPS，SOPS 解密配置，代理模式转发外部 API
//
// Usage:
//   node server.js
//   PORT=8443 CONFIG_PATH=/opt/broker/secrets/broker.yaml AGE_KEY_FILE=/opt/broker/pki/age.key node server.js

import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
// v3.0: 强认证 (TOTP + MFA 状态机)
import {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  verifyMfaCode,
  verifyStepUp,
  restoreConsumedRecoveryCode,
  isMfaRequired,
  MFA_TOKEN_TTL_MS,
  mfaClientBinding,
} from './auth-flow.js';
import { createMutationGate } from './lib/mutation-gate.js';
// v3.0: 密码 hash + TOTP + 恢复码
import {
  verifyPasswordCompat,
  verify as verifyTotpFn,
  generateSecret,
  generateRecoveryCodes,
  hashRecoveryCode,
  hashPassword,
  buildOtpauthURL,
} from './totp.js';
// v3.0 M2: API Key 管理 + Bearer 鉴权
import {
  runAll as healthcheckRunAll,
  runAllViaMcp as healthcheckRunAllViaMcp,
  getStatus as healthcheckGetStatus,
  getSecretStatus as healthcheckGetSecretStatus,
  getAlertHistory as healthcheckGetAlertHistory,
  HEALTHCHECK_BUS,
} from './healthcheck.js';
import { registerCron, startCronLoop, stopCronLoop } from './cron-tasks.js';
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
  generateMasterKey,
  createChildKey,
  canCreateChild,
  isClientIpAllowed,
  createApiKeyRateLimiter,
} from './api-keys.js';
import { BROKER_VERSION } from './version.js';
import {
  sopsDecrypt as sopsDecryptSafe,
  sopsEncryptAtomic as sopsEncryptAtomicSafe,
} from './lib/sops.js';
import { createClientBundle } from './lib/client-bundle.js';
import { normalizeClientConfig, clientSecurityConfigChanged } from './lib/client-config.js';
import {
  checkTrustedBrowserMutation,
  isBrowserRequest,
  isCookieSessionRequest,
} from './lib/browser-request.js';
import { aliyunRpcVersion, mergeAliyunQuery } from './lib/aliyun-rpc.js';
import { dohConnect } from './lib/doh.js';
import { defaultServiceTest, describeUpstreamStatus } from './lib/service-test.js';
import { relayConfig, shouldRelay, applyRelay } from './lib/outbound-relay.js';
import { resolveUpstreamUrl, validateConfiguredUpstream } from './lib/upstream-url.js';
import { buildProxyRequestHeaders, sanitizeProxyResponseHeaders } from './lib/proxy-headers.js';
import { readLimitedResponseBody, maxUpstreamResponseBytes } from './lib/proxy-body.js';
import { filteredHealthStatus } from './lib/health-visibility.js';
import { isApiKeyRouteAllowed } from './lib/api-key-route-policy.js';
import { handleHealth, buildOpsHealth } from './routes/health.js';
import { handleStatic } from './routes/static.js';
import { handleMetrics } from './routes/metrics.js';
import { defaultHealthBind, startLocalHealthServer } from './lib/local-health.js';
import { handleSshProxy } from './routes/ssh-proxy.js';
import { createReadApiRoutes } from './routes/read-api.js';
import { createAuditRoutes } from './routes/audit.js';
import { getStats, listSubscribers } from './lib/ws.js';
import { createSseCap } from './lib/sse-cap.js';
import {
  installGracefulShutdown,
  rejectIfShuttingDown,
  validateBrokerConfig,
  formatValidationReport,
  preflightPaths,
  pruneAuditFiles,
  auditPolicyFromEnv,
  runWithRequestContext,
  setResponseTraceHeaders,
  getRequestId,
  getTraceparent,
  outboundTraceHeaders,
  inc,
  observeMs,
  runProbes,
  probesFromConfig,
  redactDeep,
  send as sendSafe,
  sendBuffer as sendBufferSafe,
  securityHeaders,
  createIdentityResolver,
  createSessionStore,
  createPendingTotp,
  isPendingTotpExpired,
  readBody as readBodySafe,
  wrapAsyncRequestHandler,
  createRateLimiter,
  rateLimitKey,
  SESSION_TTL_MS,
  SESSION_HEADER,
} from './lib/index.js';
// v3.0: schema migration (in start())
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { TYPE_SCHEMAS, validateFields } from './type-schemas.js';
import { publicTemplateList } from './service-templates.js';
import {
  checkPathAllowed,
  checkMethodAllowed,
  normalizeProxyMethod,
  canProxy as canProxyClient,
  isServiceAllowed as isServiceAllowedClient,
  clientNamesAllowedFor,
} from './can-proxy.js';
import {
  issueClientCert,
  readClientCertPem,
  readClientKeyPem,
  snapshotClientCertFiles,
  restoreClientCertFiles,
  deleteClientKeyFile,
  deleteClientCertFiles,
  readCaCertPem,
  paths as certPaths,
} from './cert-issuer.js';

// Re-export the clients dir for the writable-probe helper.
const CLIENTS_DIR = certPaths.CLIENTS_DIR;

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================
// Config & env
// ============================================================
const PORT = parseInt(process.env.PORT || '8443', 10);
const HOST = process.env.HOST || process.env.BROKER_BIND || '127.0.0.1';
const CONFIG_PATH = process.env.CONFIG_PATH || resolvePath(__dirname, '../secrets/broker.yaml');
const SECRETS_PATH = process.env.SECRETS_PATH || resolvePath(__dirname, '../secrets/common.env');
// Phase 1.1.1: structured secrets (multi-field support). If this file doesn't
// exist, broker auto-migrates from common.env on first start and writes here.
const SECRETS_DETAIL_PATH =
  process.env.SECRETS_DETAIL_PATH || resolvePath(__dirname, '../secrets/secrets-detail.json');
const PKI_DIR = process.env.PKI_DIR || resolvePath(__dirname, '../pki');
const AGE_KEY_FILE = process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE;
const AUDIT_DIR = process.env.AUDIT_DIR || resolvePath(__dirname, '../audit');
const TLS_CERT = process.env.TLS_CERT || join(PKI_DIR, 'server/server.crt');
const TLS_KEY = process.env.TLS_KEY || join(PKI_DIR, 'server/server.key');
const TLS_CA = process.env.TLS_CA || join(PKI_DIR, 'ca/ca.crt');
const TLS_CRL = process.env.TLS_CRL || join(PKI_DIR, 'ca/crl.pem');
const RELOAD_TOKEN = process.env.RELOAD_TOKEN || randomUUID();
// Secure default: private keys are returned once by enrollment/rotation and
// immediately removed from the broker host. Compatibility retention must be
// explicitly enabled and is surfaced to administrators.
const RETAIN_CLIENT_PRIVATE_KEYS = process.env.BROKER_RETAIN_CLIENT_PRIVATE_KEYS === '1';

console.log('============================================');
console.log(`  Secret Broker v${BROKER_VERSION}`);
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

// Keep environment-specific wiring here; the implementation lives in lib/sops.js.
function sopsDecrypt(filePath) {
  return sopsDecryptSafe(filePath, { ageKeyFile: AGE_KEY_FILE });
}

function sopsEncryptAtomic(targetPath, plaintext) {
  return sopsEncryptAtomicSafe(targetPath, plaintext, { ageKeyFile: AGE_KEY_FILE });
}

// ============================================================
// Config loader
// ============================================================
let CONFIG = null;
// Phase 1.1.1: structured secrets. Each entry is:
//   { type, description, fields: { [fieldName]: value }, created_at, updated_at, updated_by }
// `type` is a key in type-schemas.js. `fields` is dynamic per type.
// The legacy `common.env` is read-only on startup; writes go to secrets-detail.json.
const SECRET_CACHE = new Map();

// Lazy factory: build read-api routes on first dispatch. The factory closes
// over the live module state (CONFIG, SECRET_CACHE) so a config reload is
// picked up automatically.
let _readApi = null;
function readApiRoutes() {
  if (_readApi) return _readApi;
  _readApi = createReadApiRoutes({
    config: () => CONFIG,
    SECRET_CACHE,
    audit,
    canResolve,
    checkPathAllowed,
    getSecret,
    isServiceAllowed,
    healthcheckGetSecretStatus,
    auditDir: process.env.AUDIT_DIR || resolvePath(__dirname, '../audit'),
  });
  return _readApi;
}

async function loadConfig() {
  // Dev mode: skip sops and read the file as-is (for local testing only).
  const skipSops = process.env.SOPS_SKIP === '1' || process.env.SOPS_SKIP === 'true';
  if (skipSops) {
    console.log('[config] SOPS_SKIP=1 — reading broker.yaml as plaintext (DEV ONLY)');
  } else {
    console.log('[config] Decrypting broker.yaml via SOPS...');
  }
  const yamlText = skipSops ? readFileSync(CONFIG_PATH, 'utf8') : await sopsDecrypt(CONFIG_PATH);
  const cfg = parseYaml(yamlText);
  if (!cfg || typeof cfg !== 'object') throw new Error('Invalid broker.yaml');
  cfg.services = cfg.services || {};
  cfg.clients = cfg.clients || {};
  const validation = validateBrokerConfig(cfg);
  if (!validation.ok) throw new Error('Broker configuration validation failed');
  CONFIG = cfg;
  console.log(
    `[config] Loaded: ${Object.keys(CONFIG.services).length} services, ${Object.keys(CONFIG.clients).length} clients`,
  );
}

async function loadSecrets() {
  // 1. Try new structured store first
  if (existsSync(SECRETS_DETAIL_PATH)) {
    try {
      const skipSops2 = process.env.SOPS_SKIP === '1' || process.env.SOPS_SKIP === 'true';
      const text = skipSops2
        ? readFileSync(SECRETS_DETAIL_PATH, 'utf8')
        : await sopsDecrypt(SECRETS_DETAIL_PATH);
      const obj = JSON.parse(text);
      SECRET_CACHE.clear();
      for (const [name, entry] of Object.entries(obj.secrets || {})) {
        SECRET_CACHE.set(name, normalizeSecretEntry(name, entry));
      }
      console.log(
        `[secrets] Loaded ${SECRET_CACHE.size} structured secrets from ${SECRETS_DETAIL_PATH}`,
      );
      return;
    } catch (e) {
      console.error('[secrets] Existing structured store could not be loaded');
      // Never replace a corrupt or encryption-failed existing store with empty state.
      throw new Error('Structured secret store could not be loaded', { cause: e });
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
    console.log(
      `[secrets] Migrated ${SECRET_CACHE.size} secrets; persisting to ${SECRETS_DETAIL_PATH}`,
    );
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
    // v3.1.1 M5.9: last_rotated_at + rotation_history
    // - last_rotated_at 默认 fallback 到 updated_at (老 secret 没这字段时)
    // - rotation_history 默认 [] (M5.9 才加的字段)
    last_rotated_at: entry.last_rotated_at || entry.updated_at || new Date().toISOString(),
    rotation_history: Array.isArray(entry.rotation_history) ? entry.rotation_history : [],
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
          created_at: now,
          updated_at: now,
          updated_by: 'migration',
        };
        consumed.add(name);
        consumed.add(skName);
      } else if (name === 'ALIYUN_ACCESS_KEY_ID' || name.endsWith('_ACCESS_KEY_ID')) {
        // ID without paired SECRET — treat as plain custom
        secrets[name] = {
          type: 'custom',
          description: '(migrated)',
          fields: { value: entries[name] },
          created_at: now,
          updated_at: now,
          updated_by: 'migration',
        };
        consumed.add(name);
      }
    }
  }
  // 2) Other keys: best-effort type guess
  for (const name of Object.keys(entries)) {
    if (consumed.has(name)) continue;
    let type = 'custom',
      fieldKey = 'value';
    if (/GITHUB/.test(name) || /_PAT$/.test(name)) {
      type = 'github_pat';
      fieldKey = 'token';
    } else if (/OPENAI/.test(name)) {
      type = 'openai_key';
      fieldKey = 'api_key';
    } else if (/JWT_SECRET$/.test(name)) {
      type = 'jwt_secret';
      fieldKey = 'value';
    } else if (/_WEBHOOK$/.test(name)) {
      if (/SLACK/.test(name)) type = 'slack_webhook';
      else if (/DISCORD/.test(name)) type = 'discord_webhook';
      else if (/FEISHU|LARK/.test(name)) type = 'feishu_webhook';
      else if (/DINGTALK/.test(name)) type = 'dingtalk_webhook';
      fieldKey = 'url';
    } else if (/SENTRY/.test(name)) {
      type = 'sentry_dsn';
      fieldKey = 'dsn';
    }
    secrets[name] = {
      type,
      description: '(migrated; please re-categorize via admin UI)',
      fields: { [fieldKey]: entries[name] },
      created_at: now,
      updated_at: now,
      updated_by: 'migration',
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
  if (CONFIG.clients)
    out.clients = Object.fromEntries(
      Object.entries(CONFIG.clients).map(([name, client]) => [
        name,
        Object.fromEntries(Object.entries(client).filter(([key]) => key !== '_pending_totp')),
      ]),
    );
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
  return (
    text
      // `key: 2025-08-12` (bare date) → `key: "2025-08-12"`
      .replace(/^(\s*[\w.-]+\s*:\s+)(\d{4}-\d{2}-\d{2})(\s*$)/gm, '$1"$2"$3')
      // `key: 12:34:56` (bare time) → `key: "12:34:56"`
      .replace(/^(\s*[\w.-]+\s*:\s+)(\d{1,2}:\d{2}:\d{2})(\s*$)/gm, '$1"$2"$3')
      // `key: 2025-08-12T10:00:00Z` (timestamp) → `key: "..."`
      .replace(
        /^(\s*[\w.-]+\s*:\s+)(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(\s*$)/gm,
        '$1"$2"$3',
      )
  );
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

// Client name rule: same shape as services (URL path component) but allow
// dots for legacy `client.foo` style names.
const CLIENT_NAME_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
function isValidClientName(name) {
  return typeof name === 'string' && CLIENT_NAME_RE.test(name);
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
  if (body.allow_insecure_http !== undefined) {
    out.allow_insecure_http = body.allow_insecure_http === true;
  }
  // Optional metadata
  if (body.description !== undefined) out.description = String(body.description);
  if (body.region !== undefined) out.region = String(body.region);
  if (body.api_version !== undefined) out.api_version = String(body.api_version);
  if (body.action !== undefined) out.action = String(body.action);
  // Token reference: just the name of the secret; never the value
  if (body.token_secret !== undefined) out.token_secret = String(body.token_secret);
  if (body.token_field !== undefined) out.token_field = String(body.token_field);
  // Aliyun OpenAPI v2: structured secret name (with access_key_id + access_key_secret fields)
  if (body.ak_secret !== undefined) out.ak_secret = String(body.ak_secret);
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
  if (body.header_value_template !== undefined) {
    out.header_value_template = String(body.header_value_template);
  }
  // Method restrictions must survive the administrative API boundary.
  // Preserve invalid shapes for validation rather than silently widening access.
  if (body.allow_methods !== undefined) {
    out.allow_methods = Array.isArray(body.allow_methods)
      ? [...new Set(body.allow_methods.map((m) => (typeof m === 'string' ? m.toUpperCase() : m)))]
      : body.allow_methods;
  }
  // allow_paths: array of regex strings
  if (Array.isArray(body.allow_paths)) {
    out.allow_paths = body.allow_paths.map((s) => String(s));
  }
  // dashboard_actions: array of {label, method, path, query?}
  if (Array.isArray(body.dashboard_actions)) {
    out.dashboard_actions = body.dashboard_actions
      .filter((a) => a && typeof a === 'object' && a.label && a.method && a.path)
      .map((a) => ({
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
  if (!cfg) {
    errs.push('Missing config body');
    return errs;
  }
  if (!cfg.type) errs.push('Missing type');
  else {
    // Allow any type we have callUpstream support for. (We don't restrict to
    // a known set because Phase 3 may add more.)
    const supported = new Set(['github_token', 'bearer', 'header', 'aliyun_v2', 'ssh_proxy']);
    if (!supported.has(cfg.type)) errs.push(`Unknown service type: ${cfg.type}`);
  }
  if (!cfg.upstream && cfg.type !== 'ssh_proxy') errs.push('Missing upstream URL');
  if (cfg.upstream) {
    try {
      validateConfiguredUpstream(cfg.upstream, {
        allowInsecureHttp: cfg.allow_insecure_http === true,
      });
    } catch (e) {
      errs.push(`unsafe upstream: ${e.message}`);
    }
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
  if (
    cfg.allow_methods !== undefined &&
    (!Array.isArray(cfg.allow_methods) ||
      cfg.allow_methods.length === 0 ||
      cfg.allow_methods.some(
        (method) => typeof method !== 'string' || !normalizeProxyMethod(method),
      ))
  ) {
    errs.push('allow_methods must be a non-empty array of supported HTTP methods');
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
// v3.1 M5.5: Service ↔ Secret 联动 — call_service 前置检查
// 单独模块 broker/service-secret-guard.js, 方便测试 + 复用
// ============================================================
import { checkSecretForService, guardHint } from './service-secret-guard.js';

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
// Audit log (V4.3.0: extracted to routes/audit.js factory)
// ============================================================
const {
  audit,
  readAudit,
  readAuditFiltered,
  collectAuditFacets,
  clearAuditLogs,
  bus: AUDIT_BUS,
} = createAuditRoutes({
  auditDir: AUDIT_DIR,
  getConfig: () => CONFIG,
  redact: redactDeep,
});

// ============================================================
// Session tokens + login lockout (V4.3.0-step2: extracted from
// inline duplicate of lib/session.js#createSessionStore)
// ============================================================
const {
  makeSession,
  getSession,
  deleteSession,
  deleteSessionsForClient,
  deleteSessionsForFingerprint,
  checkLoginLock,
  recordLoginFail,
  clearLoginLock,
  sessions: SESSIONS,
} = createSessionStore();

// ============================================================
// V4.8.0: SSE 并发连接上限 (REVIEW.md §3 P6) — 见 broker/lib/sse-cap.js
// ============================================================
const { adminSseKey, tryAcquireSseSlot, releaseSseSlot } = createSseCap();

function canResolve(ctx, secretName) {
  if (!ctx?.client) return false;
  // API keys are delegated capabilities: key scope/allowlist is always the
  // first boundary, even when the owning client is an admin.
  if (ctx.apiKey && !canResolveSecret(ctx.apiKey, secretName)) return false;
  if (ctx.client.role === 'admin' || (ctx.via === 'api_key' && ctx.ownerRole === 'admin')) {
    return true;
  }
  const allow = ctx.client.allowed_resolve || [];
  return checkPathAllowed(allow, secretName);
}

function canProxy(ctx, serviceName, path, method = 'GET') {
  if (!ctx?.client) return false;
  if (ctx.apiKey && !canProxyService(ctx.apiKey, serviceName)) return false;
  if (ctx.via === 'api_key' && ctx.ownerRole === 'admin') return true;
  return canProxyClient(ctx, serviceName, path, method);
}

function isServiceAllowed(ctx, serviceName) {
  if (!ctx?.client) return false;
  if (ctx.apiKey && !canProxyService(ctx.apiKey, serviceName)) return false;
  if (ctx.via === 'api_key' && ctx.ownerRole === 'admin') return true;
  return isServiceAllowedClient(ctx, serviceName);
}

// ============================================================
// Rate limit (in-memory, per identity)
// ============================================================
const checkClientRateLimit = createRateLimiter({ defaultLimit: '100/hour' });

// v3.0: 密码验证智能 wrapper — 检测 stored 是否 hash，自动选 verify 函数
// 兼容：plaintext / scrypt$... 两种格式。始终同步返回 boolean，避免调用方把
// Promise 误当作认证成功（尤其是证书轮换 / TOTP / API Key 等敏感操作）。
function verifyClientPassword(plaintext, stored) {
  return verifyPasswordCompat(plaintext, stored);
}

function rateLimit(ctx) {
  if (!ctx.client) return true; // fail at canResolve/canProxy later
  const limit = ctx.client.rate_limit || '100/hour';
  return checkClientRateLimit(rateLimitKey(ctx), limit);
}

// ============================================================
// HTTP helpers
// ============================================================
function isLoopbackAddress(addr) {
  if (!addr) return false;
  const a = String(addr).replace(/^::ffff:/, '');
  return a === '127.0.0.1' || a === '::1' || a === 'localhost';
}

/** True only for a direct loopback client (prometheus / unix). Nginx sets X-Forwarded-For. */
function isDirectLocalRequest(req) {
  if (!isLoopbackAddress(req?.socket?.remoteAddress)) return false;
  if (req.headers?.['x-forwarded-for'] || req.headers?.['x-real-ip']) return false;
  return true;
}

function sessionCookieHeader(token, { clear = false } = {}) {
  const value = clear ? '' : token;
  const maxAge = clear ? 0 : SESSION_TTL_MS / 1000;
  return `broker_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function send(res, status, body, extraHeaders = {}) {
  return sendSafe(res, status, body, {
    ...extraHeaders,
    exposeVersion: extraHeaders.exposeVersion === true || res.__exposeBrokerVersion === true,
  });
}

const bufferedMutationBodies = new WeakMap();
function readBody(req) {
  return bufferedMutationBodies.has(req)
    ? Promise.resolve(bufferedMutationBodies.get(req))
    : readBodySafe(req);
}

function jsonError(res, status, msg) {
  if (res.headersSent || res.writableEnded) return;
  return send(res, status, { error: msg, status });
}

function persistenceError(res) {
  return jsonError(res, 500, 'Unable to persist configuration');
}

function restorePlainObject(target, snapshot) {
  for (const key of Object.keys(target)) delete target[key];
  Object.assign(target, structuredClone(snapshot));
}

// ============================================================
// Aliyun / Tencent IMDS + STS token (no long-lived AK needed)
// ============================================================
const IMDS_TIMEOUT_MS = 2000;
const STS_CACHE = new Map(); // roleName -> { token, expiresAt }

async function _imdsFetch(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), IMDS_TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: ctl.signal });
    if (!r.ok) throw new Error(`IMDS ${r.status}`);
    return r;
  } finally {
    clearTimeout(t);
  }
}

// Try to get the instance-attached RAM role name. Returns null if not on ECS.
async function getAliyunRamRole() {
  try {
    const r = await _imdsFetch('http://100.100.100.200/latest/meta-data/ram/security-credentials/');
    const txt = (await r.text()).trim();
    if (!txt || txt === 'Not Found' || txt.startsWith('<!')) return null;
    // IMDS sometimes returns the role name directly, sometimes JSON-wrapped.
    return txt.replace(/^"|"$/g, '');
  } catch {
    return null;
  }
}

// Get STS credentials (cached until near expiry)
async function getAliyunStsToken(roleName) {
  const cached = STS_CACHE.get(roleName);
  if (cached && Date.now() < cached.expiresAt - 60_000) return cached;
  const r = await _imdsFetch(
    `http://100.100.100.200/latest/meta-data/ram/security-credentials/${encodeURIComponent(roleName)}`,
  );
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
    if (!role) {
      throw new Error(
        'IMDS: no RAM role attached to this instance. Run on ECS with instance profile.',
      );
    }
    return await getAliyunStsToken(role);
  }
  // SOPS-based: just return the AK/SK from the secret cache
  return null; // caller will fall back to getSecret()
}

// ============================================================
// Aliyun OpenAPI v2 signature
// https://help.aliyun.com/document_detail/315526.htm
// ============================================================
import { createHmac } from 'node:crypto';

function aliyunPercentEncode(s) {
  // Aliyun encoding: encodeURIComponent then replace !*()' with their hex
  return encodeURIComponent(s).replace(/\+/g, '%20').replace(/\*/g, '%2A').replace(/%7E/g, '~'); // ~ 已经是 %7E 了，encodeURIComponent 会编码为 %7E
}

function aliyunV2Sign(method, params, accessKeySecret) {
  // 1. Sort params by key
  const sortedKeys = Object.keys(params).sort();
  // 2. Build canonicalized query string
  const canonical = sortedKeys
    .map((k) => `${aliyunPercentEncode(k)}=${aliyunPercentEncode(params[k])}`)
    .join('&');
  // 3. StringToSign
  const stringToSign = `${method}&${aliyunPercentEncode('/')}&${aliyunPercentEncode(canonical)}`;
  // 4. Sign
  const signature = createHmac('sha1', `${accessKeySecret}&`).update(stringToSign).digest('base64');
  return signature;
}

// Build a signed aliyun_v2 URL (query params merged with Signature etc.)
function buildAliyunSignedUrl(upstream, action, query, region, creds, apiVersion) {
  const extra = { ...(query || {}) };
  delete extra.Action;
  delete extra.Signature;
  const params = {
    Format: 'JSON',
    Version: apiVersion || extra.Version || '2014-05-26',
    AccessKeyId: creds.accessKeyId,
    SignatureMethod: 'HMAC-SHA1',
    Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    SignatureVersion: '1.0',
    SignatureNonce: randomUUID(),
    Action: action,
    ...(region ? { RegionId: region } : {}),
    ...extra,
  };
  if (apiVersion) params.Version = apiVersion;
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
  try {
    const u = new URL(path, 'http://x/');
    if (u.searchParams.get('Action')) return u.searchParams.get('Action');
  } catch {}
  if (query && query.Action) return String(query.Action);
  return null;
}

async function callUpstream(serviceCfg, method, path, query, headers, body, opts = {}) {
  const normalizedMethod = normalizeProxyMethod(method || 'GET');
  if (!normalizedMethod) throw new Error(`Unsupported proxy HTTP method: ${String(method)}`);
  if (!checkMethodAllowed(serviceCfg.allow_methods, normalizedMethod)) {
    throw new Error(`HTTP method ${normalizedMethod} is not allowed for this service`);
  }
  method = normalizedMethod;

  const upstreamBase = validateConfiguredUpstream(serviceCfg.upstream, {
    allowInsecureHttp: serviceCfg.allow_insecure_http === true,
  });

  // Resolve all secrets used by this service
  const injectHeaders = { ...(serviceCfg.inject_headers || {}) };
  let url = null;

  if (
    serviceCfg.type === 'bearer' ||
    serviceCfg.type === 'github_token' ||
    serviceCfg.type === 'header'
  ) {
    // Simple bearer/header auth: resolve a single secret and inject as header.
    // `name` is added by the admin service test endpoint; fall back to the
    // route-level name (passed via opts) for clarity in error messages.
    const svcNameForErr = serviceCfg.name || opts?.serviceName || '?';
    if (!serviceCfg.token_secret) throw new Error(`Service ${svcNameForErr} missing token_secret`);
    const token = getSecretField(serviceCfg.token_secret, serviceCfg.token_field);
    if (!token) {
      throw new Error(
        `Secret ${serviceCfg.token_secret} field=${serviceCfg.token_field || '(default)'} not loaded`,
      );
    }
    if (serviceCfg.type === 'bearer') {
      injectHeaders['Authorization'] = `Bearer ${token}`;
    } else if (serviceCfg.type === 'github_token') {
      injectHeaders['Authorization'] = `token ${token}`;
    } else if (serviceCfg.type === 'header') {
      const tpl = serviceCfg.header_value_template || 'Bearer {{secret}}';
      injectHeaders[serviceCfg.header_name || 'Authorization'] = tpl.replace('{{secret}}', token);
    }
    // Build URL: caller-provided path + query against upstream
    url = resolveUpstreamUrl(upstreamBase.href, path, {
      allowInsecureHttp: serviceCfg.allow_insecure_http === true,
    });
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
        const sk = getSecretField(
          serviceCfg.ak_secret,
          serviceCfg.ak_secret_field || 'access_key_secret',
        );
        if (!ak || !sk) {
          throw new Error(`Aliyun secret ${serviceCfg.ak_secret} missing required fields`);
        }
        creds = { accessKeyId: ak, accessKeySecret: sk };
      } else {
        const ak = getSecretField(serviceCfg.access_key_secret, 'value');
        const sk = getSecretField(serviceCfg.access_secret_secret, 'value');
        if (!ak || !sk) throw new Error('Aliyun access_key or access_secret not loaded');
        creds = { accessKeyId: ak, accessKeySecret: sk };
      }
    }
    const action = getAliyunAction(path, serviceCfg, query);
    if (!action) {
      throw new Error('aliyun_v2 requires Action (set serviceCfg.action or pass ?Action=...)');
    }
    const merged = mergeAliyunQuery(path, query);
    delete merged.Action;
    const apiVersion = aliyunRpcVersion({
      serviceCfg,
      upstream: serviceCfg.upstream,
      path,
      query: merged,
    });
    delete merged.Version;
    url = buildAliyunSignedUrl(
      upstreamBase.href,
      action,
      merged,
      serviceCfg.region,
      creds,
      apiVersion,
    );
  } else {
    throw new Error(`Unsupported service type: ${serviceCfg.type}`);
  }

  // Also enforce service ACLs for administrative test/dashboard helpers.
  if (!checkPathAllowed(serviceCfg.allow_paths, url.pathname)) {
    throw new Error('Upstream path is not allowed for this service');
  }
  // Build outgoing request
  const baseHeaders = {
    'User-Agent': `secret-broker/${BROKER_VERSION}`,
    ...outboundTraceHeaders({
      traceparent: typeof getTraceparent === 'function' ? getTraceparent() : undefined,
      requestId: typeof getRequestId === 'function' ? getRequestId() : undefined,
    }),
  };
  const outHeaders = buildProxyRequestHeaders({
    baseHeaders,
    userHeaders: headers,
    injectHeaders,
  });
  // Host header 必须用 upstream 的 host，否则 upstream 验签会失败
  outHeaders['Host'] = url.host;

  const relayCfg = relayConfig();
  let connectUrl = url;
  if (shouldRelay(url.hostname, relayCfg)) {
    const applied = applyRelay(url, outHeaders, relayCfg);
    connectUrl = applied.url;
    Object.assign(outHeaders, applied.headers);
  }

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
  // (TCP 443) and connect to the IP with SNI = original hostname.
  const isHttps = connectUrl.protocol === 'https:';
  const requestLib = isHttps ? httpsRequest : httpRequest;
  let conn;
  try {
    conn = await dohConnect(connectUrl.hostname, { skip: !isHttps });
  } catch (e) {
    throw new Error(`${e.message} (UDP/53 blocked on this host; DoH over TCP/443 also failed)`);
  }
  const timeoutHost =
    connectUrl.hostname === url.hostname
      ? url.hostname
      : `${url.hostname} via ${connectUrl.hostname}`;
  const upstreamResp = await new Promise((resolve, reject) => {
    const req = requestLib(
      {
        protocol: connectUrl.protocol,
        hostname: conn.hostname,
        port: connectUrl.port || (isHttps ? 443 : 80),
        method: method || 'GET',
        path: connectUrl.pathname + connectUrl.search,
        headers: outHeaders,
        timeout: 15000,
        ...(isHttps ? { servername: conn.servername } : {}),
      },
      resolve,
    );
    req.on('error', reject);
    req.on('timeout', () =>
      req.destroy(
        new Error(
          `Upstream timeout after 15s connecting to ${timeoutHost} (TCP/TLS idle — not a DNS failure)`,
        ),
      ),
    );
    if (fetchOpts.body) req.write(fetchOpts.body);
    req.end();
  });
  const latency = Date.now() - start;

  // Read response headers through the proxy boundary sanitizer. The response
  // body is not auto-decompressed by https.request, so Content-Encoding and
  // Content-Length remain valid and must be preserved.
  const respHeaders = sanitizeProxyResponseHeaders(upstreamResp.headers);

  // Bound response buffering so a misbehaving or malicious upstream cannot
  // exhaust broker memory. The limit is configurable but hard-capped.
  const respBuf = await readLimitedResponseBody(
    upstreamResp,
    maxUpstreamResponseBytes(process.env),
  );
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
const configTransactions = createMutationGate();
async function handle(req, res) {
  const pathname = new URL(req.url || '/', 'https://broker.invalid').pathname;
  const mutates =
    !['GET', 'HEAD', 'OPTIONS'].includes(req.method) &&
    /^\/api\/v1\/(login|logout|me|api-keys|admin|reload|rotate)(?:\/|$)/.test(pathname) &&
    !pathname.endsWith('/test') &&
    pathname !== '/api/v1/healthcheck/run';
  if (mutates) {
    // Read bounded input before taking the transaction gate; slow uploaders
    // must not hold the configuration lock.
    bufferedMutationBodies.set(req, await readBodySafe(req));
    return configTransactions.run(() => handleRequest(req, res));
  }
  await configTransactions.idle();
  return handleRequest(req, res);
}

async function handleRequest(req, res) {
  return runWithRequestContext(req.headers || {}, async () => {
    setResponseTraceHeaders(res);
    if (rejectIfShuttingDown(globalThis.__brokerShuttingDown || (() => false), res, jsonError)) {
      return;
    }

    const url = new URL(req.url, `https://${req.headers.host}`);
    const m = req.method;
    const p = url.pathname;
    const t0 = Date.now();
    const route = { method: m, pathname: p };
    const rejectBrowserMutation = (action, { ctx = null, requireOrigin = false } = {}) => {
      const browserCheck = checkTrustedBrowserMutation(req, { requireOrigin });
      if (browserCheck.ok) return false;
      audit({
        action,
        status: 'denied',
        reason: browserCheck.reason,
        cn: ctx?.cn,
        fp: ctx?.fp,
        method: m,
        path: p,
        origin: browserCheck.origin || '(missing)',
      });
      jsonError(res, 403, 'Browser request origin is not trusted');
      return true;
    };

    // Phase AF: modular request pipeline (public routes)
    {
      const publicDeps = {
        send,
        jsonError,
        readBody,
        version: typeof BROKER_VERSION !== 'undefined' ? BROKER_VERSION : 'unknown',
        secretCache: SECRET_CACHE,
        config: CONFIG,
        dashboardDir: join(__dirname, 'dashboard'),
        requireSops: true,
        runReadyProbes: () => runProbes(probesFromConfig(CONFIG || {})),
        surface: 'public',
        isLocal: isDirectLocalRequest(req),
        ctx: getIdentity(req),
      };
      if (await handleHealth(req, res, route, publicDeps)) {
        observeMs('broker_http_request_duration_ms', Date.now() - t0);
        inc('broker_http_requests_total', 1, { route: p });
        return;
      }
      if (handleStatic(req, res, route, publicDeps)) {
        observeMs('broker_http_request_duration_ms', Date.now() - t0);
        inc('broker_http_requests_total', 1, { route: p });
        return;
      }
      if (handleMetrics(req, res, route, publicDeps)) {
        observeMs('broker_http_request_duration_ms', Date.now() - t0);
        return;
      }
    }

    // Public /health + dashboard static are handled by the modular pipeline above.

    // ----- POST /api/v1/login: mTLS cert OR allow_password_login client -> session token -----
    // Login must work from a browser that may not have a client cert installed.
    // Security: password-only login requires the client to be explicitly marked
    // `allow_password_login: true` in broker.yaml AND is protected by a
    // per-client lockout (5 fails -> 15 min). mTLS remains the strong default.
    if (m === 'POST' && p === '/api/v1/login') {
      if (rejectBrowserMutation('login_origin')) return;
      const body = (await readBody(req)) || {};
      const password = body.password;
      if (!password) return jsonError(res, 400, 'Missing {password}');
      const ctx0 = getIdentity(req);
      let targetClient = null,
        targetName = null,
        lockKey = null,
        via = 'mtls';
      if (ctx0 && (ctx0.via === 'mtls' || ctx0.via === 'mtls-header')) {
        if (!ctx0.client.password) {
          return jsonError(res, 403, 'No password configured for this client');
        }
        targetClient = ctx0.client;
        targetName = ctx0.clientName;
        lockKey = `${targetName}|mtls`;
      } else {
        // password-only login: client name is required and must opt in
        const clientName = (body.client || '').trim();
        const c = clientName ? CONFIG.clients[clientName] : null;
        if (!c || !c.allow_password_login) {
          audit({
            action: 'login',
            status: 'denied',
            reason: 'password_login_not_allowed',
            client: clientName || '(none)',
          });
          return jsonError(
            res,
            401,
            'mTLS client certificate required; or pass {client} with allow_password_login: true',
          );
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
      const fp = via === 'mtls' ? ctx0.fp : null;
      if (isMfaRequired(targetClient, via)) {
        const mfaToken = createMfaPending(targetName, fp, {
          securityBinding: mfaClientBinding(targetClient),
        });
        audit({ action: 'login', status: 'mfa_required', client: targetName, via });
        return send(res, 200, {
          ok: false,
          mfa_required: true,
          mfa_token: mfaToken,
          expires_in: MFA_TOKEN_TTL_MS / 1000,
          method: via,
        });
      }

      const cn = via === 'mtls' ? ctx0.cn : `${targetName}@web`;
      const token = makeSession({
        cn,
        fp,
        role: targetClient.role,
        clientName: targetName,
        cert: { subject: { CN: cn } },
        client: targetClient,
      });
      audit({ action: 'login', status: 'ok', cn, client: targetName, via });
      res.setHeader('Set-Cookie', sessionCookieHeader(token));
      return send(res, 200, {
        ...(isBrowserRequest(req) ? {} : { token }),
        expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
        cn,
        role: targetClient.role,
        via,
      });
    }

    // ----- POST /api/v1/login/mfa: 提交 TOTP code 完成登录 -----
    if (m === 'POST' && p === '/api/v1/login/mfa') {
      if (rejectBrowserMutation('login_mfa_origin')) return;
      const body = (await readBody(req)) || {};
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
        audit({
          action: 'login_mfa',
          status: 'denied',
          reason: 'client_gone',
          client: pending.clientName,
        });
        return jsonError(res, 404, 'Client no longer exists');
      }
      if (pending.securityBinding !== mfaClientBinding(targetClient)) {
        consumeMfaPending(mfaToken);
        return jsonError(res, 401, 'Authentication state changed; log in again');
      }
      const mfaLock = `mfa:${pending.clientName}`;
      if (!checkLoginLock(mfaLock)) return jsonError(res, 429, 'Too many MFA attempts');
      const mfaResult = verifyMfaCode(targetClient, code);
      if (!mfaResult.ok) {
        recordLoginFail(mfaLock);
        audit({
          action: 'login_mfa',
          status: 'denied',
          reason: 'bad_code',
          client: pending.clientName,
        });
        return jsonError(res, 401, 'Bad TOTP code or recovery code');
      }
      if (mfaResult.method === 'recovery') {
        try {
          await persistConfig();
        } catch (e) {
          restoreConsumedRecoveryCode(targetClient, mfaResult);
          audit({
            action: 'login_mfa',
            status: 'error',
            reason: 'recovery_code_persist_failed',
            client: pending.clientName,
            error: e.message,
          });
          return persistenceError(res);
        }
      }
      clearLoginLock(mfaLock);
      consumeMfaPending(mfaToken);
      const cn = pending.fp ? `${pending.clientName}@mtls` : `${pending.clientName}@web`;
      const token = makeSession({
        cn,
        fp: pending.fp,
        role: targetClient.role,
        clientName: pending.clientName,
        cert: { subject: { CN: cn } },
        client: targetClient,
      });
      audit({
        action: 'login',
        status: 'ok',
        cn,
        client: pending.clientName,
        via: 'mfa',
        mfa_method: mfaResult.method,
      });
      res.setHeader('Set-Cookie', sessionCookieHeader(token));
      return send(res, 200, {
        ...(isBrowserRequest(req) ? {} : { token }),
        expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
        cn,
        role: targetClient.role,
        via: 'mfa',
        mfa_method: mfaResult.method,
      });
    }

    // ----- POST /api/v1/logout (drop session token) -----
    if (m === 'POST' && p === '/api/v1/logout') {
      if (
        isCookieSessionRequest(req) &&
        rejectBrowserMutation('logout_origin', { requireOrigin: true })
      ) {
        return;
      }
      const token =
        req.headers[SESSION_HEADER] ||
        (req.headers.cookie || '').match(/broker_session=([^;]+)/)?.[1];
      if (token) {
        const s = SESSIONS.get(token);
        if (s) audit({ action: 'logout', cn: s.cn, fp: s.fp, status: 'ok' });
        deleteSession(token);
      }
      res.setHeader('Set-Cookie', sessionCookieHeader('', { clear: true }));
      return send(res, 200, { logged_out: true });
    }

    // ----- Everything below needs auth (mTLS cert or session token) -----
    const ctx = getIdentity(req);
    if (!ctx || !ctx.certSubject) {
      audit({
        action: 'connect',
        status: 'denied',
        reason: 'no_client_cert',
        remote: req.socket.remoteAddress,
      });
      return jsonError(res, 401, 'mTLS client certificate required');
    }
    if (!ctx.client) {
      audit({
        action: 'connect',
        status: 'denied',
        reason: 'cert_not_registered',
        cn: ctx.cn,
        fp: ctx.fp,
        remote: req.socket.remoteAddress,
      });
      return jsonError(res, 403, `Client certificate not registered. CN=${ctx.cn} fp=${ctx.fp}`);
    }
    if (!rateLimit(ctx)) {
      audit({ action: 'connect', status: 'denied', reason: 'rate_limit', cn: ctx.cn, fp: ctx.fp });
      return jsonError(res, 429, 'Rate limit exceeded');
    }
    if (ctx.via === 'api_key' && !isApiKeyRouteAllowed(m, p)) {
      audit({
        action: 'connect',
        status: 'denied',
        reason: 'api_key_route_denied',
        cn: ctx.cn,
        path: p,
        method: m,
      });
      return jsonError(res, 403, 'API key is not allowed to manage the owning account');
    }
    if (
      ((ctx.via === 'session' && isCookieSessionRequest(req)) ||
        (['mtls', 'mtls-header'].includes(ctx.via) && isBrowserRequest(req))) &&
      rejectBrowserMutation('session_origin', { ctx, requireOrigin: true })
    ) {
      return;
    }
    res.__exposeBrokerVersion = true;

    const requireStepUp = async (code, action, subject = null) => {
      if (!code || typeof code !== 'string') {
        audit({
          action,
          status: 'denied',
          reason: 'missing_verify',
          cn: ctx.cn,
          fp: ctx.fp,
          subject,
        });
        jsonError(res, 400, 'Missing {verify}');
        return null;
      }
      const verification = verifyStepUp(ctx.client, code);
      if (!verification.ok) {
        audit({
          action,
          status: 'denied',
          reason: 'bad_verify',
          cn: ctx.cn,
          fp: ctx.fp,
          subject,
        });
        jsonError(res, 401, 'Invalid verification code or password');
        return null;
      }
      if (verification.method === 'recovery') {
        try {
          await persistConfig();
        } catch (error) {
          restoreConsumedRecoveryCode(ctx.client, verification);
          audit({
            action,
            status: 'error',
            reason: 'recovery_code_persist_failed',
            cn: ctx.cn,
            fp: ctx.fp,
            subject,
            error: error.message,
          });
          persistenceError(res);
          return null;
        }
      }
      return verification;
    };

    // Authenticated ops health (version / sops / counts). Public GET /health is {status:ok} only.
    if (m === 'GET' && p === '/api/v1/health') {
      return send(
        res,
        200,
        buildOpsHealth({
          version: BROKER_VERSION,
          secretCache: SECRET_CACHE,
          config: CONFIG,
        }),
      );
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
      const certOnDisk = existsSync(cp.crt);
      const privateKeyOnDisk = existsSync(cp.key);
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
        cert_key_present_on_disk: privateKeyOnDisk,
        private_key_retention_enabled: RETAIN_CLIENT_PRIVATE_KEYS,
        cert_expires_at: c.cert_expires_at || null,
        last_password_change: c.last_password_change || null,
        last_cert_rotation: c.last_cert_rotation || null,
        rate_limit: c.rate_limit || '100/hour',
      });
    }

    // ----- POST /api/v1/me/change-password -----
    if (m === 'POST' && p === '/api/v1/me/change-password') {
      const body = (await readBody(req)) || {};
      const { old_password: oldPwd, new_password: newPwd } = body;
      if (!oldPwd || !newPwd) return jsonError(res, 400, 'Missing {old_password, new_password}');
      if (newPwd.length < 12) return jsonError(res, 400, 'new_password too short (min 12 chars)');
      const c = ctx.client;
      if (!c.password) return jsonError(res, 400, 'No password set for this client');
      const oldOk = verifyClientPassword(oldPwd, c.password);
      if (!oldOk) {
        audit({
          action: 'me_change_password',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_old',
        });
        return jsonError(res, 401, 'Old password incorrect');
      }
      if (verifyClientPassword(newPwd, c.password)) {
        return jsonError(res, 400, 'New password must differ from the current password');
      }

      const previous = {
        password: c.password,
        password_set_at: c.password_set_at,
        last_password_change: c.last_password_change,
      };
      const passwordSetAt = new Date().toISOString();
      c.password = hashPassword(newPwd);
      c.password_set_at = passwordSetAt;
      c.last_password_change = passwordSetAt;
      try {
        await persistConfig();
      } catch (e) {
        c.password = previous.password;
        c.password_set_at = previous.password_set_at;
        c.last_password_change = previous.last_password_change;
        audit({
          action: 'me_change_password',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return jsonError(res, 500, 'Unable to persist password change');
      }

      const sessionsRevoked = deleteSessionsForClient(ctx.clientName);
      res.setHeader('Set-Cookie', sessionCookieHeader('', { clear: true }));
      audit({
        action: 'me_change_password',
        cn: ctx.cn,
        fp: ctx.fp,
        status: 'ok',
        sessions_revoked: sessionsRevoked,
      });
      return send(res, 200, {
        ok: true,
        password_set_at: passwordSetAt,
        sessions_revoked: sessionsRevoked,
        reauthentication_required: true,
      });
    }

    // ----- POST /api/v1/me/rotate-cert -----
    // v3.0: 重发自己的 cert（要当前 TOTP 验证或密码）
    if (m === 'POST' && p === '/api/v1/me/rotate-cert') {
      const body = (await readBody(req)) || {};
      const verify = body.verify; // TOTP code 或 密码
      if (!verify) return jsonError(res, 400, 'Missing {verify}');
      const c = ctx.client;
      const verification = verifyStepUp(c, verify);
      if (!verification.ok) {
        audit({
          action: 'me_rotate_cert',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_verify',
        });
        return jsonError(res, 401, 'Invalid TOTP code or password');
      }
      if (!clientsDirWritable()) {
        restoreConsumedRecoveryCode(c, verification);
        return jsonError(res, 503, 'pki/clients/ is not writable; issue cert out-of-band');
      }
      let issuance;
      try {
        issuance = await issueAndPersist(ctx.clientName);
      } catch (e) {
        restoreConsumedRecoveryCode(c, verification);
        audit({
          action: 'me_rotate_cert',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return jsonError(res, 500, 'Unable to rotate client certificate');
      }
      const sessionsRevoked = deleteSessionsForFingerprint(issuance.previousFingerprint);
      audit({
        action: 'me_rotate_cert',
        cn: ctx.cn,
        fp: ctx.fp,
        status: 'ok',
        mfa_method: verification.method,
        sessions_revoked: sessionsRevoked,
      });
      return send(res, 200, {
        ok: true,
        name: ctx.clientName,
        fingerprint_sha256: issuance.cert.fingerprint_sha256,
        cert_pem: issuance.cert.cert_pem,
        key_pem: issuance.cert.key_pem,
        bundle_base64: issuance.bundle.toString('base64'),
        cert_expires_at: c.cert_expires_at,
        sessions_revoked: sessionsRevoked,
        private_key_retained: issuance.privateKeyRetained,
        warning: issuance.privateKeyRetained
          ? 'key_pem is a SECRET. Compatibility retention is enabled; disable BROKER_RETAIN_CLIENT_PRIVATE_KEYS after migration.'
          : 'key_pem and bundle_base64 are one-time secrets. Save one now; the broker has removed the private-key file.',
      });
    }

    // ----- GET /api/v1/me/audit -----
    if (m === 'GET' && p === '/api/v1/me/audit') {
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 1000);
      const since = url.searchParams.get('since');
      const lines = readAuditFiltered({ cn: ctx.cn, since, limit });
      return send(res, 200, { events: lines, count: lines.length, fp: ctx.fp });
    }

    // ----- POST /api/v1/me/totp/setup -----
    // 启 TOTP: 要当前密码 (一次性验证)，返 otpauth URL + 10 个恢复码
    // 进入"待激活"状态，必须 /totp/verify 一次正确码才正式启用
    if (m === 'POST' && p === '/api/v1/me/totp/setup') {
      const body = (await readBody(req)) || {};
      const { password } = body;
      if (!password) return jsonError(res, 400, 'Missing {password}');
      const c = ctx.client;
      if (!c.password) return jsonError(res, 400, 'No password set; cannot setup TOTP');
      if (!verifyClientPassword(password, c.password)) {
        audit({
          action: 'me_totp_setup',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_password',
        });
        return jsonError(res, 401, 'Password incorrect');
      }
      if (c.totp_secret) {
        return jsonError(res, 409, 'TOTP already enabled; disable first');
      }
      const secret = generateSecret();
      const recoveryCodes = generateRecoveryCodes();
      const recoveryHashes = recoveryCodes.map(hashRecoveryCode);
      // 暂存到"待激活"字段（不写入 totp_secret 主字段，直到 verify 成功）。
      // 明文恢复码仅存在于本次响应变量中，不进入 client 状态。
      c._pending_totp = createPendingTotp(secret, recoveryHashes);
      audit({ action: 'me_totp_setup', cn: ctx.cn, fp: ctx.fp, status: 'pending' });
      return send(res, 200, {
        ok: true,
        otpauth_url: buildOtpauthURL(ctx.clientName, 'SecretBroker', secret),
        secret, // 让用户能手动输入 (无 App 也能登)
        recovery_codes: recoveryCodes, // 仅此一次
        recovery_codes_remaining: recoveryCodes.length,
        expires_at: c._pending_totp.expires_at,
        next_step: 'POST /api/v1/me/totp/verify with a TOTP code to activate',
      });
    }

    // ----- POST /api/v1/me/totp/verify -----
    // setup 后必须 verify 一次才正式启用
    if (m === 'POST' && p === '/api/v1/me/totp/verify') {
      const body = (await readBody(req)) || {};
      const { code } = body;
      if (!code) return jsonError(res, 400, 'Missing {code}');
      const c = ctx.client;
      if (!c._pending_totp) {
        return jsonError(res, 400, 'No pending TOTP setup; call /totp/setup first');
      }
      if (isPendingTotpExpired(c._pending_totp)) {
        delete c._pending_totp;
        audit({
          action: 'me_totp_verify',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'setup_expired',
        });
        return jsonError(res, 410, 'Pending TOTP setup expired; start again');
      }
      const ok = verifyTotpFn(c._pending_totp.secret, code);
      if (!ok) {
        audit({
          action: 'me_totp_verify',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_code',
        });
        return jsonError(res, 401, 'TOTP code does not match');
      }
      const clientSnapshot = structuredClone(c);
      // 激活：pending → 正式字段
      c.totp_secret = c._pending_totp.secret;
      c.totp_enabled_at = new Date().toISOString();
      c.totp_recovery_codes_hash = c._pending_totp.recovery_hashes;
      c.preferred_2fa = 'totp';
      delete c._pending_totp;
      try {
        await persistConfig();
      } catch (e) {
        restorePlainObject(c, clientSnapshot);
        audit({
          action: 'me_totp_verify',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
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
      const body = (await readBody(req)) || {};
      const { code } = body;
      if (!code) return jsonError(res, 400, 'Missing {code}');
      const c = ctx.client;
      if (!c.totp_secret) return jsonError(res, 400, 'TOTP not enabled');
      const clientSnapshot = structuredClone(c);
      const mfaResult = verifyMfaCode(c, code);
      if (!mfaResult.ok) {
        audit({
          action: 'me_totp_disable',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_code',
        });
        return jsonError(res, 401, 'TOTP code or recovery code invalid');
      }
      delete c.totp_secret;
      delete c.totp_enabled_at;
      delete c.totp_recovery_codes_hash;
      c.preferred_2fa = 'none';
      try {
        await persistConfig();
      } catch (e) {
        restorePlainObject(c, clientSnapshot);
        audit({
          action: 'me_totp_disable',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({
        action: 'me_totp_disable',
        cn: ctx.cn,
        fp: ctx.fp,
        status: 'ok',
        mfa_method: mfaResult.method,
      });
      return send(res, 200, { ok: true, totp_disabled: true });
    }

    // ----- GET /api/v1/me/recovery-codes/remaining -----
    if (m === 'GET' && p === '/api/v1/me/recovery-codes/remaining') {
      const c = ctx.client;
      return send(res, 200, {
        remaining: (c.totp_recovery_codes_hash || []).length,
        warning:
          c.totp_recovery_codes_hash && c.totp_recovery_codes_hash.length < 3
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
      const body = (await readBody(req)) || {};
      const name = (body.name || '').trim();
      if (!name) return jsonError(res, 400, 'Missing {name}');
      // 创建者 = 自己 (admin 可指定 client)
      const targetClient =
        body.client && ctx.client.role === 'admin' ? body.client : ctx.clientName;
      if (!CONFIG.clients[targetClient]) {
        return jsonError(res, 400, `Unknown client: ${targetClient}`);
      }
      // 二次验证: 当前 TOTP code (强制)
      const verifyCode = body.verify;
      if (!verifyCode) return jsonError(res, 400, 'Missing {verify} (TOTP code)');
      // self 验证: 自己的 TOTP / 恢复码；admin 可 fallback 密码
      let verification = null;
      if (ctx.client.totp_secret || ctx.client.totp_recovery_codes_hash?.length) {
        const mfaR = verifyMfaCode(ctx.client, verifyCode);
        if (mfaR.ok) verification = mfaR;
      }
      if (
        !verification &&
        ctx.client.role === 'admin' &&
        !ctx.client.totp_secret &&
        !ctx.client.totp_recovery_codes_hash?.length &&
        ctx.client.password &&
        verifyClientPassword(verifyCode, ctx.client.password)
      ) {
        verification = { ok: true, method: 'password' };
      }
      if (!verification) {
        audit({
          action: 'api_key_create',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: 'bad_verify',
        });
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
      try {
        await persistConfig();
      } catch (e) {
        // 回滚 key 与可能已消费的恢复码
        const idx = CONFIG.api_keys.findIndex((k) => k.id === r.key_obj.id);
        if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
        restoreConsumedRecoveryCode(ctx.client, verification);
        audit({
          action: 'api_key_create',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({
        action: 'api_key_create',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        client: targetClient,
        status: 'ok',
      });
      return send(res, 200, {
        ok: true,
        key: r.key_obj, // public view
        secret: r.secret, // 仅此一次返回
        warning: 'secret will not be shown again. Save it now.',
      });
    }

    // ----- GET /api/v1/api-keys/:id (静态优先, 必须在 :id/usage 之前) -----
    const apiKeyMatch = p.match(/^\/api\/v1\/api-keys\/([a-z0-9]{16})$/);
    const apiKeyUsageMatch = p.match(/^\/api\/v1\/api-keys\/([a-z0-9]{16})\/usage$/);
    if (m === 'GET' && apiKeyMatch && apiKeyMatch[1]) {
      const id = apiKeyMatch[1];
      const k = CONFIG.api_keys.find((x) => x.id === id);
      if (!k) return jsonError(res, 404, `API key ${id} not found`);
      if (ctx.client.role !== 'admin' && k.client !== ctx.clientName) {
        return jsonError(res, 403, 'Not your API key');
      }
      return send(res, 200, { key: publicViewFn(k) });
    }

    // ----- DELETE /api/v1/api-keys/:id -----
    if (m === 'DELETE' && apiKeyMatch && apiKeyMatch[1]) {
      const id = apiKeyMatch[1];
      const k = CONFIG.api_keys.find((x) => x.id === id);
      if (!k) return jsonError(res, 404, `API key ${id} not found`);
      if (ctx.client.role !== 'admin' && k.client !== ctx.clientName) {
        return jsonError(res, 403, 'Not your API key');
      }
      const body = (await readBody(req)) || {};
      const verifyCode = body.verify;
      if (!verifyCode) return jsonError(res, 400, 'Missing {verify}');
      let verification = null;
      if (ctx.client.totp_secret || ctx.client.totp_recovery_codes_hash?.length) {
        const mfaR = verifyMfaCode(ctx.client, verifyCode);
        if (mfaR.ok) verification = mfaR;
      }
      if (
        !verification &&
        ctx.client.role === 'admin' &&
        !ctx.client.totp_secret &&
        !ctx.client.totp_recovery_codes_hash?.length &&
        ctx.client.password &&
        verifyClientPassword(verifyCode, ctx.client.password)
      ) {
        verification = { ok: true, method: 'password' };
      }
      if (!verification) {
        audit({
          action: 'api_key_revoke',
          cn: ctx.cn,
          fp: ctx.fp,
          name: k.name,
          status: 'denied',
          reason: 'bad_verify',
        });
        return jsonError(res, 401, 'Invalid TOTP code or password');
      }
      const keySnapshot = structuredClone(k);
      const r = revokeApiKeyFn(CONFIG.api_keys, id, ctx.clientName);
      if (!r.ok) {
        return jsonError(res, 400, r.reason);
      }
      try {
        await persistConfig();
      } catch (e) {
        restorePlainObject(k, keySnapshot);
        restoreConsumedRecoveryCode(ctx.client, verification);
        audit({
          action: 'api_key_revoke',
          cn: ctx.cn,
          fp: ctx.fp,
          name: k.name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({ action: 'api_key_revoke', cn: ctx.cn, fp: ctx.fp, name: k.name, status: 'ok' });
      return send(res, 200, { ok: true, id, revoked_at: k.revoked_at });
    }

    // ----- GET /api/v1/api-keys/:id/usage -----
    if (m === 'GET' && apiKeyUsageMatch && apiKeyUsageMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const id = apiKeyUsageMatch[1];
      const k = CONFIG.api_keys.find((x) => x.id === id);
      if (!k) return jsonError(res, 404, `API key ${id} not found`);
      // API key identities are audited as cn=apikey:<id>; filter exactly so
      // usage for one key can never include another client's audit events.
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 1000);
      const lines = readAuditFiltered({ cn: `apikey:${k.id}`, since: null, limit });
      return send(res, 200, {
        id,
        name: k.name,
        use_count: k.use_count,
        last_used_at: k.last_used_at,
        events: lines,
      });
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
      const body = (await readBody(req)) || {};
      const name = (body.name || '').trim();
      if (!name) return jsonError(res, 400, 'Missing {name}');
      for (const field of ['child_scopes', 'allowed_secrets', 'allowed_services', 'ip_whitelist']) {
        if (body[field] !== undefined && !Array.isArray(body[field])) {
          return jsonError(res, 400, `${field} must be an array`);
        }
      }
      // TOTP / 恢复码强制；admin password 可作 fallback
      const verifyCode = body.verify;
      if (!verifyCode) return jsonError(res, 400, 'Missing {verify}');
      let verification = null;
      if (ctx.client.totp_secret || ctx.client.totp_recovery_codes_hash?.length) {
        const mfaR = verifyMfaCode(ctx.client, verifyCode);
        if (mfaR.ok) verification = mfaR;
      }
      if (
        !verification &&
        !ctx.client.totp_secret &&
        !ctx.client.totp_recovery_codes_hash?.length &&
        ctx.client.password &&
        verifyClientPassword(verifyCode, ctx.client.password)
      ) {
        verification = { ok: true, method: 'password' };
      }
      if (!verification) {
        audit({
          action: 'master_key_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'denied',
          reason: 'bad_verify',
        });
        return jsonError(res, 401, 'Invalid TOTP code or password');
      }
      const { id, secret, key_obj } = generateMasterKey(name, ctx.clientName, {
        default_child_ttl_seconds: body.default_child_ttl_seconds,
        child_scopes: Array.isArray(body.child_scopes) ? body.child_scopes : undefined,
        allowed_secrets: Array.isArray(body.allowed_secrets) ? body.allowed_secrets : undefined,
        allowed_services: Array.isArray(body.allowed_services) ? body.allowed_services : undefined,
        rate_limit: body.rate_limit,
        ip_whitelist: Array.isArray(body.ip_whitelist) ? body.ip_whitelist : null,
        ttl_ms: body.ttl_ms,
        created_by: ctx.clientName,
      });
      CONFIG.api_keys.push(key_obj);
      try {
        await persistConfig();
      } catch (e) {
        const idx = CONFIG.api_keys.findIndex((x) => x.id === id);
        if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
        restoreConsumedRecoveryCode(ctx.client, verification);
        audit({
          action: 'master_key_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({ action: 'master_key_create', cn: ctx.cn, fp: ctx.fp, name, status: 'ok', id });
      return send(res, 200, {
        ok: true,
        key: publicViewFn(key_obj),
        secret,
        warning:
          'Master key will not be shown again. Save it now. Use POST /api/v1/api-keys/issue-child to mint short-lived child keys.',
      });
    }

    // ----- GET /api/v1/api-keys/master -----
    if (m === 'GET' && p === '/api/v1/api-keys/master') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const masters = (CONFIG.api_keys || []).filter((k) => k.is_master);
      return send(res, 200, { keys: masters.map(publicViewFn) });
    }

    // ----- POST /api/v1/api-keys/issue-child -----
    if (m === 'POST' && p === '/api/v1/api-keys/issue-child') {
      // 必须用 API Key (Bearer) + is_master + can_create_child
      if (ctx.via !== 'api_key') {
        return jsonError(
          res,
          401,
          'This endpoint requires Master API Key (Authorization: Bearer ...)',
        );
      }
      const master = ctx.apiKey;
      const check = canCreateChild(master);
      if (!check.ok) {
        audit({
          action: 'issue_child',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'denied',
          reason: check.reason,
        });
        return jsonError(res, 403, `Master key cannot create child: ${check.reason}`);
      }
      const body = (await readBody(req)) || {};
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
        audit({
          action: 'issue_child',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          reason: r.reason,
        });
        return jsonError(res, 400, `Cannot create child: ${r.reason}`);
      }
      try {
        await persistConfig();
      } catch (e) {
        const idx = CONFIG.api_keys.findIndex((x) => x.id === r.key_obj.id);
        if (idx >= 0) CONFIG.api_keys.splice(idx, 1);
        audit({
          action: 'issue_child',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({
        action: 'issue_child',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        child_id: r.key_obj.id,
        status: 'ok',
      });
      return send(res, 200, {
        ok: true,
        key: r.key_obj,
        secret: r.secret,
        warning: 'Child key will not be shown again. It will expire in ttl_seconds.',
        parent_master_id: master.id,
      });
    }

    // V4.1.1: Read-only API routes (identity, services, secrets, secrets/resolve)
    // extracted to broker/routes/read-api.js for testability.
    // The routes are constructed lazily on first use because they close over
    // module-level state (CONFIG, SECRET_CACHE, audit, ...) that may be reloaded.
    if (m === 'GET' || (m === 'POST' && p === '/api/v1/secrets/resolve')) {
      if (await readApiRoutes().dispatch(req, res, { method: m, pathname: p }, ctx)) return;
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

    // ============================================================
    // v3.0 M4: 凭据自检与告警
    // ============================================================
    // GET  /api/v1/healthcheck/status    — 看最新一次自检结果
    // POST /api/v1/healthcheck/run       — 手动触发 (admin)
    // ============================================================

    // ----- GET /api/v1/healthcheck/status -----
    if (m === 'GET' && p === '/api/v1/healthcheck/status') {
      const s = healthcheckGetStatus();
      const visible = filteredHealthStatus(s, (name) => canResolve(ctx, name), {
        admin: ctx.client.role === 'admin',
      });
      return send(res, 200, visible);
    }

    // ----- POST /api/v1/healthcheck/run (admin) -----
    if (m === 'POST' && p === '/api/v1/healthcheck/run') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      // v3.0 M5: upstream 模式决定走 broker 本地 (默认) 或 mcp-server (出网绕过)
      // 配置: broker.yaml healthcheck: { upstream: 'mcp_server'|'local', mcp_server_url: 'http://127.0.0.1:3001' }
      const hcCfg = CONFIG.healthcheck || {};
      const upstream = hcCfg.upstream || 'local';
      const mcpUrl = hcCfg.mcp_server_url || 'http://127.0.0.1:3001';
      try {
        let r;
        if (upstream === 'mcp_server') {
          r = await healthcheckRunAllViaMcp(mcpUrl);
        } else {
          // local: 返 entry 完整 (type + fields + description), 让 healthcheck 按 type-schemas 抽字段
          const getSecrets = () => {
            const out = {};
            for (const [name, entry] of SECRET_CACHE) {
              out[name] = {
                type: entry.type,
                fields: entry.fields || {},
                description: entry.description || '',
              };
            }
            return out;
          };
          r = await healthcheckRunAll(getSecrets);
        }
        // 同步写 audit
        for (const [name, c] of Object.entries(r.checks)) {
          audit({
            action: 'healthcheck',
            cn: ctx.cn,
            fp: ctx.fp,
            secret: name,
            status: c.status,
            detail: c.detail,
            latency_ms: c.latency_ms,
          });
        }
        return send(res, 200, r);
      } catch (e) {
        audit({
          action: 'healthcheck_run',
          cn: ctx.cn,
          fp: ctx.fp,
          status: 'error',
          error: e.message,
        });
        return jsonError(res, 500, 'Healthcheck run failed');
      }
    }

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
          // v3.1.1 M5.9: 轮换历史 (前 10 条, 倒序 — 最新在前)
          rotation_history: Array.isArray(entry.rotation_history)
            ? entry.rotation_history.slice(0, 10)
            : [],
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
      const body = (await readBody(req)) || {};
      const { name, type, description, fields } = body;
      if (!isValidSecretName(name)) {
        return jsonError(
          res,
          400,
          'Invalid secret name. Use [A-Za-z0-9_.-], must start with letter/digit/underscore, max 128 chars.',
        );
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
        audit({
          action: 'admin_secrets_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'denied',
          reason: 'already_exists',
        });
        return jsonError(res, 409, `Secret ${name} already exists. Use PUT to update.`);
      }
      const now = new Date().toISOString();
      const who = ctx.cn || 'admin';
      SECRET_CACHE.set(name, {
        type,
        description: description || '',
        fields,
        created_at: now,
        updated_at: now,
        updated_by: who,
      });
      try {
        await persistSecretsDetail();
      } catch (e) {
        SECRET_CACHE.delete(name);
        audit({
          action: 'admin_secrets_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({ action: 'admin_secrets_create', cn: ctx.cn, fp: ctx.fp, name, type, status: 'ok' });
      return send(res, 200, { ok: true, name, type });
    }

    // ----- PUT /api/v1/admin/secrets/:name (update) -----
    // Match the create endpoint's SECRET_NAME_RE exactly, so any name POST accepts
    // is also routable via PUT/DELETE. The previous hard-coded `[A-Za-z0-9_.]+`
    // silently 404'd for names containing hyphens (e.g. `aliyun-1786567607488`).
    const updateMatch = p.match(
      /^\/api\/v1\/admin\/secrets\/([A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})$/,
    );
    if (m === 'PUT' && updateMatch && updateMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const name = updateMatch[1];
      const existing = SECRET_CACHE.get(name);
      if (!existing) return jsonError(res, 404, `Secret ${name} not found`);
      const body = (await readBody(req)) || {};
      const updated = { ...existing };
      if (body.type !== undefined) {
        if (!ALLOWED_SECRET_TYPES.has(body.type)) {
          return jsonError(res, 400, `Unknown type: ${body.type}`);
        }
        updated.type = body.type;
      }
      if (body.description !== undefined) {
        updated.description = String(body.description);
      }
      if (body.fields !== undefined) {
        if (typeof body.fields !== 'object') {
          return jsonError(res, 400, '{fields} must be an object');
        }
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
        audit({
          action: 'admin_secrets_update',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
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
        audit({
          action: 'admin_secrets_delete',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
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
          allow_insecure_http: svc.allow_insecure_http === true,
          region: svc.region || '',
          action: svc.action || '',
          token_secret: svc.token_secret || null,
          inject_headers: svc.inject_headers || {},
          header_name: svc.header_name || null,
          header_value_template: svc.header_value_template || null,
          allow_paths: svc.allow_paths || null,
          allow_methods: svc.allow_methods || null,
          dashboard_actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
          allowed_clients: clientNamesAllowedFor(CONFIG.clients, name),
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
    const svcMatch = p.match(/^\/api\/v1\/admin\/services\/([a-z][a-z0-9_-]{0,63})$/);

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
        allow_insecure_http: svc.allow_insecure_http === true,
        region: svc.region || '',
        action: svc.action || '',
        token_secret: svc.token_secret || null,
        inject_headers: svc.inject_headers || {},
        header_name: svc.header_name || null,
        header_value_template: svc.header_value_template || null,
        allow_paths: svc.allow_paths || null,
        allow_methods: svc.allow_methods || null,
        dashboard_actions: Array.isArray(svc.dashboard_actions) ? svc.dashboard_actions : [],
        allowed_clients: clientNamesAllowedFor(CONFIG.clients, name),
      });
    }

    // ----- POST /api/v1/admin/services (create) -----
    if (m === 'POST' && p === '/api/v1/admin/services') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const body = (await readBody(req)) || {};
      const name = body.name;
      const cfg = normalizeServiceConfig(body);
      const errs = validateServiceConfig(name, cfg);
      if (errs.length > 0) {
        audit({
          action: 'admin_services_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'denied',
          reason: 'validation',
          errs,
        });
        return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
      }
      if (CONFIG.services[name]) {
        audit({
          action: 'admin_services_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'denied',
          reason: 'already_exists',
        });
        return jsonError(res, 409, `Service ${name} already exists. Use PUT to update.`);
      }
      CONFIG.services[name] = cfg;
      try {
        await persistConfig();
      } catch (e) {
        delete CONFIG.services[name];
        audit({
          action: 'admin_services_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({
        action: 'admin_services_create',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        type: cfg.type,
        status: 'ok',
      });
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
      const body = (await readBody(req)) || {};
      const patch = normalizeServiceConfig(body);
      // Build the next config: existing first, then patch overrides. For
      // array fields, if the client sent an array (even empty), use it as-is;
      // if they sent nothing, preserve the existing array.
      const next = { ...existing, ...patch };
      // Special case: allow_resolve / allowed_proxy as arrays
      if (body.allowed_resolve !== undefined) next.allowed_resolve = patch.allowed_resolve || [];
      if (body.allowed_proxy !== undefined) next.allowed_proxy = patch.allowed_proxy || [];
      if (body.dashboard_actions !== undefined) {
        next.dashboard_actions = patch.dashboard_actions || [];
      }
      if (body.inject_headers !== undefined) next.inject_headers = patch.inject_headers || {};
      // Name is immutable via PUT — keep the URL's name.
      const errs = validateServiceConfig(name, next);
      if (errs.length > 0) {
        audit({
          action: 'admin_services_update',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'denied',
          reason: 'validation',
          errs,
        });
        return jsonError(res, 400, 'Validation failed: ' + errs.join('; '));
      }
      const prev = { ...existing };
      CONFIG.services[name] = next;
      try {
        await persistConfig();
      } catch (e) {
        CONFIG.services[name] = prev;
        audit({
          action: 'admin_services_update',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
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
        audit({
          action: 'admin_services_delete',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
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
      const body = (await readBody(req)) || {};
      const picked = defaultServiceTest({ ...svc, name });
      const method = body.method || picked.method || 'GET';
      const path = body.path || picked.path || '/';
      const query = body.query !== undefined ? body.query : picked.query;
      const start = Date.now();
      try {
        // Pass the service name so callUpstream's error messages are useful.
        const r = await callUpstream(
          { ...svc, name },
          method,
          path,
          query,
          body.headers,
          body.body,
          { serviceName: name },
        );
        const classified = describeUpstreamStatus(r.status, {
          path,
          hostname: (() => {
            try {
              return new URL(svc.upstream).hostname;
            } catch {
              return '';
            }
          })(),
        });
        const ok = classified.ok === true;
        audit({
          action: 'admin_services_test',
          cn: ctx.cn,
          fp: ctx.fp,
          service: name,
          method,
          path,
          upstream_status: r.status,
          latency_ms: r.latency,
          status: ok ? 'ok' : 'error',
        });
        return send(res, 200, {
          ok,
          method,
          path,
          upstream_status: r.status,
          latency_ms: r.latency,
          body_preview: r.body ? r.body.toString('utf8').slice(0, 500) : '',
          ...(classified.error ? { error: classified.error } : {}),
        });
      } catch (err) {
        audit({
          action: 'admin_services_test',
          cn: ctx.cn,
          fp: ctx.fp,
          service: name,
          method,
          path,
          status: 'error',
          error: err.message,
        });
        return send(res, 502, {
          ok: false,
          error: err.message,
          method,
          path,
          latency_ms: Date.now() - start,
        });
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
    const clientEnrollMatch = p.match(
      /^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/enrollment$/,
    );
    const clientRotateMatch = p.match(
      /^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/rotate$/,
    );
    const clientRevokeMatch = p.match(
      /^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/revoke$/,
    );
    const clientBundleMatch = p.match(
      /^\/api\/v1\/admin\/clients\/([a-z][a-z0-9_.-]{0,63})\/bundle$/,
    );

    // ----- GET /api/v1/admin/clients -----
    if (m === 'GET' && p === '/api/v1/admin/clients') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const writable = clientsDirWritable(); // probe once per list
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
      return send(res, 200, {
        clients: out,
        pki_writable: writable,
        private_key_retention_enabled: RETAIN_CLIENT_PRIVATE_KEYS,
      });
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
        private_key_retention_enabled: RETAIN_CLIENT_PRIVATE_KEYS,
        rate_limit: c.rate_limit || '100/hour',
        allowed_resolve: c.allowed_resolve || [],
        allowed_proxy: c.allowed_proxy || [],
        last_seen_ms_ago: lastSeenAgo(name),
      });
    }

    // ----- POST /api/v1/admin/clients (create) -----
    if (m === 'POST' && p === '/api/v1/admin/clients') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const body = (await readBody(req)) || {};
      const name = body.name;
      if (!isValidClientName(name)) {
        return jsonError(res, 400, 'Invalid client name. Use [a-z][a-z0-9_.-]{0,63}.');
      }
      if (CONFIG.clients[name]) {
        return jsonError(res, 409, `Client ${name} already exists.`);
      }
      let cfg;
      try {
        cfg = normalizeClientConfig(body);
      } catch (e) {
        return jsonError(res, 400, e.message);
      }
      if (cfg.password === null) delete cfg.password;
      if (cfg.allow_password_login && !cfg.password) {
        return jsonError(res, 400, 'A password is required when password login is enabled');
      }
      const verification = await requireStepUp(body.verify, 'admin_clients_create', name);
      if (!verification) return;
      CONFIG.clients[name] = cfg;
      try {
        await persistConfig();
      } catch (e) {
        delete CONFIG.clients[name];
        audit({
          action: 'admin_clients_create',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({
        action: 'admin_clients_create',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        role: cfg.role,
        status: 'ok',
        mfa_method: verification.method,
      });
      return send(res, 200, { ok: true, name, role: cfg.role });
    }

    // ----- PUT /api/v1/admin/clients/:name (update) -----
    if (m === 'PUT' && clientMatch && clientMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const name = clientMatch[1];
      const existing = CONFIG.clients[name];
      if (!existing) return jsonError(res, 404, `Client ${name} not found`);
      const body = (await readBody(req)) || {};
      let patch;
      try {
        patch = normalizeClientConfig(body);
      } catch (e) {
        return jsonError(res, 400, e.message);
      }
      // Apply patch over existing (don't touch cert_fingerprint_sha256; that's
      // owned by the enrollment flow).
      const previous = existing;
      const next = { ...existing, ...patch };
      if (Object.prototype.hasOwnProperty.call(patch, 'password') && patch.password === null) {
        delete next.password;
        delete next.password_set_at;
        delete next.last_password_change;
      }
      if (next.allow_password_login && !next.password) {
        return jsonError(res, 400, 'A password is required when password login is enabled');
      }
      const securityChanged = clientSecurityConfigChanged(existing, next);
      let verification = null;
      if (securityChanged) {
        verification = await requireStepUp(body.verify, 'admin_clients_update', name);
        if (!verification) return;
      }
      CONFIG.clients[name] = next;
      try {
        await persistConfig();
      } catch (e) {
        CONFIG.clients[name] = previous;
        audit({
          action: 'admin_clients_update',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      const sessionsRevoked = securityChanged ? deleteSessionsForClient(name) : 0;
      audit({
        action: 'admin_clients_update',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        security_changed: securityChanged,
        sessions_revoked: sessionsRevoked,
        mfa_method: verification?.method || null,
      });
      return send(res, 200, {
        ok: true,
        name,
        security_changed: securityChanged,
        sessions_revoked: sessionsRevoked,
        reauthentication_required: sessionsRevoked > 0,
      });
    }

    // ----- DELETE /api/v1/admin/clients/:name -----
    if (m === 'DELETE' && clientMatch && clientMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const name = clientMatch[1];
      const existing = CONFIG.clients[name];
      if (!existing) return jsonError(res, 404, `Client ${name} not found`);
      const body = (await readBody(req)) || {};
      const verification = await requireStepUp(body.verify, 'admin_clients_delete', name);
      if (!verification) return;
      const previousApiKeys = CONFIG.api_keys;
      const apiKeysRemoved = (CONFIG.api_keys || []).filter((key) => key.client === name).length;
      delete CONFIG.clients[name];
      CONFIG.api_keys = (CONFIG.api_keys || []).filter((key) => key.client !== name);
      try {
        await persistConfig();
      } catch (e) {
        CONFIG.clients[name] = existing;
        CONFIG.api_keys = previousApiKeys;
        audit({
          action: 'admin_clients_delete',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }

      const sessionsRevoked = deleteSessionsForClient(name);
      // Config is already durable, so a leftover cert file cannot authenticate;
      // remove the material best-effort after the irreversible boundary.
      deleteClientCertFiles(name);
      audit({
        action: 'admin_clients_delete',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        sessions_revoked: sessionsRevoked,
        api_keys_removed: apiKeysRemoved,
        mfa_method: verification.method,
      });
      return send(res, 200, {
        ok: true,
        name,
        sessions_revoked: sessionsRevoked,
        api_keys_removed: apiKeysRemoved,
      });
    }

    // Issue a cert and make the filesystem/config transition transactional.
    // OpenSSL replaces the final files before broker.yaml is persisted, so keep
    // in-memory copies of the previous material and restore both sides on error.
    async function issueAndPersist(name) {
      const c = CONFIG.clients[name];
      if (!c) throw new Error(`Client ${name} disappeared mid-enrollment`);
      const clientSnapshot = structuredClone(c);
      const fileSnapshot = snapshotClientCertFiles(name);
      try {
        const cert = await issueClientCert(name); // DEFAULT_CERT_DAYS = 90
        const bundle = createClientBundle({
          name,
          certPem: cert.cert_pem,
          keyPem: cert.key_pem,
          caPem: readCaCertPem(),
        });
        if (!RETAIN_CLIENT_PRIVATE_KEYS) {
          deleteClientKeyFile(name, { strict: true });
        }
        const rotatedAt = new Date();
        c.cert_fingerprint_sha256 = cert.fingerprint_sha256;
        c.last_cert_rotation = rotatedAt.toISOString();
        c.cert_expires_at = new Date(rotatedAt.getTime() + cert.days * 86_400_000).toISOString();
        await persistConfig();
        return {
          cert,
          bundle,
          previousFingerprint: clientSnapshot.cert_fingerprint_sha256 || null,
          privateKeyRetained: RETAIN_CLIENT_PRIVATE_KEYS,
        };
      } catch (error) {
        restorePlainObject(c, clientSnapshot);
        try {
          restoreClientCertFiles(name, fileSnapshot);
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'Certificate issuance failed and filesystem rollback was incomplete',
          );
        }
        throw error;
      }
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
      } catch {
        return false;
      }
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
      const body = (await readBody(req)) || {};
      const verification = await requireStepUp(body.verify, 'admin_clients_enroll', name);
      if (!verification) return;
      if (!clientsDirWritable()) {
        return jsonError(res, 503, 'Certificate issuance is unavailable on this server');
      }
      let issuance;
      try {
        issuance = await issueAndPersist(name);
      } catch (e) {
        audit({
          action: 'admin_clients_enroll',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return jsonError(res, 500, 'Unable to issue client certificate');
      }
      const sessionsRevoked = deleteSessionsForFingerprint(issuance.previousFingerprint);
      audit({
        action: 'admin_clients_enroll',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        sessions_revoked: sessionsRevoked,
        mfa_method: verification.method,
      });
      return send(res, 200, {
        ok: true,
        name,
        fingerprint_sha256: issuance.cert.fingerprint_sha256,
        cert_pem: issuance.cert.cert_pem,
        key_pem: issuance.cert.key_pem,
        bundle_base64: issuance.bundle.toString('base64'),
        cert_expires_at: CONFIG.clients[name].cert_expires_at,
        sessions_revoked: sessionsRevoked,
        private_key_retained: issuance.privateKeyRetained,
        warning: issuance.privateKeyRetained
          ? 'key_pem is a SECRET. Compatibility retention is enabled; disable BROKER_RETAIN_CLIENT_PRIVATE_KEYS after migration.'
          : 'key_pem and bundle_base64 are one-time secrets. Deliver one out-of-band; the broker has removed the private-key file.',
      });
    }

    // ----- POST /api/v1/admin/clients/:name/rotate -----
    if (m === 'POST' && clientRotateMatch && clientRotateMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const name = clientRotateMatch[1];
      if (!CONFIG.clients[name]) return jsonError(res, 404, `Client ${name} not found`);
      const body = (await readBody(req)) || {};
      const verification = await requireStepUp(body.verify, 'admin_clients_rotate', name);
      if (!verification) return;
      if (!clientsDirWritable()) {
        return jsonError(res, 503, 'Certificate rotation is unavailable on this server');
      }
      let issuance;
      try {
        issuance = await issueAndPersist(name);
      } catch (e) {
        audit({
          action: 'admin_clients_rotate',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return jsonError(res, 500, 'Unable to rotate client certificate');
      }
      const sessionsRevoked = deleteSessionsForFingerprint(issuance.previousFingerprint);
      audit({
        action: 'admin_clients_rotate',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        sessions_revoked: sessionsRevoked,
        mfa_method: verification.method,
      });
      return send(res, 200, {
        ok: true,
        name,
        fingerprint_sha256: issuance.cert.fingerprint_sha256,
        cert_pem: issuance.cert.cert_pem,
        key_pem: issuance.cert.key_pem,
        bundle_base64: issuance.bundle.toString('base64'),
        cert_expires_at: CONFIG.clients[name].cert_expires_at,
        sessions_revoked: sessionsRevoked,
        private_key_retained: issuance.privateKeyRetained,
        warning: issuance.privateKeyRetained
          ? 'key_pem is a SECRET. The previous fingerprint and sessions are revoked, but compatibility retention remains enabled.'
          : 'key_pem and bundle_base64 are one-time secrets. The previous fingerprint and sessions are revoked; the new private-key file was removed.',
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
      const body = (await readBody(req)) || {};
      const verification = await requireStepUp(body.verify, 'admin_clients_revoke', name);
      if (!verification) return;
      if (!c.cert_fingerprint_sha256) {
        return send(res, 200, { ok: true, name, already_revoked: true });
      }
      const clientSnapshot = structuredClone(c);
      const previousFingerprint = c.cert_fingerprint_sha256;
      delete c.cert_fingerprint_sha256;
      c.cert_revoked_at = new Date().toISOString();
      try {
        await persistConfig();
      } catch (e) {
        restorePlainObject(c, clientSnapshot);
        audit({
          action: 'admin_clients_revoke',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      const sessionsRevoked = deleteSessionsForFingerprint(previousFingerprint);
      audit({
        action: 'admin_clients_revoke',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        sessions_revoked: sessionsRevoked,
        mfa_method: verification.method,
      });
      return send(res, 200, { ok: true, name, sessions_revoked: sessionsRevoked });
    }

    // ----- POST /api/v1/admin/clients/:name/bundle -----
    // Legacy compatibility only. Secure-default enrollment/rotation returns an
    // in-memory one-time bundle and deletes the private-key file immediately.
    if (clientBundleMatch && clientBundleMatch[1]) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const name = clientBundleMatch[1];
      const c = CONFIG.clients[name];
      if (!c) return jsonError(res, 404, `Client ${name} not found`);
      if (!RETAIN_CLIENT_PRIVATE_KEYS) {
        return jsonError(
          res,
          410,
          'Client private keys are not retained; issue or rotate the certificate to obtain a new one-time bundle',
        );
      }
      if (m !== 'POST') {
        return send(
          res,
          405,
          {
            error: 'Use POST with {verify} to retrieve a retained compatibility bundle',
            status: 405,
          },
          { Allow: 'POST' },
        );
      }

      const body = (await readBody(req)) || {};
      const verification = await requireStepUp(body.verify, 'admin_clients_bundle', name);
      if (!verification) return;

      let bundle;
      try {
        bundle = createClientBundle({
          name,
          certPem: readClientCertPem(name),
          keyPem: readClientKeyPem(name),
          caPem: readCaCertPem(),
        });
      } catch (error) {
        audit({
          action: 'admin_clients_bundle',
          cn: ctx.cn,
          fp: ctx.fp,
          name,
          status: 'error',
          error: error.message,
        });
        return jsonError(res, 409, `Client certificate bundle is unavailable for ${name}`);
      }
      audit({
        action: 'admin_clients_bundle',
        cn: ctx.cn,
        fp: ctx.fp,
        name,
        status: 'ok',
        mfa_method: verification.method,
      });
      return sendBufferSafe(res, 200, bundle, 'application/zip', {
        'Content-Disposition': `attachment; filename="${name}-bundle.zip"`,
        exposeVersion: true,
      });
    }

    // ----- POST /api/v1/proxy/:service -----
    const proxyMatch = p.match(/^\/api\/v1\/proxy\/([a-z0-9_-]+)$/);
    if (m === 'POST' && proxyMatch) {
      const serviceName = proxyMatch[1];
      const svc = CONFIG.services[serviceName];
      if (!svc) {
        audit({
          action: 'proxy',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          status: 'unknown_service',
        });
        return jsonError(res, 404, `Unknown service: ${serviceName}`);
      }
      const body = (await readBody(req)) || {};
      const method = normalizeProxyMethod(body.method || 'GET');
      let path;
      try {
        const resolved = resolveUpstreamUrl(svc.upstream, body.path || '/', {
          allowInsecureHttp: svc.allow_insecure_http === true,
        });
        path = resolved.pathname + resolved.search;
      } catch {
        return jsonError(res, 400, 'Invalid proxy path');
      }
      if (!method) {
        audit({
          action: 'proxy',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          method: body.method,
          path,
          status: 'denied',
          reason: 'invalid_method',
        });
        return jsonError(res, 400, `Unsupported proxy HTTP method: ${String(body.method)}`);
      }
      const authorizationPath = new URL(path, 'https://broker.invalid').pathname;
      if (
        !checkMethodAllowed(svc.allow_methods, method) ||
        !checkPathAllowed(svc.allow_paths, authorizationPath) ||
        !canProxy(ctx, serviceName, authorizationPath, method)
      ) {
        audit({
          action: 'proxy',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          method,
          path,
          status: 'denied',
        });
        return jsonError(res, 403, `Not allowed to proxy ${serviceName}${path}`);
      }
      // v3.1 M5.5: Service ↔ Secret 联动 — 前置检查 token_secret 健康度
      // 当 secret 处于 expired / unreachable / misconfigured / fail 时, 提前 503 阻断
      const guard = checkSecretForService(svc.token_secret, healthcheckGetSecretStatus);
      if (!guard.allowed) {
        audit({
          action: 'proxy_blocked',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          method,
          path,
          secret: svc.token_secret || null,
          secret_status: guard.status,
          status: 'denied',
        });
        // 不同 status 给不同提示。只有管理员获得内部 secret 名称/detail；
        // 普通调用方只需要知道 service 当前凭据不可用，避免泄露凭据目录元数据。
        const hint = guardHint(guard.status);
        const message =
          ctx.client.role === 'admin'
            ? `Service ${serviceName} blocked: secret "${svc.token_secret}" is ${guard.status} (${guard.detail}). Action: ${hint}. Run "Run Now" healthcheck to refresh.`
            : `Service ${serviceName} is temporarily unavailable because its credential is ${guard.status}. Action: ${hint}.`;
        return jsonError(res, 503, message);
      }
      try {
        // Pass the service name so callUpstream's error messages are useful.
        const r = await callUpstream(
          { ...svc, name: serviceName },
          method,
          path,
          body.query,
          body.headers,
          body.body,
          { serviceName },
        );
        audit({
          action: 'proxy',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          method,
          path,
          upstream_status: r.status,
          latency_ms: r.latency,
          secret_status: guard.status, // v3.1 M5.5: 记录当时 secret 健康度
          status: r.status >= 200 && r.status < 400 ? 'ok' : 'error',
        });
        // forward response
        res.writeHead(r.status, {
          ...r.headers,
          ...securityHeaders({ kind: 'json' }),
          'Content-Security-Policy': "sandbox; default-src 'none'; frame-ancestors 'none'",
          'X-Broker-Latency-Ms': String(r.latency),
          'X-Broker-Version': BROKER_VERSION,
        });
        return res.end(r.body);
      } catch (err) {
        audit({
          action: 'proxy',
          cn: ctx.cn,
          fp: ctx.fp,
          service: serviceName,
          method,
          path,
          status: 'error',
          error: err.message,
        });
        const message =
          ctx.client.role === 'admin'
            ? `Upstream error: ${err.message}`
            : 'Upstream request failed';
        return jsonError(res, 502, message);
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
        client: url.searchParams.get('client'),
        service: url.searchParams.get('service'),
        action: url.searchParams.get('action'),
        status: url.searchParams.get('status'),
        since: url.searchParams.get('since'),
        until: url.searchParams.get('until'),
        limit: parseInt(url.searchParams.get('limit') || '5000', 10),
      };
      const events = readAuditFiltered(params);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      if (fmt === 'json') {
        const body = JSON.stringify(
          { exported_at: new Date().toISOString(), count: events.length, events },
          null,
          2,
        );
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="audit-${stamp}.json"`,
          'X-Broker-Version': BROKER_VERSION,
          ...securityHeaders({ kind: 'json' }),
        });
        return res.end(body);
      } else {
        // csv
        // Columns: ts, action, status, cn, fp, service, method, path, error, name, field, reason
        const cols = [
          'ts',
          'action',
          'status',
          'cn',
          'fp',
          'service',
          'method',
          'path',
          'error',
          'name',
          'field',
          'reason',
          'latency_ms',
          'upstream_status',
        ];
        const escape = (v) => {
          if (v == null) return '';
          const s = String(v);
          return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const lines = [cols.join(',')];
        for (const e of events) lines.push(cols.map((c) => escape(e[c])).join(','));
        const body = lines.join('\n') + '\n';
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="audit-${stamp}.csv"`,
          'X-Broker-Version': BROKER_VERSION,
          ...securityHeaders({ kind: 'json' }),
        });
        return res.end(body);
      }
    }

    // ----- GET /api/v1/admin/audit (filtered list) -----
    if (m === 'GET' && p === '/api/v1/admin/audit') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const params = {
        client: url.searchParams.get('client'),
        service: url.searchParams.get('service'),
        action: url.searchParams.get('action'),
        status: url.searchParams.get('status'),
        since: url.searchParams.get('since'),
        until: url.searchParams.get('until'),
        limit: parseInt(url.searchParams.get('limit') || '200', 10),
      };
      const events = readAuditFiltered(params);
      return send(res, 200, { events });
    }

    // ----- GET /api/v1/admin/audit/facets (dropdown options from live config + logs) -----
    if (m === 'GET' && p === '/api/v1/admin/audit/facets') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      return send(res, 200, collectAuditFacets());
    }

    // ----- DELETE /api/v1/admin/audit (wipe jsonl files; writes one audit_cleared event) -----
    if (m === 'DELETE' && p === '/api/v1/admin/audit') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only / 需要管理员');
      const body = (await readBody(req)) || {};
      if (body.confirm !== true && url.searchParams.get('confirm') !== 'true') {
        return jsonError(res, 400, 'Pass {confirm:true} to clear audit logs');
      }
      const deleted = clearAuditLogs();
      audit({
        action: 'audit_cleared',
        cn: ctx.cn,
        fp: ctx.fp,
        status: 'ok',
        deleted: deleted.length,
      });
      return send(res, 200, { ok: true, deleted });
    }

    // ----- GET /api/v1/ws-stats (v4.4.0: admin inspect of WS subscribers) -----
    // Returns subscriber count + per-event count + (admin only) full subscriber list.
    // docs/WEBSOCKET.md:150 — was a documented-but-unimplemented endpoint.
    if (m === 'GET' && p === '/api/v1/ws-stats') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const stats = getStats();
      const subscribers = listSubscribers();
      // 也返回每事件订阅计数,便于 dashboard 看 alert 流是否有人在听。
      // SUBS_BY_EVENT 是 ws 模块私有实现细节，这里只基于公开快照统计。
      const eventCounts = {};
      for (const e of stats.events) {
        eventCounts[e] = subscribers.filter((sub) => sub.events.includes(e)).length;
      }
      return send(res, 200, {
        subscriber_count: stats.subscriberCount,
        events: stats.events,
        event_counts: eventCounts,
        subscribers,
        version: BROKER_VERSION,
      });
    }

    // ----- GET /api/v1/admin/audit/stream (SSE) -----
    // Server-Sent Events: streams new audit events to the admin UI live.
    // Browser opens via `new EventSource('/api/v1/admin/audit/stream')`.
    // Sends a hello ping, then `event: <name>\ndata: <json>\n\n` for each event.
    // Closes after 30 minutes (clients can reconnect).
    // V4.8.0: 同一 admin 客户端最多 3 个并发 SSE 连接,超过返回 429 (REVIEW.md P6)。
    if (m === 'GET' && p === '/api/v1/admin/audit/stream') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      // V4.8.0: 并发上限 (REVIEW.md P6)
      const adminKey = adminSseKey(ctx.clientName || ctx.cn);
      const slot = tryAcquireSseSlot(adminKey);
      if (!slot.acquired) {
        audit({
          action: 'sse_open',
          status: 'denied',
          reason: 'too_many_concurrent',
          client: ctx.clientName,
          current: slot.current,
          limit: slot.limit,
        });
        return jsonError(
          res,
          429,
          `Too many concurrent SSE connections for ${ctx.clientName} (limit ${slot.limit})`,
        );
      }
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no', // disable buffering under nginx
        'X-Broker-Version': BROKER_VERSION,
        ...securityHeaders({ kind: 'sse' }),
      });
      res.write(': hello\n\n');
      res.write('event: ready\ndata: {"ok":true}\n\n');
      const onEvent = (e) => {
        try {
          res.write(`event: audit\ndata: ${JSON.stringify(e)}\n\n`);
        } catch {
          /* socket closed */
        }
      };
      AUDIT_BUS.on('event', onEvent);
      // Keep-alive comment every 25s (so proxies don't kill idle conns)
      const ka = setInterval(() => {
        try {
          res.write(': ka\n\n');
        } catch {}
      }, 25_000);
      // Auto-close after 30 min
      const closeTimer = setTimeout(
        () => {
          try {
            res.end();
          } catch {}
        },
        30 * 60 * 1000,
      );
      req.on('close', () => {
        clearInterval(ka);
        clearTimeout(closeTimer);
        AUDIT_BUS.off('event', onEvent);
        releaseSseSlot(adminKey); // V4.8.0
      });
      return; // keep connection open
    }

    // ----- GET /api/v1/admin/healthcheck/stream (SSE) -----
    // v3.1.1 M5.6: 实时推送 healthcheck 状态
    //   event: run_complete    — 每次 healthcheck 跑完 (full state)
    //   event: status_change   — 状态变化 (alert history entry)
    //   event: ready           — 初次连接
    // Closes after 30 minutes (clients can reconnect).
    if (m === 'GET' && p === '/api/v1/admin/healthcheck/stream') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
        'X-Broker-Version': BROKER_VERSION,
        ...securityHeaders({ kind: 'sse' }),
      });
      res.write(': hello\n\n');
      res.write('event: ready\ndata: {"ok":true}\n\n');
      const onComplete = (state) => {
        try {
          res.write(`event: run_complete\ndata: ${JSON.stringify(state)}\n\n`);
        } catch {
          /* socket closed */
        }
      };
      const onChange = (change) => {
        try {
          res.write(`event: status_change\ndata: ${JSON.stringify(change)}\n\n`);
        } catch {
          /* socket closed */
        }
      };
      HEALTHCHECK_BUS.on('run_complete', onComplete);
      HEALTHCHECK_BUS.on('status_change', onChange);
      // 启动时立即推一次当前 state
      try {
        const currentState = healthcheckGetStatus();
        res.write(`event: run_complete\ndata: ${JSON.stringify(currentState)}\n\n`);
      } catch {
        /* state not loaded yet */
      }
      const ka = setInterval(() => {
        try {
          res.write(': ka\n\n');
        } catch {}
      }, 25_000);
      const closeTimer = setTimeout(
        () => {
          try {
            res.end();
          } catch {}
        },
        30 * 60 * 1000,
      );
      req.on('close', () => {
        clearInterval(ka);
        clearTimeout(closeTimer);
        HEALTHCHECK_BUS.off('run_complete', onComplete);
        HEALTHCHECK_BUS.off('status_change', onChange);
      });
      return;
    }

    // ----- GET /api/v1/admin/alerts/history -----
    // v3.1.1 M5.6: 返 alert_history (状态变化时间线)
    if (m === 'GET' && p === '/api/v1/admin/alerts/history') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      const events = healthcheckGetAlertHistory(limit);
      return send(res, 200, { events, count: events.length });
    }

    // ----- POST /api/v1/reload (admin only) -----
    if (m === 'POST' && p === '/api/v1/reload') {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const tok = url.searchParams.get('token') || req.headers['x-reload-token'];
      if (tok !== RELOAD_TOKEN) return jsonError(res, 401, 'Bad reload token');
      const previousConfig = CONFIG;
      const previousSecrets = new Map(SECRET_CACHE);
      try {
        await loadConfig();
        await loadSecrets();
        audit({ action: 'reload', cn: ctx.cn, fp: ctx.fp, status: 'ok' });
        return send(res, 200, {
          reloaded: true,
          services: Object.keys(CONFIG.services),
          secrets: SECRET_CACHE.size,
        });
      } catch (err) {
        CONFIG = previousConfig;
        SECRET_CACHE.clear();
        for (const [name, value] of previousSecrets) SECRET_CACHE.set(name, value);
        audit({ action: 'reload', cn: ctx.cn, fp: ctx.fp, status: 'error', error: err.message });
        return jsonError(res, 503, 'Broker reload rejected; previous state retained');
      }
    }

    // ----- POST /api/v1/rotate/:name -----
    // v3.1.1 M5.9: 实际记录轮换时间戳 + rotation_history (凭据零接触: 不接受 value, 只标 "我刚轮换了 X")
    // 凭据值的实际修改走 /api/v1/admin/secrets/:name (PUT), 那里有完整的值更新逻辑
    // 此端点用于"我刚在外部 (GitHub/CF/...) 轮换了, 告诉 broker 一下" — 写 last_rotated_at + history
    const rotMatch = p.match(/^\/api\/v1\/rotate\/([a-zA-Z0-9_.-]+)$/);
    if (m === 'POST' && rotMatch) {
      if (ctx.client.role !== 'admin') return jsonError(res, 403, 'Admin only');
      const name = rotMatch[1];
      const existing = SECRET_CACHE.get(name);
      if (!existing) return jsonError(res, 404, `Secret ${name} not found`);
      const body = (await readBody(req)) || {};
      const now = new Date().toISOString();
      const who = ctx.cn || 'admin';
      const note = body.note && typeof body.note === 'string' ? body.note.slice(0, 200) : '';
      const source =
        body.source && typeof body.source === 'string' ? body.source.slice(0, 50) : 'manual';
      // rotation_history: unshift 最新, cap 50 entries
      const history = Array.isArray(existing.rotation_history)
        ? existing.rotation_history.slice()
        : [];
      history.unshift({ ts: now, by: who, note, source });
      if (history.length > 50) history.length = 50;
      const updated = { ...existing, last_rotated_at: now, rotation_history: history };
      const prevSnapshot = JSON.parse(JSON.stringify(existing));
      SECRET_CACHE.set(name, updated);
      try {
        await persistSecretsDetail();
      } catch (e) {
        SECRET_CACHE.set(name, prevSnapshot);
        audit({
          action: 'rotate',
          cn: ctx.cn,
          fp: ctx.fp,
          secret: name,
          status: 'error',
          error: e.message,
        });
        return persistenceError(res);
      }
      audit({ action: 'rotate', cn: ctx.cn, fp: ctx.fp, secret: name, status: 'ok', source, note });
      return send(res, 200, {
        rotated: name,
        last_rotated_at: now,
        rotation_count: history.length,
        // 凭据零接触: 不返 value, 只返 metadata
        note: 'Rotation recorded. To update the value, use PUT /api/v1/admin/secrets/:name (or scripts/rotate-secret-ecs.sh).',
      });
    }

    // ----- SSH proxy (was in API_HANDLERS but never dispatched) -----
    if (p.startsWith('/api/v1/ssh')) {
      const sshDeps = {
        send,
        jsonError,
        readBody,
        audit,
        ctx,
        config: CONFIG,
        rateLimit: (c, _bucket) => rateLimit(c),
        getSecret: async (name, c) => {
          if (!canResolve(c, name)) {
            throw new Error('secret not accessible');
          }
          const entry = getSecret(name);
          if (!entry) throw new Error('secret not loaded');
          const fields = entry.fields || {};
          return {
            ...fields,
            private_key: fields.private_key || fields.key || '',
            type: entry.type,
            name: entry.name || name,
          };
        },
      };
      const sshHandled = await handleSshProxy(req, res, route, sshDeps);
      // handleSshProxy historically returned undefined after send(); treat headersSent as handled
      if (sshHandled || res.headersSent) {
        observeMs('broker_http_request_duration_ms', Date.now() - t0);
        inc('broker_http_requests_total', 1, { route: p });
        return;
      }
    }

    // 404
    audit({ action: 'unknown', cn: ctx.cn, fp: ctx.fp, method: m, path: p, status: '404' });
    observeMs('broker_http_request_duration_ms', Date.now() - t0);
    inc('broker_http_requests_total', 1, { route: p });
    return jsonError(res, 404, `Not found: ${m} ${p}`);
  }); // Phase AF: end request pipeline (runWithRequestContext)
}

// ============================================================
// Identity: try session token first (for dashboard / browser), then mTLS
// ============================================================
// V4.1.1: Identity resolution extracted to broker/lib/mtls.js for testability.
// We keep the inline thin wrappers here so the rest of server.js doesn't change.
// All actual logic now lives in createIdentityResolver() from lib/index.js.

// Initialize before the resolver captures this dependency (no TDZ at startup).
const rateLimitApiKey = createApiKeyRateLimiter({ defaultLimit: '100/hour' });

const identityResolver = createIdentityResolver({
  config: () => CONFIG,
  getSession,
  parseBearer,
  findApiKey,
  isClientIpAllowed,
  rateLimitApiKey,
  recordUse,
  recordClientSeen,
  audit,
});

// Public dispatch and authenticated dispatch share one decision per request:
// repeated lookups must not debit API-key rate limits or use counters twice.
const requestIdentities = new WeakMap();
function getIdentity(req) {
  if (!requestIdentities.has(req)) requestIdentities.set(req, identityResolver.getIdentity(req));
  return requestIdentities.get(req);
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

  const server = createHttpsServer(
    tlsOpts,
    wrapAsyncRequestHandler(handle, {
      errorResponder: jsonError,
      onError: (err, req) => {
        if (err?.statusCode === 413) {
          console.warn('[http] request body rejected as too large:', req?.method, req?.url);
          return;
        }
        console.error('[http] unhandled request error:', err?.message || String(err));
      },
    }),
  );

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
    console.log(`[broker] mTLS HTTPS listening on https://${HOST}:${server.address().port}`);
    console.log('[broker] reload token loaded (not printed)');
    if (process.env.BROKER_HEALTH_DISABLE !== '1') {
      startLocalHealthServer({
        listen: defaultHealthBind(),
        log: (m) => console.log(m),
        onRequest: async (req, res) => {
          const url = new URL(req.url || '/', 'http://127.0.0.1');
          const route = { method: req.method || 'GET', pathname: url.pathname };
          const localSend = (response, status, body, extraHeaders = {}) =>
            sendSafe(response, status, body, { ...extraHeaders, noSecurityHeaders: true });
          const localJsonError = (response, status, message) =>
            localSend(response, status, { error: message, status });
          const handled = await handleHealth(req, res, route, {
            send: localSend,
            jsonError: localJsonError,
            version: BROKER_VERSION,
            secretCache: SECRET_CACHE,
            config: CONFIG,
            requireSops: true,
            surface: 'local',
            runReadyProbes: () => runProbes(probesFromConfig(CONFIG || {})),
          });
          if (!handled && !res.headersSent) {
            localJsonError(res, 404, `Not found: ${route.method} ${route.pathname}`);
          }
        },
      }).catch((e) => {
        console.warn('[broker] local health listener failed:', e.message);
      });
    }

    // v3.0 M4: 启动 cron 循环 (04:00 daily healthcheck)
    // v3.0 M5: 跟 /api/v1/healthcheck/run 一样支持 upstream: 'local' | 'mcp_server'
    const hcCfg = CONFIG.healthcheck || { enabled: true, schedule: '04:00' };
    if (hcCfg.enabled !== false) {
      const schedule = hcCfg.schedule || '04:00';
      const cronUpstream = hcCfg.upstream || 'local';
      const cronMcpUrl = hcCfg.mcp_server_url || 'http://127.0.0.1:3001';
      // 从 broker 内存 SECRET_CACHE 拿 secrets (有 type + fields)
      const getSecrets = () => {
        const out = {};
        for (const [name, entry] of SECRET_CACHE) {
          out[name] = {
            type: entry.type,
            fields: entry.fields || {},
            description: entry.description || '',
          };
        }
        return out;
      };
      registerCron(schedule, async () => {
        console.log(`[cron] running healthcheck (${schedule}, upstream=${cronUpstream})`);
        try {
          const r =
            cronUpstream === 'mcp_server'
              ? await healthcheckRunAllViaMcp(cronMcpUrl)
              : await healthcheckRunAll(getSecrets);
          const summary = r.summary;
          console.log(
            `[cron] healthcheck done: ${summary.ok} ok / ${summary.expired} expired / ${summary.fail} fail / ${summary.skipped} skipped`,
          );
          // 写 audit (每个 check 一条)
          for (const [name, c] of Object.entries(r.checks)) {
            audit({
              action: 'healthcheck',
              cn: 'system',
              fp: 'system',
              secret: name,
              status: c.status,
              detail: c.detail,
              latency_ms: c.latency_ms,
              ts: c.ts,
            });
          }
          // SSE 推 (供 dashboard alerts 页用)
          HEALTHCHECK_BUS.emit('result', r);
        } catch (e) {
          console.error('[cron] healthcheck failed:', e.message);
        }
      });
      startCronLoop();
      console.log(`[cron] registered healthcheck (schedule=${schedule}, upstream=${cronUpstream})`);
    }
  });

  // Phase E: graceful shutdown (SIGTERM/SIGINT drain)
  const _shutdownCtl = installGracefulShutdown({
    server,
    onShutdown: [() => stopCronLoop()],
  });
  globalThis.__brokerShuttingDown = _shutdownCtl.shuttingDown;

  // Phase D/F: audit prune
  try {
    const policy = auditPolicyFromEnv();
    registerCron('03:30', () => {
      const r = pruneAuditFiles(AUDIT_DIR, policy.retainDays);
      console.log('[cron] audit prune deleted=', r.deleted?.length || 0);
    });
  } catch (e) {
    console.warn('[cron] audit prune register failed:', e.message);
  }
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
    // Phase E: configuration and filesystem preflight are security gates.
    // Never continue booting when a validator or required-path check itself fails:
    // "warn and continue" can turn a validator regression into an insecure startup.
    const vr = validateBrokerConfig(CONFIG);
    if (!vr.ok) {
      throw new Error('config validation failed:\n' + formatValidationReport(vr));
    }
    for (const w of vr.warnings || []) console.warn('[config]', w.path, w.message);

    const pf = preflightPaths(
      {
        configPath: CONFIG_PATH,
        ageKey: AGE_KEY_FILE,
        caCert: TLS_CA,
        serverCert: TLS_CERT,
        serverKey: TLS_KEY,
      },
      { existsSync },
    );
    if (!pf.ok) {
      throw new Error('preflight failed:\n' + formatValidationReport(pf));
    }

    // v3.0: startup schema migration is also required. If encrypted persistence
    // fails, do not serve traffic with a partially migrated in-memory config.
    const { migrateV2ToV3 } = await import('./migrate-v2-to-v3.js');
    const migPath = dirname(fileURLToPath(import.meta.url));
    const clientsDir = CLIENTS_DIR || join(migPath, '..', 'pki', 'clients');
    const { changed, changes } = await migrateV2ToV3(CONFIG, clientsDir, audit, persistConfig);
    if (changed) {
      console.log(`[migrate v2->v3] applied ${changes.length} change(s):`);
      changes.forEach((c) => console.log('  -', c));
    } else {
      console.log('[migrate v2->v3] already at v3, no changes');
    }
    start();
  } catch (err) {
    console.error('[bootstrap] failed:', err.message);
    process.exit(1);
  }
})();
