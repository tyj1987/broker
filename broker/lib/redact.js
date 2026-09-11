// broker/lib/redact.js — V4 secret value redaction
// Goal: ensure secret values NEVER appear in logs, audit, error responses.
//
// Patterns matched (case-insensitive where appropriate):
//   - GitHub classic PAT  (ghp_...)
//   - GitHub fine-grained (github_pat_...)
//   - GitHub App user-to-server (ghu_...)
//   - GitHub App server-to-server (ghs_...)
//   - GitHub OAuth refresh (ghr_...)
//   - OpenAI classic (sk-...)
//   - OpenAI project (sk-proj-...)
//   - Anthropic (sk-ant-... or sk-ant-api03-...)
//   - Google AI / Gemini (AIza...)
//   - Mistral / Cohere (varies, see below)
//   - Aliyun AccessKey (LTAI... or STS prefix)
//   - Tencent SecretId (AKID...)
//   - AWS AccessKey (AKIA... long-term, ASIA... STS)
//   - Azure Tenant (16 hex / 36 uuid)
//   - Slack bot (xoxb-...)
//   - Slack user (xoxp-...)
//   - Generic Bearer / API key (long base64-ish strings after "Bearer ")
//   - Basic auth (user:password in Authorization header)
//   - PEM private keys (-----BEGIN ... PRIVATE KEY-----)
//   - SSH private keys (-----BEGIN OPENSSH PRIVATE KEY-----)
//
// Zero deps. Safe to use in any hot path.

const PATTERNS = [
  // GitHub
  { name: 'github_pat',        regex: /ghp_[A-Za-z0-9]{20,}/g,                     replace: 'ghp_***' },
  { name: 'github_fine_grain',  regex: /github_pat_[A-Za-z0-9_]{20,}/g,            replace: 'github_pat_***' },
  { name: 'github_app_ghu',     regex: /ghu_[A-Za-z0-9]{20,}/g,                    replace: 'ghu_***' },
  { name: 'github_app_ghs',     regex: /ghs_[A-Za-z0-9]{20,}/g,                    replace: 'ghs_***' },
  { name: 'github_oauth_ghr',   regex: /ghr_[A-Za-z0-9]{20,}/g,                    replace: 'ghr_***' },
  // Secret Broker
  { name: 'broker_api_key',      regex: /mb_(live|test)_[A-Za-z0-9]{20,}/g,         replace: 'mb_$1_***' },
  // OpenAI
  { name: 'openai_sk_proj',     regex: /sk-proj-[A-Za-z0-9_\-]{20,}/g,            replace: 'sk-proj-***' },
  { name: 'openai_classic',     regex: /sk-[A-Za-z0-9]{20,}/g,                    replace: 'sk-***' },
  // Anthropic
  { name: 'anthropic_key',      regex: /sk-ant-[A-Za-z0-9_\-]{20,}/g,              replace: 'sk-ant-***' },
  // Google AI
  { name: 'google_ai_key',      regex: /AIza[A-Za-z0-9_\-]{30,}/g,                 replace: 'AIza***' },
  // Aliyun
  { name: 'aliyun_ak',          regex: /LTAI[A-Za-z0-9]{12,}/g,                    replace: 'LTAI***' },
  { name: 'aliyun_sts',         regex: /STS\.[A-Za-z0-9_\-]{16,}/g,                replace: 'STS.***' },
  // Tencent
  { name: 'tencent_secret_id',  regex: /AKID[A-Za-z0-9]{16,}/g,                    replace: 'AKID***' },
  // AWS
  { name: 'aws_access_key',     regex: /\b(AKIA|ASIA)[A-Z0-9]{12,}\b/g,            replace: '$1***' },
  // Azure (tenant_id is UUID)
  { name: 'azure_tenant',       regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, replace: '***-tenant-***' },
  // Slack
  { name: 'slack_bot',          regex: /xoxb-[A-Za-z0-9\-]{20,}/g,                replace: 'xoxb-***' },
  { name: 'slack_user',         regex: /xoxp-[A-Za-z0-9\-]{20,}/g,                replace: 'xoxp-***' },
  // Stripe
  { name: 'stripe_sk',          regex: /\bsk_(live|test)_[A-Za-z0-9]{20,}\b/g,     replace: 'sk_$1_***' },
  { name: 'stripe_rk',          regex: /\brk_(live|test)_[A-Za-z0-9]{20,}\b/g,     replace: 'rk_$1_***' },
  // JWT (heuristic: three base64url segments separated by dots, length > 50)
  { name: 'jwt',                regex: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g, replace: 'eyJ***.***.***' },
  // PEM private keys (single line content might be wrapped; match start/end markers)
  { name: 'pem_private_key',    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/g,
    replace: '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----' },
  // Basic auth header
  { name: 'basic_auth',         regex: /(Basic\s+)[A-Za-z0-9+/=]{8,}/g,             replace: '$1***' },
  // Free-form error text containing a labelled credential assignment
  { name: 'labelled_secret',    regex: /((?:password|passwd|passphrase|client[_-]?secret|app[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key|kms[_-]?key|api[_-]?key|access[_-]?key[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|refresh[_-]?token|access[_-]?token)\s*[:=]\s*)[^\s,;]+/gi, replace: '$1***' },
  // Generic Bearer token (long opaque string after "Bearer ")
  { name: 'bearer_token',       regex: /(Bearer\s+)[A-Za-z0-9_\-\.~+\/=]{20,}/g,    replace: '$1***' },
  // Docker registry token
  { name: 'docker_registry',    regex: /\bdocker_[A-Za-z0-9_\-]{20,}\b/g,            replace: 'docker_***' },
];

const SENSITIVE_KEYS = new Set([
  'authorization', 'proxyauthorization', 'cookie', 'setcookie',
  'password', 'passwd', 'passphrase', 'secret', 'clientsecret',
  'passwordhash', 'apikey', 'accesskey', 'accesskeyid', 'accesskeysecret', 'appsecret', 'signingkey', 'encryptionkey', 'masterkey', 'kmskey',
  'secretaccesskey', 'secretid', 'secretkey', 'authorizationheader',
  'privatekey', 'token', 'accesstoken', 'refreshtoken', 'idtoken',
  'session', 'sessiontoken', 'securitytoken', 'credential', 'credentials',
  'recoverycode', 'recoverycodes', 'otp', 'totp', 'totpsecret',
  'totprecoverycodeshash',
]);

function isSensitiveKey(key) {
  return SENSITIVE_KEYS.has(String(key).toLowerCase().replace(/[^a-z0-9]/g, ''));
}

/**
 * Redact all known secret value patterns from a string.
 * Returns the input with matches replaced by safe placeholders.
 *
 * @param {string} input
 * @returns {string} safe text
 */
export function redact(input) {
  if (typeof input !== 'string' || input.length === 0) return input;
  // Fast path: skip if no suspicious token at all
  if (!hasLikelySecret(input)) return input;
  let out = input;
  for (const p of PATTERNS) {
    out = out.replace(p.regex, p.replace);
  }
  return out;
}

/**
 * Recursively walk an object/array and redact all string leaves.
 * Non-clone mutation: returns a new structure; safe for logging.
 *
 * @param {any} value
 * @returns {any} deep-redacted copy
 */
export function redactDeep(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redact(value);
  if (typeof value !== 'object') return value;
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map(v => redactDeep(v, seen));
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) ? '[REDACTED]' : redactDeep(v, seen);
  }
  return out;
}

/**
 * Cheap heuristic: does this string contain anything that might be a secret?
 * Used to short-circuit redact() on safe text (saves CPU in hot paths).
 * Must stay in sync with PATTERNS above — when a new pattern is added
 * the matching prefix/keyword should be added here too.
 */
export function hasLikelySecret(s) {
  if (typeof s !== 'string' || s.length < 8) return false;
  // Heuristics: presence of common token prefixes, PEM marker, JWT shape, UUID
  return /ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|mb_(?:live|test)_|sk-|sk-ant-|sk-proj-|AIza|LTAI|AKID|AKIA|ASIA|STS\.|xoxb|xoxp|xapp|xoxa|sk_(live|test)|rk_(live|test)|docker_|-----BEGIN|Basic\s|Bearer\s+[A-Za-z0-9]|(?:password|passwd|passphrase|client[_-]?secret|app[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key|kms[_-]?key|api[_-]?key|access[_-]?key[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|refresh[_-]?token|access[_-]?token)\s*[:=]|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(s);
}

/**
 * Convenience: build a redacted JSON string for logging.
 * Falls back to JSON.stringify of redactDeep().
 */
export function redactJson(value) {
  try {
    return JSON.stringify(redactDeep(value));
  } catch (_e) {
    return '[unserializable]';
  }
}

/**
 * Names of patterns currently supported (for tests / docs).
 */
export const SUPPORTED_PATTERNS = PATTERNS.map(p => p.name);
