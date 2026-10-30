// broker/auth-flow.js — 登录状态机（密码 → TOTP → session）
// v3.0 新增。
//
// 状态机：
//   PASSWORD_OK → MFA_REQUIRED(mfa_token) → MFA_OK → SESSION
//                ↓
//               SESSION（无 TOTP 时直返）
//
// 临时 mfa_token 5 分钟有效，单次使用，存内存（broker 重启失效，安全）
//
// 与 server.js 集成：
//   1. /api/v1/login 调 verifyPassword() → 返 ok:false + mfa_token (若启用了 TOTP)
//   2. /api/v1/login/mfa 调 verifyMfaCode() → 返 session

import { randomUUID, createHash } from 'node:crypto';
import { verify as verifyTotp, findRecoveryCode, verifyPassword } from './totp.js';

const MFA_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 分钟
const MAX_MFA_PENDING = 10_000;

// 内存存活的 mfa_token 池
// 形如: { token: { clientName, fp, createdAt, used } }
const MFA_PENDING = new Map();

function gcMfaPending() {
  const now = Date.now();
  for (const [t, v] of MFA_PENDING) {
    if (now - v.createdAt > MFA_TOKEN_TTL_MS) MFA_PENDING.delete(t);
  }
}

// 每分钟 GC 一次（懒 GC 也行，这里主动做）
const GC_INTERVAL = setInterval(gcMfaPending, 60_000);
GC_INTERVAL.unref?.();

/**
 * 创建 MFA pending 状态
 * @param {string} clientName
 * @param {string} fp 客户端 cert fingerprint（mTLS 走的话记录；密码登录可空）
 * @returns {string} mfa_token
 */
function createMfaPending(clientName, fp = '', opts = {}) {
  gcMfaPending();
  const maxEntries =
    Number.isSafeInteger(opts.maxEntries) && opts.maxEntries > 0
      ? opts.maxEntries
      : MAX_MFA_PENDING;
  while (MFA_PENDING.size >= maxEntries) {
    const oldestToken = MFA_PENDING.keys().next().value;
    if (!oldestToken) break;
    MFA_PENDING.delete(oldestToken);
  }
  const token = randomUUID();
  MFA_PENDING.set(token, {
    clientName,
    fp,
    createdAt: Date.now(),
    used: false,
    securityBinding: opts.securityBinding || null,
  });
  return token;
}

/**
 * 查 mfa pending（消费前只读）
 */
function getMfaPending(token) {
  if (!token) return null;
  const v = MFA_PENDING.get(token);
  if (!v) return null;
  if (Date.now() - v.createdAt > MFA_TOKEN_TTL_MS) {
    MFA_PENDING.delete(token);
    return null;
  }
  if (v.used) return null;
  return v;
}

/**
 * 消费 mfa pending（验证后调用）
 */
function consumeMfaPending(token) {
  const v = MFA_PENDING.get(token);
  if (!v) return false;
  v.used = true;
  // 立即删除（单次使用）
  MFA_PENDING.delete(token);
  return true;
}

/**
 * 验证 TOTP code 或恢复码
 * @param {object} clientConfig client.<NAME> 配置
 * @param {string} code 6 位 TOTP 或 恢复码 (大小写不敏感)
 * @returns {{ ok: boolean, method?: 'totp'|'recovery' }}
 */
function verifyMfaCode(clientConfig, code) {
  if (!code || typeof code !== 'string') return { ok: false };

  // 1. 先尝 TOTP code（6 位数字）
  if (/^\d{6}$/.test(code) && clientConfig.totp_secret) {
    if (verifyTotp(clientConfig.totp_secret, code)) {
      return { ok: true, method: 'totp' };
    }
  }

  // 2. 尝恢复码（格式 XXXX-XXXX 或 XXXXXXXX）
  if (clientConfig.totp_recovery_codes_hash && clientConfig.totp_recovery_codes_hash.length > 0) {
    const idx = findRecoveryCode(code, clientConfig.totp_recovery_codes_hash);
    if (idx >= 0) {
      // Recoverable transaction metadata lets callers restore the hash when
      // durable persistence fails. These underscored fields are internal only.
      const [_recovery_hash] = clientConfig.totp_recovery_codes_hash.splice(idx, 1);
      return { ok: true, method: 'recovery', _recovery_index: idx, _recovery_hash };
    }
  }

  return { ok: false };
}

function verifyStepUp(clientConfig, code, opts = {}) {
  if (!clientConfig || !code || typeof code !== 'string') return { ok: false };
  if (clientConfig.totp_secret || clientConfig.totp_recovery_codes_hash?.length) {
    // Once MFA is configured, the first factor alone must never satisfy step-up.
    return verifyMfaCode(clientConfig, code);
  }
  if (opts.allowPassword !== false && clientConfig.password) {
    if (verifyPassword(code, clientConfig.password)) {
      return { ok: true, method: 'password' };
    }
  }
  return { ok: false };
}

export function mfaClientBinding(clientConfig) {
  // Bind a pending first factor to security-relevant live state. No plaintext
  // secret is exposed; old challenges die after password/role/certificate changes.
  return createHash('sha256')
    .update(
      JSON.stringify({
        password: clientConfig?.password,
        totp: clientConfig?.totp_secret,
        role: clientConfig?.role,
        fingerprint: clientConfig?.cert_fingerprint_sha256,
        resolve: clientConfig?.allowed_resolve,
        proxy: clientConfig?.allowed_proxy,
        passwordLogin: clientConfig?.allow_password_login,
      }),
    )
    .digest('hex');
}

function restoreConsumedRecoveryCode(clientConfig, verification) {
  if (verification?.method !== 'recovery' || !verification._recovery_hash) return false;
  if (!Array.isArray(clientConfig.totp_recovery_codes_hash)) {
    clientConfig.totp_recovery_codes_hash = [];
  }
  const hashes = clientConfig.totp_recovery_codes_hash;
  if (!hashes.includes(verification._recovery_hash)) {
    const index = Number.isInteger(verification._recovery_index)
      ? Math.max(0, Math.min(verification._recovery_index, hashes.length))
      : hashes.length;
    hashes.splice(index, 0, verification._recovery_hash);
  }
  delete verification._recovery_index;
  delete verification._recovery_hash;
  return true;
}

/**
 * 检查 client 是否需要 MFA
 * - 已启 TOTP → 需要
 * - role: ci + mTLS 登录 → 可豁免（机器凭证书）
 * - 强制开关: client.mfa_required = false → 免
 * @returns {boolean}
 */
function isMfaRequired(clientConfig, loginMethod /* 'password' | 'mtls' */) {
  if (!clientConfig) return false;
  if (clientConfig.mfa_required === false) return false;
  if (clientConfig.totp_secret) return true;
  // mTLS 登录的 ci client 可豁免
  if (loginMethod === 'mtls' && clientConfig.role === 'ci') return false;
  return false;
}

// 用于测试 / 调试
function _dumpMfaPending() {
  return Array.from(MFA_PENDING.entries()).map(([t, v]) => ({
    token: t.slice(0, 8) + '...',
    clientName: v.clientName,
    ageSec: Math.floor((Date.now() - v.createdAt) / 1000),
    used: v.used,
  }));
}

function _resetMfaPendingForTests() {
  MFA_PENDING.clear();
}

export {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  verifyMfaCode,
  verifyStepUp,
  restoreConsumedRecoveryCode,
  isMfaRequired,
  MFA_TOKEN_TTL_MS,
  MAX_MFA_PENDING,
  _dumpMfaPending,
  _resetMfaPendingForTests,
};
