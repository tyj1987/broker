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

import { randomUUID } from 'node:crypto';
import { findMatchingCounter, findRecoveryCode } from './totp.js';

const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;  // 5 分钟

// 内存存活的 mfa_token 池
// 形如: { token: { clientName, fp, createdAt, used } }
const MFA_PENDING = new Map();
const MFA_FAILURES = new Map();
const MFA_MAX_FAILURES = 5;
const MFA_FAILURE_WINDOW_MS = 15 * 60 * 1000;

function isMfaLocked(clientName) {
  const value = MFA_FAILURES.get(clientName);
  if (!value) return false;
  if (Date.now() - value.startedAt >= MFA_FAILURE_WINDOW_MS) {
    MFA_FAILURES.delete(clientName);
    return false;
  }
  return value.failures >= MFA_MAX_FAILURES;
}

function clearMfaFailures(clientName) {
  MFA_FAILURES.delete(clientName);
}

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
function createMfaPending(clientName, fp = '') {
  gcMfaPending();
  if (!clientName || isMfaLocked(clientName)) return null;
  const token = randomUUID();
  MFA_PENDING.set(token, { clientName, fp, createdAt: Date.now(), used: false, failures: 0 });
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

function recordMfaFailure(token, maxFailures = 5) {
  const value = MFA_PENDING.get(token);
  if (!value || !Number.isSafeInteger(maxFailures) || maxFailures <= 0) return false;
  value.failures = (value.failures || 0) + 1;
  const aggregate = MFA_FAILURES.get(value.clientName);
  const current = !aggregate || Date.now() - aggregate.startedAt >= MFA_FAILURE_WINDOW_MS
    ? { failures: 0, startedAt: Date.now() }
    : aggregate;
  current.failures += 1;
  MFA_FAILURES.set(value.clientName, current);
  if (value.failures >= maxFailures) MFA_PENDING.delete(token);
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
    const counter = findMatchingCounter(clientConfig.totp_secret, code);
    const lastCounter = Number(clientConfig.totp_last_used_counter ?? -1);
    if (counter !== null && Number.isSafeInteger(lastCounter) && counter > lastCounter) {
      return { ok: true, method: 'totp', totp_counter: counter };
    }
  }

  // 2. 尝恢复码（格式 XXXX-XXXX 或 XXXXXXXX）
  if (clientConfig.totp_recovery_codes_hash && clientConfig.totp_recovery_codes_hash.length > 0) {
    const idx = findRecoveryCode(code, clientConfig.totp_recovery_codes_hash);
    if (idx >= 0) {
      // The caller removes and durably persists this index transactionally.
      return { ok: true, method: 'recovery', recovery_index: idx };
    }
  }

  return { ok: false };
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

export {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  recordMfaFailure,
  isMfaLocked,
  clearMfaFailures,
  verifyMfaCode,
  isMfaRequired,
  MFA_TOKEN_TTL_MS,
  MFA_MAX_FAILURES,
  MFA_FAILURE_WINDOW_MS,
  _dumpMfaPending,
};
