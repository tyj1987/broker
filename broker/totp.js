// broker/totp.js — RFC 6238 TOTP (Time-based One-Time Password) 实现
// 零 npm 依赖，纯 Node.js 内置 crypto
//
// 用法：
//   import { generateSecret, verify, buildOtpauthURL, generateRecoveryCodes } from './totp.js';
//   const s = generateSecret();        // base32 32 字符
//   const url = buildOtpauthURL('tyj', 'broker.example.com', s);
//   const ok = verify(s, '123456');    // boolean
//   const codes = generateRecoveryCodes();  // ['aB3-xY7z', ...] 10 个
//
// 安全注意：
//   - secret 永远不写到日志或响应体
//   - recovery codes 用 SHA-256 hash 后存
//   - verify 容忍 ±1 个 30s 窗口 (RFC 6238 推荐)

import crypto from 'node:crypto';

// ============================================================
// Base32 编解码 (RFC 4648)
// ============================================================

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const s = str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0, value = 0, output = [];
  for (let i = 0; i < s.length; i++) {
    const idx = B32_ALPHABET.indexOf(s[i]);
    if (idx === -1) throw new Error('Invalid base32 char: ' + s[i]);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

// ============================================================
// TOTP 核心
// ============================================================

/**
 * 生成 32 字符 base32 secret (160 bit entropy)
 * @returns {string} base32 secret (大写无 padding)
 */
function generateSecret() {
  // 20 字节 = 160 bit，符合 RFC 6238 SHA-1 推荐长度
  return base32Encode(crypto.randomBytes(20));
}

/**
 * 计算指定时间戳的 TOTP code
 * @param {string} secret base32 secret
 * @param {number} [timestamp=Date.now()/1000] unix 秒
 * @param {number} [period=30] 周期 (秒)
 * @param {number} [digits=6] code 长度
 * @returns {string} TOTP code (digits 位)
 */
function computeCode(secret, timestamp = Date.now() / 1000, period = 30, digits = 6) {
  const counter = Math.floor(timestamp / period);
  const counterBuf = Buffer.alloc(8);
  // 大端 64-bit
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  // 动态截断 (RFC 4226 §5.3)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24)
               | ((hmac[offset + 1] & 0xff) << 16)
               | ((hmac[offset + 2] & 0xff) << 8)
               | (hmac[offset + 3] & 0xff);
  const otp = (binary % (10 ** digits)).toString().padStart(digits, '0');
  return otp;
}

/**
 * 验证 TOTP code，容忍 ±window 个时间步
 * @param {string} secret base32 secret
 * @param {string} code 用户输入的 6 位 code
 * @param {object} [opts] { period, digits, window }
 * @returns {boolean} 是否有效
 */
function verify(secret, code, opts = {}) {
  if (!secret || !code) return false;
  const period = opts.period || 30;
  const digits = opts.digits || 6;
  const window = opts.window !== undefined ? opts.window : 1;
  // 输入必须是 digits 位数字
  if (!/^\d+$/.test(code) || code.length !== digits) return false;
  const now = Date.now() / 1000;
  for (let w = -window; w <= window; w++) {
    const t = now + w * period;
    if (computeCode(secret, t, period, digits) === code) return true;
  }
  return false;
}

/**
 * 生成 otpauth:// URL (供 Authenticator App 扫码)
 * @param {string} account 账号名 (e.g. client.tyj-laptop)
 * @param {string} issuer 发行方 (e.g. SecretBroker)
 * @param {string} secret base32 secret
 * @param {object} [opts] { period, digits, algorithm }
 * @returns {string} otpauth URL
 */
function buildOtpauthURL(account, issuer, secret, opts = {}) {
  const period = opts.period || 30;
  const digits = opts.digits || 6;
  const algorithm = opts.algorithm || 'SHA1';
  const label = encodeURIComponent(`${issuer}:${account}`);
  const encIssuer = encodeURIComponent(issuer);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encIssuer}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
}

// ============================================================
// Recovery Codes (一次性恢复码)
// ============================================================

const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去掉 0/O/1/I/L 防误读
const RECOVERY_CODE_LEN = 8;
const RECOVERY_CODE_COUNT = 10;

/**
 * 生成 10 个一次性恢复码 (e.g. ['7K3M-9PXQ', '2H4N-8BVR', ...])
 * @returns {string[]} 10 个恢复码 (大写 + '-' 分隔)
 */
function generateRecoveryCodes() {
  const codes = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    let s = '';
    for (let j = 0; j < RECOVERY_CODE_LEN; j++) {
      s += RECOVERY_CODE_ALPHABET[crypto.randomInt(RECOVERY_CODE_ALPHABET.length)];
    }
    // 格式化成 "XXXX-XXXX" 易读
    codes.push(`${s.slice(0, 4)}-${s.slice(4)}`);
  }
  return codes;
}

/**
 * Hash 恢复码用于存储 (SHA-256 + salt)
 * @param {string} code 恢复码 (大小写不敏感 + 去 '-')
 * @returns {string} hex hash
 */
function hashRecoveryCode(code) {
  const normalized = code.replace(/-/g, '').toUpperCase();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * 验证恢复码并返回 hash 索引 (用于删除已用码)
 * @param {string} code 用户输入
 * @param {string[]} hashList 已存 hash 列表
 * @returns {number} 命中索引 (返回 -1 表示没命中)
 */
function findRecoveryCode(code, hashList) {
  if (!code || !Array.isArray(hashList)) return -1;
  const target = hashRecoveryCode(code);
  return hashList.indexOf(target);
}

// ============================================================
// 密码哈希 (Argon2id 替代 - 这里用 scrypt 因为零依赖)
// ============================================================

/**
 * 用 scrypt hash 密码 (Node.js 内置，零依赖)
 * @param {string} password 明文密码
 * @returns {string} 格式 "scrypt$N$r$p$saltB64$hashB64"
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  // N=16384, r=8, p=1 (与 OpenSSL 默认一致，约 100ms)
  const N = 16384, r = 8, p = 1, keylen = 64;
  const hash = crypto.scryptSync(password, salt, keylen, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/**
 * 验证明文密码与 scrypt hash
 * @param {string} password 明文
 * @param {string} stored 存储的 hash
 * @returns {boolean} 是否匹配
 */
function verifyPassword(password, stored) {
  if (!password || !stored) return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10);
  const r = parseInt(parts[2], 10);
  const p = parseInt(parts[3], 10);
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  try {
    const actual = crypto.scryptSync(password, salt, expected.length, { N, r, p });
    return crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}

// ============================================================
// 导出
// ============================================================

export {
  // TOTP
  generateSecret,
  computeCode,
  verify,
  buildOtpauthURL,
  // Recovery codes
  generateRecoveryCodes,
  hashRecoveryCode,
  findRecoveryCode,
  // Password hashing
  hashPassword,
  verifyPassword,
  // Base32 (导出供测试用)
  base32Encode,
  base32Decode,
};
