// broker/migrate-v2-to-v3.js — v2 → v3 broker.yaml 迁移
//
// 启动时由 server.js 调用一次，自动给老 client 加默认字段，
// 老的明文 password 字段自动 hash 化。
// 幂等：跑过不会再改。
//
// v3.0 新增字段（默认）：
//   - password_set_at          (v3.0 引入)
//   - password_expires_at      (默认 null, 永久)
//   - totp_secret              (默认 undefined, 启 TOTP 时填)
//   - totp_enabled_at          (默认 undefined)
//   - totp_recovery_codes_hash (默认 [])
//   - cert_expires_at          (从 cert PEM 解析, 默认 365d 后续会改成 90d)
//   - last_password_change     (默认 = password_set_at)
//   - last_cert_rotation       (默认 = cert_expires_at - 365d)
//   - preferred_2fa            (默认 'none')
//
// 行为：
//   1. password 字段若是明文 → hash 化
//   2. 给每个 client 补缺失的 v3.0 字段
//   3. cert_expires_at 从磁盘 PEM 解析
//   4. 写 audit log
//
// 注意：仅修改内存中的 CONFIG.clients，不直接写 broker.yaml
// （由 server.js 的 persistConfig 统一加密落盘）

import { readFileSync, existsSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { hashPassword } from './totp.js';

const SCHEMA_VERSION = 3;

/**
 * v2 → v3 迁移（幂等）
 * @param {object} CONFIG - 内存中的 broker 配置
 * @param {string} clientsDir - pki/clients/ 路径（用于读 cert 算 expires）
 * @param {function} audit - audit log 写入函数
 * @param {function} persistConfig - 加密写回函数
 * @returns {{ changed: boolean, changes: string[] }}
 */
export async function migrateV2ToV3(CONFIG, clientsDir, audit, persistConfig) {
  const changes = [];
  let needsPersist = false;

  // 0. 顶层 schema version
  if (!CONFIG.schema_version || CONFIG.schema_version < SCHEMA_VERSION) {
    CONFIG.schema_version = SCHEMA_VERSION;
    changes.push(`schema_version: ${CONFIG.schema_version || 1} -> ${SCHEMA_VERSION}`);
    needsPersist = true;
  }

  // 1. clients 字典
  for (const [name, c] of Object.entries(CONFIG.clients || {})) {
    if (!c) continue;

    // 1.1 明文 password -> hash
    if (c.password && !c.password.startsWith('scrypt$')) {
      const plain = c.password;
      c.password = hashPassword(plain);
      c.password_set_at = c.password_set_at || new Date().toISOString();
      c.last_password_change = c.password_set_at;
      changes.push(`${name}: password plaintext -> scrypt hash`);
      needsPersist = true;
    }

    // 1.2 password_set_at 默认值
    if (!c.password_set_at && c.password) {
      c.password_set_at = new Date().toISOString();
      changes.push(`${name}: default password_set_at`);
      needsPersist = true;
    }

    // 1.3 cert_expires_at 从 cert PEM 解析
    if (!c.cert_expires_at && c.cert_fingerprint_sha256) {
      const crtPath = `${clientsDir}/${name}.crt`;
      if (existsSync(crtPath)) {
        try {
          const pem = readFileSync(crtPath, 'utf8');
          const cert = new X509Certificate(pem);
          const notAfter = new Date(cert.notAfter);
          c.cert_expires_at = notAfter.toISOString();
          // last_cert_rotation = notAfter - 365d
          const issued = new Date(notAfter);
          issued.setDate(issued.getDate() - 365);
          c.last_cert_rotation = issued.toISOString();
          changes.push(`${name}: cert_expires_at parsed from PEM`);
          needsPersist = true;
        } catch (e) {
          // 解析失败不阻塞
        }
      }
    }

    // 1.4 preferred_2fa 默认
    if (c.preferred_2fa === undefined) {
      c.preferred_2fa = c.totp_secret ? 'totp' : 'none';
      changes.push(`${name}: default preferred_2fa=${c.preferred_2fa}`);
      needsPersist = true;
    }
  }

  // 2. 顶层 notifications 字段
  if (!CONFIG.notifications) {
    CONFIG.notifications = { sms: null, email: null };
    changes.push('top-level: added empty notifications');
    needsPersist = true;
  }

  // 3. 顶层 api_keys 字段
  if (!Array.isArray(CONFIG.api_keys)) {
    CONFIG.api_keys = [];
    changes.push('top-level: initialized api_keys=[]');
    needsPersist = true;
  }

  // 4. 顶层 healthcheck 字段
  if (!CONFIG.healthcheck) {
    CONFIG.healthcheck = { enabled: true, schedule: '04:00', alert_channels: ['sse'] };
    changes.push('top-level: default healthcheck config');
    needsPersist = true;
  }

  // 5. 持久化
  if (needsPersist) {
    try {
      await persistConfig();
      audit({ action: 'migration', from: 2, to: SCHEMA_VERSION, status: 'ok', changes: changes.length });
    } catch (e) {
      audit({ action: 'migration', from: 2, to: SCHEMA_VERSION, status: 'error', error: e.message });
      throw e;
    }
  }

  return { changed: needsPersist, changes };
}
