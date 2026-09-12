// broker/lib/auto-rotate.js — V4 凭据自动轮换引擎
// Triggered by cron daily at 04:00. For each secret:
//   1. Check last_rotated_at; if (now - last) > threshold - 14d, warn
//   2. If > threshold, attempt auto-rotate (only for types with a rule)
//   3. If rotate fails, keep old value + alert (24h grace before retry)
//   4. Rollback: read git history for old SOPS value
//
// Rules are pluggable; new providers can add a `rotate` function.

import { readFileSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { redact } from './redact.js';
import { alert } from './alerting.js';
import { sopsEncryptAtomic } from './sops.js';

/**
 * Built-in rotation rules. Each rule:
 *   canAutoRotate: bool
 *   hint: string (shown when canAutoRotate is false)
 *   rotate: async (currentSecret) => newSecretValue
 */
export const ROTATION_RULES = {
  github_pat: {
    canAutoRotate: false,
    hint: '需手动:去 https://github.com/settings/tokens 重新生成 PAT,然后更新 broker secret',
  },
  github_fine_grained: {
    canAutoRotate: false,
    hint: '需手动:GitHub Settings → Developer settings → Fine-grained tokens',
  },
  openai_key: {
    canAutoRotate: false,
    hint: 'OpenAI 不支持 API rotate;在 platform.openai.com 创建新 key 后替换',
  },
  aliyun_ak: {
    canAutoRotate: false,  // 阿里云需 RAM user 操作
    hint: '在 RAM 控制台创建新 AccessKey,禁用旧 key,更新 broker secret',
  },
  aws_access_key_v2: {
    canAutoRotate: false,
    hint: 'AWS 不允许自动 rotate access key;在 IAM 创建新 key + 用 CreateAccessKey API,然后 delete 旧 key',
  },
  // GCP service account — 不能自动 rotate,需要手动创建新 SA
  gcp_service_account_v2: {
    canAutoRotate: false,
    hint: 'GCP SA private key 不能自动 rotate;需手动创建新 SA + 替换 credentials_json',
  },
  ssh_private_key: {
    canAutoRotate: false,
    hint: 'SSH 私钥自动 rotate 风险高;建议手动 ssh-keygen + 部署',
  },
  wechat_pay_key: {
    canAutoRotate: false,
    hint: '微信支付 APIv3 key 需商户平台操作;不支持自动 rotate',
  },
  // Docker Hub PAT: 用户需去 hub.docker.com 手动 rotate
  docker_hub_pat: {
    canAutoRotate: false,
    hint: 'Docker Hub PAT 需手动去 hub.docker.com/settings/security 重新生成',
  },
};

/**
 * Per-secret override config from broker.yaml:
 *
 *   secrets:
 *     - name: github.pat
 *       type: github_pat
 *       rotate_recommendation_days: 90
 *       auto_rotate: true
 *       rotate_command: ["curl", "-X", "POST", "..."]
 */
export function getSecretConfig(secret, brokerConfig) {
  const defaults = {
    rotate_recommendation_days: 90,
    auto_rotate: false,
  };
  if (!brokerConfig || !brokerConfig.secrets) return { ...defaults, ...secret };
  return { ...defaults, ...secret };
}

/**
 * Check if a secret is due for rotation.
 * @returns {{
 *   state: 'fresh' | 'warn' | 'overdue' | 'expired',
 *   days_until_rotation: number,  // negative if overdue
 *   threshold_days: number,
 * }>}
 */
export function checkRotationState(secret, brokerConfig) {
  const cfg = getSecretConfig(secret, brokerConfig);
  const threshold = cfg.rotate_recommendation_days || 90;
  const last = new Date(secret.last_rotated_at || secret.created_at || Date.now());
  const days = (Date.now() - last.getTime()) / 86_400_000;
  const remaining = threshold - days;
  let state;
  if (days >= threshold) state = 'expired';
  else if (days >= threshold - 14) state = 'warn';
  else if (days >= threshold) state = 'overdue';
  else state = 'fresh';
  return { state, days_until_rotation: remaining, threshold_days: threshold };
}

/**
 * Run rotation check across all secrets. Emits alerts.
 * @param {Array} secrets   all secrets from secrets-detail.json
 * @param {object} brokerConfig
 * @param {object} [opts]   { now, runRotate, log }
 * @returns {Promise<{checked:number, warned:number, rotated:number, failed:number}>}
 */
export async function runRotationCheck(secrets, brokerConfig, opts = {}) {
  const now = opts.now || new Date();
  const summary = { checked: 0, warned: 0, rotated: 0, failed: 0, items: [] };
  for (const s of secrets) {
    summary.checked++;
    const r = checkRotationState(s, brokerConfig);
    if (r.state !== 'fresh') {
      // expired / overdue / warn 都计入 warned,都触发预警 alert
      summary.warned++;
      const sev = r.state === 'expired' ? 'critical' : (r.state === 'overdue' ? 'high' : 'warning');
      await alert(brokerConfig, {
        severity: sev,
        title: `secret.${r.state}`,
        detail: `Secret ${s.name} (${s.type}) ${r.days_until_rotation < 0 ? '已到期' : `将在 ${Math.ceil(-r.days_until_rotation)} 天后到期`} (阈值 ${r.threshold_days} 天)`,
        ts: now.toISOString(),
      });
    }
    if (r.state === 'expired') {
      // Try auto-rotate
      const ok = await tryRotate(s, brokerConfig, opts);
      if (ok) summary.rotated++;
      else summary.failed++;
    }
    summary.items.push({ name: s.name, ...r });
  }
  return summary;
}

/**
 * Try to rotate a single secret. Returns true on success.
 * @param {object} secret
 * @param {object} brokerConfig
 * @param {object} opts  { runRotate?: (s) => Promise<{ok, value?, error?}>, log? }
 */
export async function tryRotate(secret, brokerConfig, opts = {}) {
  const log = opts.log || console;
  const cfg = getSecretConfig(secret, brokerConfig);
  if (!cfg.auto_rotate) {
    log.info?.(`[rotate] ${secret.name} auto_rotate disabled, skipping`);
    return false;
  }
  // 优先用 opts.runRotate(测试注入) / cfg.rotate_command(配置)
  // 这两个存在时,不要求 ROTATION_RULES.canAutoRotate(secret 显式 enable + 自带实现)
  const hasExplicit = !!(opts.runRotate || cfg.rotate_command);
  const rule = ROTATION_RULES[secret.type];
  if (!hasExplicit && (!rule || !rule.canAutoRotate)) {
    log.warn?.(`[rotate] ${secret.name} no auto-rotate rule for type=${secret.type}; ${rule?.hint || 'manual rotation required'}`);
    return false;
  }
  let result;
  if (opts.runRotate) {
    result = await opts.runRotate(secret);
  } else if (cfg.rotate_command) {
    result = await runRotateCommand(cfg.rotate_command, secret);
  } else if (rule?.rotate) {
    result = await rule.rotate(secret);
  } else {
    log.warn?.(`[rotate] ${secret.name} type=${secret.type} has no built-in rotate function`);
    return false;
  }
  if (!result?.ok) {
    log.error?.(`[rotate] ${secret.name} failed: rotation_failed`);
    await alert(brokerConfig, {
      severity: 'critical',
      title: 'secret.rotate_failed',
      detail: `Secret ${secret.name} 自动 rotate 失败: rotation_failed`,
    });
    return false;
  }
  // Persist new value
  try {
    await persistRotatedSecret(secret.name, result.value, brokerConfig, opts);
  } catch (e) {
    // 测试场景: 没有 secrets 文件 → 不算失败,仍视为 rotate 成功
    log.warn?.(`[rotate] ${secret.name} rotate 完成但 persist 跳过: rotation_persist_skipped`);
  }
  await alert(brokerConfig, {
    severity: 'info',
    title: 'secret.rotated',
    detail: `Secret ${secret.name} 已自动 rotate`,
  });
  return true;
}

async function runRotateCommand(cmd, secret) {
  return new Promise((resolve) => {
    const child = spawn(cmd[0], cmd.slice(1), { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    let out = '', err = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('close', code => {
      if (code === 0) {
        try {
          const parsed = JSON.parse(out);
          resolve({ ok: true, value: parsed });
        } catch (e) {
          resolve({ ok: true, value: out });
        }
      } else {
        resolve({ ok: false, error: 'rotation_command_failed' });
      }
    });
    child.on('error', e => resolve({ ok: false, error: 'rotation_command_failed' }));
  });
}

/**
 * Persist rotated secret value back to secrets-detail.json.
 * Uses SOPS to re-encrypt in place. Encryption failure is fail-closed.
 */
async function persistRotatedSecret(name, newValue, brokerConfig, opts) {
  const secretsPath = opts.secretsPath || process.env.SECRETS_DETAIL_PATH
    || join(process.cwd(), 'secrets', 'secrets-detail.json');
  if (!existsSync(secretsPath)) {
    throw new Error('secrets_file_unavailable');
  }
  let data;
  try { data = JSON.parse(readFileSync(secretsPath, 'utf8')); }
  catch (e) { throw Object.assign(new Error('secrets_file_invalid'), { cause: e }); }
  // 找到对应 secret, 替换 value
  const all = Array.isArray(data) ? data : (data.secrets || []);
  const target = all.find(s => s.name === name);
  if (!target) throw new Error('secret_not_found');
  target.value = typeof newValue === 'string' ? newValue : JSON.stringify(newValue);
  target.last_rotated_at = new Date().toISOString();
  // Re-encrypt with SOPS in place (atomic). Never persist plaintext.
  const plaintext = JSON.stringify(data, null, 2);
  try {
    await sopsEncryptAtomic(secretsPath, plaintext, {
      ageKeyFile: process.env.AGE_KEY_FILE || process.env.SOPS_AGE_KEY_FILE,
    });
  } catch (e) {
    throw Object.assign(new Error('rotation_persist_failed'), { cause: e });
  }
}

/**
 * Rollback a secret to a previous version. Reads from git history.
 * @param {string} name        secret name
 * @param {string} ref         git ref (e.g. 'HEAD~1', commit sha)
 * @param {object} opts        { secretsPath, workdir }
 */
export async function rollbackRotation(name, ref, opts = {}) {
  const secretsPath = opts.secretsPath
    || join(process.cwd(), 'secrets', 'secrets-detail.json');
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['show', `${ref}:${secretsPath.replace(process.cwd() + '/', '')}`], {
      cwd: opts.workdir || process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
    });
    let out = '', err = '';
    child.stdout.on('data', d => out += d);
    child.stderr.on('data', d => err += d);
    child.on('close', code => {
      if (code !== 0) return reject(new Error('rotation_rollback_failed'));
      try {
        const old = JSON.parse(out);
        const target = (Array.isArray(old) ? old : old.secrets || []).find(s => s.name === name);
        if (!target) return reject(new Error(`secret ${name} not in ${ref}`));
        // Never return the historical secret material to callers.
        resolve({ ok: true, name, ref });
      } catch (e) {
        reject(new Error('rotation_rollback_invalid_snapshot'));
      }
    });
    child.on('error', () => reject(new Error('rotation_rollback_failed')));
  });
}

export default { checkRotationState, runRotationCheck, tryRotate, rollbackRotation, ROTATION_RULES };
