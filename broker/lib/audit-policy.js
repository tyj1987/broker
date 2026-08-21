// broker/lib/audit-policy.js — sampling + retention for JSONL audit files (no deps)
// Phase D.

import { existsSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Should this event be written?
 * @param {object} event
 * @param {{ sampleRate?: number, alwaysActions?: string[], dropActions?: string[] }} policy
 * @returns {boolean}
 */
export function shouldSampleAudit(event, policy = {}) {
  const action = (event?.action || '').toLowerCase();
  const drop = (policy.dropActions || []).map((a) => a.toLowerCase());
  if (drop.includes(action)) return false;

  const always = (policy.alwaysActions || [
    'login', 'login_mfa', 'logout', 'secret_get', 'secret_put', 'secret_delete',
    'proxy', 'connect',
  ]).map((a) => a.toLowerCase());
  if (always.includes(action)) return true;
  if (event?.status === 'denied' || event?.status === 'error') return true;

  const rate = policy.sampleRate;
  if (rate == null || rate >= 1) return true;
  if (rate <= 0) return false;
  return Math.random() < rate;
}

/**
 * Wrap an audit(fn) so sampling applies. Always emits to bus if opts.busAlways.
 * @param {(e: object) => object} auditFn
 * @param {object} policy
 */
export function withAuditSampling(auditFn, policy = {}) {
  return function sampledAudit(event) {
    if (!shouldSampleAudit(event, policy)) {
      return { ...event, _sampled_out: true };
    }
    return auditFn(event);
  };
}

/**
 * Delete audit-*.jsonl files older than retainDays.
 * @param {string} auditDir
 * @param {number} retainDays default 30
 * @returns {{ deleted: string[], kept: string[] }}
 */
export function pruneAuditFiles(auditDir, retainDays = 30) {
  const deleted = [];
  const kept = [];
  if (!existsSync(auditDir)) return { deleted, kept };
  const cutoff = Date.now() - retainDays * 24 * 60 * 60 * 1000;
  const files = readdirSync(auditDir).filter(
    (f) => f.startsWith('audit-') && (f.endsWith('.jsonl') || f.endsWith('.jsonl.1')),
  );
  for (const f of files) {
    const p = join(auditDir, f);
    let mtime;
    try {
      mtime = statSync(p).mtimeMs;
    } catch {
      continue;
    }
    // Prefer date in filename audit-YYYY-MM-DD.jsonl
    const dm = f.match(/audit-(\d{4}-\d{2}-\d{2})/);
    if (dm) {
      const t = Date.parse(dm[1] + 'T00:00:00Z');
      if (!Number.isNaN(t) && t < cutoff) {
        try {
          unlinkSync(p);
          deleted.push(f);
        } catch {
          kept.push(f);
        }
        continue;
      }
    } else if (mtime < cutoff) {
      try {
        unlinkSync(p);
        deleted.push(f);
      } catch {
        kept.push(f);
      }
      continue;
    }
    kept.push(f);
  }
  return { deleted, kept };
}

/**
 * Policy from env:
 *   AUDIT_SAMPLE_RATE=0.1
 *   AUDIT_RETAIN_DAYS=30
 */
export function auditPolicyFromEnv(env = process.env) {
  const sampleRate = env.AUDIT_SAMPLE_RATE != null
    ? Number(env.AUDIT_SAMPLE_RATE)
    : 1;
  const retainDays = env.AUDIT_RETAIN_DAYS != null
    ? Number(env.AUDIT_RETAIN_DAYS)
    : 30;
  return {
    sampleRate: Number.isFinite(sampleRate) ? sampleRate : 1,
    retainDays: Number.isFinite(retainDays) ? retainDays : 30,
  };
}
