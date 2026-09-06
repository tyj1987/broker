// broker/lib/audit.js — JSONL audit log + in-process SSE bus
// Phase B extraction from server.js.

import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { redactDeep } from './redact.js';

/**
 * Create an audit subsystem bound to a directory.
 * @param {string} auditDir
 */
export function createAudit(auditDir) {
  if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });

  const bus = new EventEmitter();
  bus.setMaxListeners(0);

  let auditBytes = 0;

  function auditFilePath() {
    const d = new Date().toISOString().slice(0, 10);
    return join(auditDir, `audit-${d}.jsonl`);
  }

  function audit(event) {
    const e = redactDeep({
      ts: new Date().toISOString(),
      id: randomUUID(),
      ...event,
    });
    const line = JSON.stringify(e) + '\n';
    try {
      appendFileSync(auditFilePath(), line, { encoding: 'utf8' });
      auditBytes += Buffer.byteLength(line, 'utf8');
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
    setImmediate(() => bus.emit('event', e));
    return e;
  }

  function readAuditFiltered({
    client, service, action, status, since, until, limit = 100,
  } = {}) {
    const files = readdirSync(auditDir)
      .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    const out = [];
    const maxLimit = Math.min(Math.max(1, limit), 5000);
    const cnL = client ? String(client).toLowerCase() : null;
    const svcL = service ? String(service).toLowerCase() : null;
    const actL = action ? String(action).toLowerCase() : null;
    const stL = status ? String(status).toLowerCase() : null;
    for (const f of files) {
      if (out.length >= maxLimit) break;
      const content = readFileSync(join(auditDir, f), 'utf8');
      for (const line of content.split('\n').reverse()) {
        if (!line) continue;
        let e;
        try { e = JSON.parse(line); } catch { continue; }
        if (since && e.ts < since) continue;
        if (until && e.ts > until) continue;
        if (cnL && !(e.cn || '').toLowerCase().includes(cnL)) continue;
        if (svcL && !(e.service || '').toLowerCase().includes(svcL)) continue;
        if (actL && !(e.action || '').toLowerCase().includes(actL)) continue;
        if (stL && !(e.status || '').toLowerCase().includes(stL)) continue;
        out.push(e);
        if (out.length >= maxLimit) break;
      }
    }
    return out;
  }

  function readAudit({ since, limit = 100 } = {}) {
    return readAuditFiltered({ since, limit });
  }

  return { audit, readAudit, readAuditFiltered, bus };
}
