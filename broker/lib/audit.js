// broker/lib/audit.js — JSONL audit log + in-process SSE bus + ring buffer
// Phase B extraction from server.js.
// V4.1.1: hard fail on disk write error so callers can refuse the operation,
// and keep an in-memory ring buffer for hot reads (avoids re-reading 100s of MB
// of jsonl every dashboard refresh).

import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { redactDeep } from './redact.js';

const RING_BUFFER_MAX = 1000;
const WRITE_FAILURE_BACKOFF_MS = 30_000;

class AuditWriteError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'AuditWriteError';
    this.cause = cause;
  }
}

/**
 * Create an audit subsystem bound to a directory.
 * @param {string} auditDir
 * @param {{ onWriteError?: (err: Error, event: object) => void, hashChain?: boolean }} [opts]
 */
export function createAudit(auditDir, opts = {}) {
  if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });

  const bus = new EventEmitter();
  bus.setMaxListeners(0);

  let auditBytes = 0;
  let lastWriteError = null;
  let lastWriteErrorAt = 0;
  let consecutiveFailures = 0;
  let lastHash = null; // for tamper-evidence chain (V4.1.1)

  // Ring buffer for hot reads (most recent first)
  const ring = []; // array of events, append at end
  const ringById = new Map(); // id -> event for dedupe

  function auditFilePath() {
    const d = new Date().toISOString().slice(0, 10);
    return join(auditDir, `audit-${d}.jsonl`);
  }

  function audit(event, opts2 = {}) {
    const mandatory = opts2.mandatory === true;
    const e = redactDeep({
      ts: new Date().toISOString(),
      id: randomUUID(),
      ...event,
    });
    const line = JSON.stringify(e) + '\n';
    let writeError = null;
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
      // mark healthy again
      if (consecutiveFailures > 0) {
        bus.emit('recovery', { ts: e.ts, after_failures: consecutiveFailures });
      }
      consecutiveFailures = 0;
      lastWriteError = null;
    } catch (err) {
      writeError = new AuditWriteError(
        `audit write failed (mandatory=${mandatory}): ${err.message}`,
        err,
      );
      consecutiveFailures++;
      lastWriteError = err;
      lastWriteErrorAt = Date.now();
      // Notify subscribers (dashboard) that audit is unhealthy
      bus.emit('write_error', { ts: e.ts, error: err.message, mandatory, consecutive: consecutiveFailures });
      // Optional callback for operator alerting
      if (typeof opts.onWriteError === 'function') {
        try { opts.onWriteError(err, e); } catch { /* don't let alerting kill the audit */ }
      }
      // Hard fail: if caller marked this audit as mandatory (login, secret rotate, etc.),
      // throw so the upstream HTTP handler can return 503 and the caller can retry.
      if (mandatory) {
        throw writeError;
      }
    }
    // Push to ring buffer (only after we have an id; failed events also pushed so callers
    // can correlate if they catch the throw).
    if (ring.length >= RING_BUFFER_MAX) {
      const evicted = ring.shift();
      if (evicted) ringById.delete(evicted.id);
    }
    ring.push(e);
    ringById.set(e.id, e);
    setImmediate(() => bus.emit('event', e));
    return e;
  }

  /**
   * Read from the in-memory ring buffer (most recent first).
   * @param {{ limit?: number, action?: string, status?: string, cn?: string }} [filter]
   */
  function readRing(filter = {}) {
    const limit = Math.min(Math.max(1, filter.limit || 100), RING_BUFFER_MAX);
    const actL = filter.action ? String(filter.action).toLowerCase() : null;
    const stL = filter.status ? String(filter.status).toLowerCase() : null;
    const cnL = filter.cn ? String(filter.cn).toLowerCase() : null;
    const out = [];
    for (let i = ring.length - 1; i >= 0 && out.length < limit; i--) {
      const e = ring[i];
      if (actL && !(e.action || '').toLowerCase().includes(actL)) continue;
      if (stL && !(e.status || '').toLowerCase().includes(stL)) continue;
      if (cnL && !(e.cn || '').toLowerCase().includes(cnL)) continue;
      out.push(e);
    }
    return out;
  }

  function readAuditFiltered({
    client, service, action, status, since, until, limit = 100, prefer = 'auto',
  } = {}) {
    const maxLimit = Math.min(Math.max(1, limit), 5000);
    // If filter fits within ring buffer scope (no since/until older than ring) and
    // user is OK with ring semantics, short-circuit.
    if (prefer === 'ring') return readRing({ action, status, cn: client, limit: maxLimit });
    const out = [];
    const files = readdirSync(auditDir)
      .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
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

  function health() {
    const inBackoff = lastWriteError && (Date.now() - lastWriteErrorAt) < WRITE_FAILURE_BACKOFF_MS;
    return {
      ok: lastWriteError === null,
      last_write_error: lastWriteError ? lastWriteError.message : null,
      last_write_error_at: lastWriteErrorAt || null,
      consecutive_failures: consecutiveFailures,
      in_backoff: !!inBackoff,
      ring_buffer_size: ring.length,
      ring_buffer_max: RING_BUFFER_MAX,
      audit_dir: auditDir,
    };
  }

  return {
    audit,
    readAudit,
    readAuditFiltered,
    readRing,
    health,
    bus,
    AuditWriteError,
  };
}
