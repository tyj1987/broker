// broker/lib/audit-async.js — V4.1.1 async I/O helpers for audit
//
// Audit writes are critical for compliance. The sync appendFileSync() in
// audit.js is fine for single-process brokers, but blocks the event loop
// briefly on every call. For high-throughput deployments or audit-mandatory
// flows that need true durability, switch to async appendFile() with proper
// backpressure handling.
//
// Usage:
//   const audit = createAuditAsync({ auditDir: '/var/log/broker/audit' });
//   await audit.write({ action: 'login', cn, fp, status: 'ok' });
//
// The async variant emits the same `event` on the bus, returns the same
// event envelope, and respects the same `mandatory: true` option.

import { EventEmitter } from 'node:events';
import { appendFile, mkdir, rename, stat, readdir, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { redactDeep } from './redact.js';

const RING_BUFFER_MAX = 1000;
const ROTATE_BYTES = 50 * 1024 * 1024;

export class AsyncAuditWriteError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'AsyncAuditWriteError';
    this.cause = cause;
  }
}

/**
 * @param {object} opts
 * @param {string} opts.auditDir
 * @param {Function} [opts.onWriteError]  - (err, event) => void
 */
export function createAuditAsync(opts) {
  const { auditDir, onWriteError } = opts;
  if (!auditDir) throw new Error('audit-async: auditDir required');

  const bus = new EventEmitter();
  bus.setMaxListeners(0);

  let auditBytes = 0;
  let lastWriteError = null;
  let lastWriteErrorAt = 0;
  let consecutiveFailures = 0;

  const ring = [];
  const ringById = new Map();

  async function ensureDir() {
    if (!existsSync(auditDir)) await mkdir(auditDir, { recursive: true });
  }

  function auditFilePath(d = new Date()) {
    const day = d.toISOString().slice(0, 10);
    return join(auditDir, `audit-${day}.jsonl`);
  }

  async function rotateIfNeeded() {
    if (auditBytes <= ROTATE_BYTES) return;
    const old = auditFilePath();
    const rotated = old.replace(/\.jsonl$/, `-${Date.now()}-${randomUUID()}.jsonl`);
    try { await rename(old, rotated); auditBytes = 0; } catch { /* ignore */ }
  }

  /**
   * Write an audit event. Async — awaits the underlying fs.appendFile.
   * @param {object} event
   * @param {{ mandatory?: boolean }} [opts]
   * @returns {Promise<object>} the written event
   */
  async function write(event, opts2 = {}) {
    const mandatory = opts2.mandatory === true;
    const e = redactDeep({
      ts: new Date().toISOString(),
      id: randomUUID(),
      ...event,
    });
    const line = JSON.stringify(e) + '\n';
    let writeError = null;
    try {
      await ensureDir();
      await appendFile(auditFilePath(), line, { encoding: 'utf8' });
      auditBytes += Buffer.byteLength(line, 'utf8');
      await rotateIfNeeded();
      if (consecutiveFailures > 0) bus.emit('recovery', { ts: e.ts, after_failures: consecutiveFailures });
      consecutiveFailures = 0;
      lastWriteError = null;
    } catch (err) {
      writeError = new AsyncAuditWriteError(`audit write failed (mandatory=${mandatory}): ${err.message}`, err);
      consecutiveFailures++;
      lastWriteError = err;
      lastWriteErrorAt = Date.now();
      bus.emit('write_error', { ts: e.ts, error: err.message, mandatory, consecutive: consecutiveFailures });
      if (typeof onWriteError === 'function') {
        try { onWriteError(err, e); } catch { /* ignore */ }
      }
      if (mandatory) throw writeError;
    }
    if (ring.length >= RING_BUFFER_MAX) {
      const evicted = ring.shift();
      if (evicted) ringById.delete(evicted.id);
    }
    ring.push(e);
    ringById.set(e.id, e);
    setImmediate(() => bus.emit('event', e));
    return e;
  }

  async function readRing(filter = {}) {
    const limit = Math.min(Math.max(1, filter.limit || 100), RING_BUFFER_MAX);
    const actL = filter.action ? String(filter.action).toLowerCase() : null;
    const stL = filter.status ? String(filter.status).toLowerCase() : null;
    const cnL = filter.cn ? String(filter.cn).toLowerCase() : null;
    const out = [];
    for (let i = ring.length - 1; i >= 0 && out.length < limit; i--) {
      const ev = ring[i];
      if (actL && !(ev.action || '').toLowerCase().includes(actL)) continue;
      if (stL && !(ev.status || '').toLowerCase().includes(stL)) continue;
      if (cnL && !(ev.cn || '').toLowerCase().includes(cnL)) continue;
      out.push(ev);
    }
    return out;
  }

  async function readFiltered({ client, service, action, status, since, until, limit = 100 } = {}) {
    const maxLimit = Math.min(Math.max(1, limit), 5000);
    const files = (await readdir(auditDir))
      .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    const out = [];
    const cnL = client ? String(client).toLowerCase() : null;
    const svcL = service ? String(service).toLowerCase() : null;
    const actL = action ? String(action).toLowerCase() : null;
    const stL = status ? String(status).toLowerCase() : null;
    for (const f of files) {
      if (out.length >= maxLimit) break;
      const content = await readFile(join(auditDir, f), 'utf8');
      for (const line of content.split('\n').reverse()) {
        if (!line) continue;
        let ev;
        try { ev = JSON.parse(line); } catch { continue; }
        if (since && ev.ts < since) continue;
        if (until && ev.ts > until) continue;
        if (cnL && !(ev.cn || '').toLowerCase().includes(cnL)) continue;
        if (svcL && !(ev.service || '').toLowerCase().includes(svcL)) continue;
        if (actL && !(ev.action || '').toLowerCase().includes(actL)) continue;
        if (stL && !(ev.status || '').toLowerCase().includes(stL)) continue;
        out.push(ev);
        if (out.length >= maxLimit) break;
      }
    }
    return out;
  }

  function health() {
    return {
      ok: lastWriteError === null,
      last_write_error: lastWriteError ? lastWriteError.message : null,
      last_write_error_at: lastWriteErrorAt || null,
      consecutive_failures: consecutiveFailures,
      ring_buffer_size: ring.length,
      ring_buffer_max: RING_BUFFER_MAX,
      audit_dir: auditDir,
    };
  }

  return { write, readRing, readFiltered, health, bus, AsyncAuditWriteError };
}
