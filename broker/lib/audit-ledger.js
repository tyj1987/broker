// Durable, single-directory audit ledger. Append -> fsync -> atomic checkpoint.
// An interrupted append/checkpoint is never silently truncated, resealed or
// declared verified. Operators must preserve evidence and reconcile it offline.
// Historical unsigned JSONL is inventoried byte-for-byte, not retroactively signed.
import * as fs from 'node:fs';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { GENESIS_HASH, HASH_RE, computeHash, sealEvent, verifyChain } from './audit-hash-chain.js';

export const LEDGER_STATE = 'audit-chain-state.json';
export const LEDGER_LOCK = 'audit-chain.lock';
const SEGMENT_RE = /^audit-chain-\d{12}\.jsonl$/;
const LOG_RE = /^audit-[A-Za-z0-9_.-]+\.jsonl(?:\.\d+)?$/;
const MAX_SEGMENTS = 4096;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_SCAN_BYTES = 512 * 1024 * 1024;
const MAX_EVENT_BYTES = 1024 * 1024;
const digest = (data) => createHash('sha256').update(data).digest('hex');
const safeInteger = (n) => Number.isSafeInteger(n) && n >= 0;

export class AuditLedgerError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'AuditLedgerError';
    this.code = 'AUDIT_UNAVAILABLE';
    this.statusCode = 503;
  }
}

function regularBytes(path, limit = MAX_FILE_BYTES) {
  const info = fs.lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > limit)
    throw new AuditLedgerError('Audit file is not a bounded regular file');
  return fs.readFileSync(path);
}

export function auditLogFiles(dir) {
  // Older numbered rotations precede the current same-day file. Chain segment
  // numbers are zero padded and naturally sort after legacy date filenames.
  return fs
    .readdirSync(dir)
    .filter((name) => LOG_RE.test(name))
    .sort((a, b) => {
      const abase = a.replace(/\.\d+$/, '');
      const bbase = b.replace(/\.\d+$/, '');
      if (abase !== bbase) return abase < bbase ? -1 : 1;
      return (
        Number(b.match(/\.(\d+)$/)?.[1] || 0) - Number(a.match(/\.(\d+)$/)?.[1] || 0) ||
        a.localeCompare(b)
      );
    });
}

function parseRecords(bytes) {
  if (bytes.length && bytes[bytes.length - 1] !== 10)
    throw new AuditLedgerError('Incomplete audit record at file tail');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return text
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => {
      if (Buffer.byteLength(line) > MAX_EVENT_BYTES)
        throw new AuditLedgerError('Audit record exceeds verification limit');
      const event = JSON.parse(line);
      if (!event || typeof event !== 'object' || Array.isArray(event))
        throw new AuditLedgerError('Invalid audit record');
      return event;
    });
}

function readState(dir) {
  const state = JSON.parse(regularBytes(join(dir, LEDGER_STATE), 4 * 1024 * 1024));
  if (
    state.schema !== 1 ||
    typeof state.chain_id !== 'string' ||
    !/^[0-9a-f-]{36}$/.test(state.chain_id) ||
    !safeInteger(state.revision) ||
    !safeInteger(state.total_events) ||
    !HASH_RE.test(state.head_hash) ||
    !Array.isArray(state.segments) ||
    state.segments.length > MAX_SEGMENTS ||
    !Array.isArray(state.legacy_files) ||
    state.legacy_files.length > MAX_SEGMENTS ||
    state.legacy_manifest_sha256 !== computeHash(state.legacy_files)
  )
    throw new AuditLedgerError('Invalid audit checkpoint');
  const names = new Set();
  for (const entry of state.legacy_files) {
    if (
      !LOG_RE.test(entry.name) ||
      SEGMENT_RE.test(entry.name) ||
      names.has(entry.name) ||
      !safeInteger(entry.bytes) ||
      !safeInteger(entry.records) ||
      !HASH_RE.test(entry.sha256)
    )
      throw new AuditLedgerError('Invalid legacy audit inventory');
    names.add(entry.name);
  }
  for (const [index, segment] of state.segments.entries()) {
    if (
      segment.name !== `audit-chain-${String(index + 1).padStart(12, '0')}.jsonl` ||
      names.has(segment.name) ||
      !safeInteger(segment.bytes) ||
      segment.bytes > MAX_FILE_BYTES ||
      !safeInteger(segment.count) ||
      segment.count < 1 ||
      !safeInteger(segment.first_sequence) ||
      !safeInteger(segment.last_sequence) ||
      !safeInteger(segment.last_record_bytes) ||
      segment.last_record_bytes < 1 ||
      segment.last_record_bytes > segment.bytes ||
      segment.last_record_bytes > MAX_EVENT_BYTES ||
      !HASH_RE.test(segment.start_hash) ||
      !HASH_RE.test(segment.end_hash) ||
      !Number.isFinite(Date.parse(segment.created_at)) ||
      (segment.closed_at !== null && !Number.isFinite(Date.parse(segment.closed_at))) ||
      (segment.pruned_at !== null &&
        (!Number.isFinite(Date.parse(segment.pruned_at)) || segment.closed_at === null)) ||
      (segment.closed_at !== null && !HASH_RE.test(segment.sha256))
    )
      throw new AuditLedgerError('Invalid audit segment checkpoint');
    if (index < state.segments.length - 1 && segment.closed_at === null)
      throw new AuditLedgerError('Non-final audit segment is open');
    if (
      index === state.segments.length - 1 &&
      (segment.pruned_at !== null || segment.closed_at !== null)
    )
      throw new AuditLedgerError('Final audit segment must remain active');
    names.add(segment.name);
  }
  return state;
}

function syncDirectory(dir, io) {
  // Windows does not expose a portable directory fsync through Node. File data
  // is still fsynced; power-loss guarantees depend on the OS/filesystem.
  if (process.platform === 'win32') return;
  const fd = io.openSync(dir, 'r');
  try {
    io.fsyncSync(fd);
  } finally {
    io.closeSync(fd);
  }
}

function commitState(dir, state, io = fs) {
  const tmp = join(dir, `.audit-chain-state.${randomUUID()}.tmp`);
  try {
    io.writeFileSync(tmp, JSON.stringify(state) + '\n', { mode: 0o600, flag: 'wx', flush: true });
    io.renameSync(tmp, join(dir, LEDGER_STATE));
    syncDirectory(dir, io);
  } finally {
    try {
      io.unlinkSync(tmp);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}

function withLock(dir, operation, io = fs) {
  let fd;
  const path = join(dir, LEDGER_LOCK);
  try {
    // Lock ownership is not inferred from a PID: containers may reuse PIDs.
    // A crash-left lock requires explicit operator reconciliation, never theft.
    fd = io.openSync(path, 'wx', 0o600);
    io.writeFileSync(fd, JSON.stringify({ pid: process.pid, token: randomUUID() }) + '\n');
    return operation();
  } catch (error) {
    if (error instanceof AuditLedgerError) throw error;
    throw new AuditLedgerError('Audit transaction could not be committed', error);
  } finally {
    if (fd !== undefined) {
      io.closeSync(fd);
      io.unlinkSync(path);
    }
  }
}

function managedVerification(dir, state, { maxBytes = MAX_SCAN_BYTES } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0)
    throw new AuditLedgerError('Invalid audit verification budget');
  let scanned = 0;
  const read = (name) => {
    const length = fs.lstatSync(join(dir, name)).size;
    scanned += length;
    if (scanned > Math.min(maxBytes, MAX_SCAN_BYTES))
      throw new AuditLedgerError(
        'Audit verification byte budget exceeded; offline verification required',
      );
    return regularBytes(join(dir, name));
  };
  const expected = new Set([
    ...state.legacy_files.map((e) => e.name),
    ...state.segments.map((e) => e.name),
  ]);
  if (auditLogFiles(dir).some((name) => !expected.has(name)))
    throw new AuditLedgerError('Uncheckpointed audit file found');
  for (const legacy of state.legacy_files) {
    const data = read(legacy.name);
    if (
      data.length !== legacy.bytes ||
      digest(data) !== legacy.sha256 ||
      parseRecords(data).length !== legacy.records
    )
      throw new AuditLedgerError('Legacy audit baseline changed');
  }
  let previous = GENESIS_HASH;
  let total = 0;
  let retained = 0;
  let pruned = 0;
  let hasRetained = false;
  for (const segment of state.segments) {
    if (
      segment.start_hash !== previous ||
      segment.first_sequence !== total + 1 ||
      segment.last_sequence !== total + segment.count
    )
      throw new AuditLedgerError('Audit checkpoint continuity mismatch');
    if (segment.pruned_at !== null) {
      if (hasRetained) throw new AuditLedgerError('Audit retention is not a contiguous prefix');
      if (fs.existsSync(join(dir, segment.name))) {
        const data = read(segment.name);
        if (data.length !== segment.bytes || digest(data) !== segment.sha256)
          throw new AuditLedgerError('Retired audit file differs from checkpoint');
      }
      pruned += segment.count;
    } else {
      hasRetained = true;
      const data = read(segment.name);
      if (data.length !== segment.bytes)
        throw new AuditLedgerError(
          'Audit size/checkpoint mismatch (truncation or uncommitted tail)',
        );
      if (segment.closed_at !== null && digest(data) !== segment.sha256)
        throw new AuditLedgerError('Closed audit segment checksum mismatch');
      const events = parseRecords(data);
      const verified = verifyChain(events, { initialHash: previous });
      if (
        !verified.ok ||
        events.length !== segment.count ||
        verified.last_hash !== segment.end_hash
      )
        throw new AuditLedgerError(verified.reason || 'Audit segment event count/head mismatch');
      for (const [index, event] of events.entries()) {
        if (
          event.audit_sequence !== total + index + 1 ||
          event.audit_chain_id !== state.chain_id ||
          event.legacy_manifest_sha256 !== state.legacy_manifest_sha256
        )
          throw new AuditLedgerError('Audit event binding mismatch');
      }
      retained += events.length;
    }
    total += segment.count;
    previous = segment.end_hash;
  }
  if (total !== state.total_events || previous !== state.head_hash)
    throw new AuditLedgerError('Audit tail checkpoint mismatch');
  return {
    ok: true,
    count: retained,
    files: state.segments.filter((s) => s.pruned_at === null).length,
    chain_id: state.chain_id,
    total_events: total,
    head_hash: previous,
    checkpoint_revision: state.revision,
    verification_scope: pruned
      ? 'retained-events-with-local-retention-checkpoints'
      : 'managed-chain',
    pruned_events: pruned,
    legacy_files: state.legacy_files.length,
    legacy_records: state.legacy_files.reduce((n, e) => n + e.records, 0),
    legacy_baseline_unchanged: true,
    legacy_history_verified: state.legacy_files.length === 0,
    full_history_verified: pruned === 0 && state.legacy_files.length === 0,
    independently_anchored: false,
    scanned_bytes: scanned,
  };
}

export function verifyAuditDirectory(dir, options = {}) {
  if (!fs.existsSync(dir)) throw new AuditLedgerError('Audit directory is unavailable');
  if (fs.existsSync(join(dir, LEDGER_LOCK)))
    return {
      ok: false,
      retryable: true,
      reason: 'Audit transaction is locked or requires crash reconciliation',
    };
  try {
    if (fs.existsSync(join(dir, LEDGER_STATE))) {
      const before = regularBytes(join(dir, LEDGER_STATE), 4 * 1024 * 1024);
      const result = managedVerification(dir, readState(dir), options);
      if (!before.equals(regularBytes(join(dir, LEDGER_STATE), 4 * 1024 * 1024)))
        return {
          ok: false,
          retryable: true,
          reason: 'Audit checkpoint changed during verification',
        };
      return result;
    }
    const files = auditLogFiles(dir);
    if (files.some((name) => SEGMENT_RE.test(name)))
      return { ok: false, reason: 'Audit checkpoint is missing' };
    let bytes = 0;
    const events = [];
    for (const name of files) {
      const data = regularBytes(join(dir, name));
      bytes += data.length;
      if (bytes > MAX_SCAN_BYTES)
        throw new AuditLedgerError('Audit verification byte budget exceeded');
      for (const event of parseRecords(data)) events.push(event);
    }
    const result = verifyChain(events);
    return {
      ...result,
      files: files.length,
      verification_scope: 'legacy-files-without-durable-checkpoint',
      independently_anchored: false,
      full_history_verified: false,
    };
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof AuditLedgerError
          ? error.message
          : 'Unreadable or malformed audit evidence',
    };
  }
}

function initialize(dir, io) {
  if (io.existsSync(join(dir, LEDGER_STATE))) {
    const state = readState(dir);
    managedVerification(dir, state);
    return state;
  }
  const names = auditLogFiles(dir);
  if (names.length > MAX_SEGMENTS)
    throw new AuditLedgerError('Legacy inventory exceeds checkpoint capacity');
  if (names.some((name) => SEGMENT_RE.test(name)))
    throw new AuditLedgerError('Refusing to reinitialize a ledger with a missing checkpoint');
  let bytes = 0;
  const legacy = names.map((name) => {
    const data = regularBytes(join(dir, name));
    bytes += data.length;
    if (bytes > MAX_SCAN_BYTES)
      throw new AuditLedgerError('Legacy inventory exceeds online migration budget');
    return { name, bytes: data.length, records: parseRecords(data).length, sha256: digest(data) };
  });
  const state = {
    schema: 1,
    chain_id: randomUUID(),
    revision: 0,
    created_at: new Date().toISOString(),
    total_events: 0,
    head_hash: GENESIS_HASH,
    legacy_files: legacy,
    legacy_manifest_sha256: computeHash(legacy),
    segments: [],
  };
  commitState(dir, state, io);
  return state;
}

function checkActiveTail(dir, state) {
  const segment = state.segments.at(-1);
  if (!segment) return;
  const file = join(dir, segment.name);
  const st = fs.lstatSync(file);
  if (!st.isFile() || st.isSymbolicLink() || st.size !== segment.bytes)
    throw new AuditLedgerError('Audit active-file size changed');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(segment.last_record_bytes);
    if (fs.readSync(fd, buf, 0, buf.length, segment.bytes - buf.length) !== buf.length)
      throw new AuditLedgerError('Audit active tail cannot be read');
    const [event] = parseRecords(buf);
    if (
      event?.hash !== state.head_hash ||
      !verifyChain([event], { initialHash: event?.prev_hash }).ok
    )
      throw new AuditLedgerError('Audit active tail changed');
  } finally {
    fs.closeSync(fd);
  }
}

function appendLocked(dir, state, event, { io, maxSegmentBytes, now }) {
  checkActiveTail(dir, state);
  const timestamp = new Date(now()).toISOString();
  const sealed = sealEvent(
    {
      ...event,
      audit_chain_id: state.chain_id,
      audit_sequence: state.total_events + 1,
      legacy_manifest_sha256: state.legacy_manifest_sha256,
    },
    state.head_hash,
  );
  const line = JSON.stringify(sealed) + '\n';
  const length = Buffer.byteLength(line);
  if (length > MAX_EVENT_BYTES) throw new AuditLedgerError('Audit event exceeds maximum size');
  let segment = state.segments.at(-1);
  const newSegment =
    !segment ||
    segment.bytes + length > maxSegmentBytes ||
    segment.created_at.slice(0, 10) !== timestamp.slice(0, 10);
  if (newSegment) {
    if (state.segments.length >= MAX_SEGMENTS)
      throw new AuditLedgerError(
        'Audit segment checkpoint capacity reached; export/migration required',
      );
    if (segment) {
      segment.closed_at = timestamp;
      segment.sha256 = digest(regularBytes(join(dir, segment.name)));
    }
    segment = {
      name: `audit-chain-${String(state.segments.length + 1).padStart(12, '0')}.jsonl`,
      created_at: timestamp,
      closed_at: null,
      pruned_at: null,
      bytes: 0,
      count: 0,
      first_sequence: state.total_events + 1,
      last_sequence: state.total_events,
      start_hash: state.head_hash,
      end_hash: state.head_hash,
      last_record_bytes: 0,
      sha256: null,
    };
    state.segments.push(segment);
  }
  io.appendFileSync(join(dir, segment.name), line, {
    encoding: 'utf8',
    mode: 0o600,
    flag: newSegment ? 'ax' : 'a',
    flush: true,
  });
  segment.bytes += length;
  segment.count++;
  segment.last_sequence++;
  segment.end_hash = sealed.hash;
  segment.last_record_bytes = length;
  state.total_events++;
  state.head_hash = sealed.hash;
  state.revision++;
  commitState(dir, state, io);
  return sealed;
}

export function createAuditLedger(dir, options = {}) {
  const io = options.io || fs;
  const maxSegmentBytes = options.maxSegmentBytes ?? 50 * 1024 * 1024;
  if (
    !Number.isSafeInteger(maxSegmentBytes) ||
    maxSegmentBytes < 256 ||
    maxSegmentBytes > 50 * 1024 * 1024
  )
    throw new TypeError('Invalid audit segment limit');
  const now = options.now || Date.now;
  if (!io.existsSync(dir)) io.mkdirSync(dir, { recursive: true, mode: 0o700 });
  withLock(dir, () => initialize(dir, io), io);
  let lastError = null;
  return {
    append(event) {
      try {
        const result = withLock(
          dir,
          () => appendLocked(dir, readState(dir), event, { io, maxSegmentBytes, now }),
          io,
        );
        lastError = null;
        return result;
      } catch (error) {
        lastError = error;
        throw error;
      }
    },
    health() {
      return { ok: lastError === null, last_error_code: lastError?.code || null };
    },
  };
}

// Only a verified, closed, contiguous prefix can expire. Persist an intent,
// preserve segment hashes/counts/boundaries in the checkpoint, then unlink.
// The retained-chain result explicitly disclaims verification of removed data.
export function pruneAuditLedger(dir, retainDays = 30, { now = Date.now } = {}) {
  if (!Number.isFinite(retainDays) || retainDays <= 0)
    throw new TypeError('retainDays must be positive');
  return withLock(dir, () => {
    const state = readState(dir);
    managedVerification(dir, state);
    const cutoff = now() - retainDays * 86400000;
    const eligible = [];
    for (const segment of state.segments.slice(0, -1)) {
      if (segment.pruned_at) continue;
      if (segment.closed_at === null || Date.parse(segment.closed_at) >= cutoff) break;
      eligible.push(segment);
    }
    if (eligible.length) {
      const timestamp = new Date(now()).toISOString();
      appendLocked(
        dir,
        state,
        {
          ts: timestamp,
          id: randomUUID(),
          action: 'audit_retention',
          status: 'planned',
          retain_days: retainDays,
          segment_count: eligible.length,
          segment_checkpoints_sha256: computeHash(eligible),
          through_sequence: eligible.at(-1).last_sequence,
          through_hash: eligible.at(-1).end_hash,
        },
        { io: fs, maxSegmentBytes: 50 * 1024 * 1024, now },
      );
      for (const segment of eligible) segment.pruned_at = timestamp;
      state.revision++;
      commitState(dir, state);
    }
    const deleted = [];
    const kept = state.legacy_files.map((e) => e.name);
    for (const segment of state.segments) {
      if (!segment.pruned_at) {
        kept.push(segment.name);
        continue;
      }
      if (!fs.existsSync(join(dir, segment.name))) continue;
      try {
        if (digest(regularBytes(join(dir, segment.name))) !== segment.sha256)
          throw new AuditLedgerError('Retired audit checkpoint mismatch');
        fs.unlinkSync(join(dir, segment.name));
        deleted.push(segment.name);
      } catch {
        kept.push(segment.name);
      }
    }
    syncDirectory(dir, fs);
    return {
      deleted,
      kept,
      legacy_preserved: state.legacy_files.length,
      verification_scope: 'retained-events-with-local-retention-checkpoints',
    };
  });
}
