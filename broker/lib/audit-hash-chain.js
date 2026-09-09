// broker/lib/audit-hash-chain.js — V4.1.1 tamper-evident audit log.
//
// Each audit event includes `prev_hash` (the hash of the previous event)
// and `hash` (SHA-256 of this event). The chain is verifiable by walking
// from the most recent event back to genesis; any modification to a past
// event invalidates all subsequent hashes.
//
// Format:
//   {
//     ...eventFields,
//     prev_hash: "abc...",  // hex SHA-256 of previous event's canonical JSON (or '0'*64 for genesis)
//     hash:      "def...",  // hex SHA-256 of canonical JSON of this event WITHOUT hash field
//   }
//
// Verification walks backward: for each event e[i], check that e[i].hash ==
// sha256(canonicalize({...e[i], hash: undefined})). Also check that
// e[i].prev_hash == e[i-1].hash.

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const GENESIS_HASH = '0'.repeat(64);
export { GENESIS_HASH };

function canonicalize(obj) {
  // Stable JSON: sorted keys, no whitespace.
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

export function computeHash(eventWithoutHash) {
  return createHash('sha256').update(canonicalize(eventWithoutHash)).digest('hex');
}

/**
 * Wrap a base audit event with prev_hash + hash fields.
 * @param {object} event
 * @param {string} prevHash  - previous event's hash (or GENESIS)
 * @returns {object} event with { prev_hash, hash }
 */
export function sealEvent(event, prevHash) {
  const withPrev = { ...event, prev_hash: prevHash || GENESIS_HASH };
  // hash is computed over the event WITHOUT the hash field
  const hash = computeHash(withPrev);
  return { ...withPrev, hash };
}

/**
 * Verify the chain integrity of an array of events.
 * Returns { ok: boolean, broken_at?: number, reason?: string }.
 * Events should be in chronological order (oldest first).
 */
export function verifyChain(events) {
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (e.prev_hash !== prevHash) {
      return { ok: false, broken_at: i, reason: `prev_hash mismatch at index ${i}: expected ${prevHash.slice(0, 12)}, got ${e.prev_hash?.slice(0, 12)}` };
    }
    // Recompute hash from event WITHOUT hash field
    const { hash: stored, ...rest } = e;
    const computed = computeHash(rest);
    if (computed !== stored) {
      return { ok: false, broken_at: i, reason: `hash mismatch at index ${i}: expected ${computed.slice(0, 12)}, got ${stored?.slice(0, 12)}` };
    }
    prevHash = stored;
  }
  return { ok: true, count: events.length };
}

function chainFiles(auditDir, chainOnly = false) {
  const files = readdirSync(auditDir)
    .filter(f => f.startsWith('audit-chain-') && f.endsWith('.jsonl'))
    .sort();
  if (files.length > 0 || chainOnly) return files;
  return readdirSync(auditDir)
    .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
    .sort();
}

function parseLines(content, file) {
  const events = [];
  for (const [index, line] of content.split('\n').entries()) {
    if (!line) continue;
    try { events.push(JSON.parse(line)); } catch {
      throw new Error(`invalid audit JSON in ${file} at line ${index + 1}`);
    }
  }
  return events;
}

export function loadAuditChainStateSync(auditDir, { chainOnly = false } = {}) {
  const files = chainFiles(auditDir, chainOnly);
  const events = files.flatMap(file => parseLines(readFileSync(join(auditDir, file), 'utf8'), file));
  const result = verifyChain(events);
  if (!result.ok) throw new Error(`audit chain verification failed: ${result.reason}`);
  return {
    files: files.length,
    count: events.length,
    lastHash: events.length > 0 ? events.at(-1).hash : GENESIS_HASH,
  };
}

/**
 * Read all audit files in a directory and verify the chain.
 * @param {string} auditDir
 * @returns {Promise<{ ok: boolean, count: number, broken_at?: number, reason?: string, files: number }>}
 */
export async function verifyAuditDir(auditDir) {
  const files = chainFiles(auditDir);
  const all = [];
  for (const f of files) {
    const content = await readFile(join(auditDir, f), 'utf8');
    all.push(...parseLines(content, f));
  }
  const result = verifyChain(all);
  return { ...result, files: files.length };
}

/**
 * Build a chainable audit writer that holds the prev_hash in memory.
 * Returns a function `write(event)` that seals and emits.
 */
export function createChainWriter(opts = {}) {
  const onEvent = opts.onEvent || (() => {});
  let prevHash = GENESIS_HASH;
  let count = 0;
  return {
    write(event) {
      const sealed = sealEvent(event, prevHash);
      prevHash = sealed.hash;
      count++;
      onEvent(sealed);
      return sealed;
    },
    get prevHash() { return prevHash; },
    get count() { return count; },
  };
}
