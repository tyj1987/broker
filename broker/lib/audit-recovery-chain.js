import { constants, opendirSync, lstatSync, realpathSync, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { isAbsolute, normalize, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { computeHash, GENESIS_HASH } from './audit-hash-chain.js';

export const AUDIT_RECOVERY_CHAIN_LIMITS = Object.freeze({ maxFiles: 512, maxDirectoryEntries: 4096,
  maxBytes: 64 * 1024 * 1024, maxFileBytes: 8 * 1024 * 1024, maxLineBytes: 256 * 1024,
  maxEvents: 100_000, deadlineMs: 60_000 });
const fail = () => { throw new Error('Recovery chain snapshot is unavailable'); };
function sameFile(left, right) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'mode', 'nlink'].every(key => left[key] === right[key]);
}
function canonicalPath(path) {
  const resolved = realpathSync.native(path);
  return process.platform === 'win32' ? resolved.toLowerCase() === path.toLowerCase() : resolved === path;
}

/**
 * Take one bounded, no-link, stable-file snapshot. Only hashes and historical
 * file counts survive parsing; repeated anchor proofs do not reread logs.
 * A recovery copy must be quiescent. This is not an atomic filesystem snapshot.
 */
export function readAuditRecoveryChainSnapshot(path, { signal, ...overrides } = {}) {
  const limits = { ...AUDIT_RECOVERY_CHAIN_LIMITS, ...overrides };
  if (typeof path !== 'string' || !isAbsolute(path) || normalize(path) !== path
    || (signal !== undefined && !(signal instanceof AbortSignal))
    || Object.keys(overrides).some(key => !Object.hasOwn(AUDIT_RECOVERY_CHAIN_LIMITS, key))
    || Object.entries(limits).some(([key, n]) => !Number.isSafeInteger(n) || n < 1 || n > AUDIT_RECOVERY_CHAIN_LIMITS[key])) fail();
  const end = performance.now() + limits.deadlineMs;
  const check = () => { if (signal?.aborted || performance.now() >= end) fail(); };
  let directory;
  try {
    check();
    const initial = lstatSync(path);
    if (!initial.isDirectory() || initial.isSymbolicLink() || !canonicalPath(path)) fail();
    directory = opendirSync(path);
    const names = [];
    let entries = 0;
    for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {
      check();
      if (++entries > limits.maxDirectoryEntries) fail();
      if (entry.name.startsWith('audit-chain-') && entry.name.endsWith('.jsonl')) {
        if (!entry.isFile() || entry.isSymbolicLink() || names.length >= limits.maxFiles) fail();
        names.push(entry.name);
      }
    }
    directory.closeSync(); directory = undefined;
    names.sort();
    const retained = [];
    const hashes = [GENESIS_HASH];
    const fileCounts = [0];
    let total = 0;
    for (const [index, name] of names.entries()) {
      check();
      const file = join(path, name);
      let fd;
      try {
        fd = openSync(file, constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW | constants.O_NONBLOCK));
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.nlink !== 1 || !canonicalPath(file)
          || stat.size > limits.maxFileBytes || total + stat.size > limits.maxBytes) fail();
        const bytes = Buffer.alloc(stat.size + 1);
        let size = 0;
        while (size < bytes.length) {
          check();
          const count = readSync(fd, bytes, size, bytes.length - size, size);
          if (!count) break;
          size += count;
        }
        if (size !== stat.size || !sameFile(stat, fstatSync(fd)) || !sameFile(stat, lstatSync(file))) fail();
        total += size;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size));
        for (const line of text.split('\n')) {
          check();
          if (!line) continue;
          if (hashes.length > limits.maxEvents || Buffer.byteLength(line) > limits.maxLineBytes) fail();
          const event = JSON.parse(line);
          if (!event || typeof event !== 'object' || Array.isArray(event)) fail();
          const { hash, ...body } = event;
          if (body.prev_hash !== hashes.at(-1) || hash !== computeHash(body)) fail();
          hashes.push(hash); fileCounts.push(index + 1);
        }
        retained.push({ file, stat });
      } finally { if (fd !== undefined) closeSync(fd); }
    }
    // Include files read earlier and the directory itself in the final check.
    for (const { file, stat } of retained) {
      check();
      if (!sameFile(stat, lstatSync(file)) || !canonicalPath(file)) fail();
    }
    if (!sameFile(initial, lstatSync(path)) || !canonicalPath(path)) fail();
    check();
    return (eventCount) => {
      if (!Number.isSafeInteger(eventCount) || eventCount < 0 || eventCount >= hashes.length) fail();
      return Object.freeze({ files: names.length, count: hashes.length - 1, lastHash: hashes.at(-1),
        anchoredEventCount: eventCount, hashAtAnchor: hashes[eventCount], filesAtAnchor: fileCounts[eventCount] });
    };
  } catch { fail(); }
  finally { if (directory !== undefined) { try { directory.closeSync(); } catch { /* already failed */ } } }
}
