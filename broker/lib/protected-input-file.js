import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { dirname, isAbsolute, normalize } from 'node:path';

function sameFile(left, right) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'mode', 'uid', 'gid'].every(
    (field) => left?.[field] === right?.[field],
  );
}

function sameCanonicalPath(left, right, platform) {
  const normalizedLeft = normalize(left);
  const normalizedRight = normalize(right);
  return platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function trustedOwner(uid, effectiveUid) {
  return Number.isSafeInteger(uid) && (uid === 0 || uid === effectiveUid);
}

/**
 * Read a bounded operator input without following links or accepting a file
 * that changes between validation and use. POSIX credential inputs must be
 * owner-only; public certificate inputs may be readable but never writable by
 * group or other users. Windows ACLs remain an operator boundary, while the
 * same reparse-point and stable-file checks still apply.
 */
export function readProtectedInputFile(
  filePath,
  label,
  maxBytes,
  {
    sensitive = false,
    platform = process.platform,
    effectiveUid = typeof process.getuid === 'function' ? process.getuid() : null,
    lstatImpl = lstatSync,
    realpathImpl = realpathSync.native,
    openImpl = openSync,
    fstatImpl = fstatSync,
    readImpl = readSync,
    closeImpl = closeSync,
  } = {},
) {
  if (
    typeof filePath !== 'string' ||
    !isAbsolute(filePath) ||
    typeof label !== 'string' ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 1
  ) {
    throw new Error(`${label || 'Input'} path is invalid`);
  }

  const parent = dirname(filePath);
  const parentStat = lstatImpl(parent);
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    !sameCanonicalPath(realpathImpl(parent), parent, platform)
  ) {
    throw new Error(`${label} file boundary is unsafe`);
  }

  if (
    platform !== 'win32' &&
    (!Number.isSafeInteger(effectiveUid) ||
      !trustedOwner(parentStat.uid, effectiveUid) ||
      (parentStat.mode & 0o022) !== 0)
  ) {
    throw new Error(`${label} file permissions are unsafe`);
  }

  let descriptor;
  try {
    const flags = constants.O_RDONLY | (platform === 'win32' ? 0 : constants.O_NOFOLLOW);
    descriptor = openImpl(filePath, flags);
    const openedStat = fstatImpl(descriptor);
    if (!openedStat.isFile()
      || !sameCanonicalPath(realpathImpl(filePath), filePath, platform)) {
      throw new Error(`${label} file boundary is unsafe`);
    }
    if (platform !== 'win32'
      && (!trustedOwner(openedStat.uid, effectiveUid)
        || (openedStat.mode & (sensitive ? 0o077 : 0o022)) !== 0)) {
      throw new Error(`${label} file permissions are unsafe`);
    }
    if (openedStat.size < 1 || openedStat.size > maxBytes) {
      throw new Error(`${label} file size is invalid`);
    }
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readImpl(descriptor, buffer, length, buffer.length - length, length);
      if (!Number.isSafeInteger(count) || count < 0 || count > buffer.length - length) {
        throw new Error(`${label} file read is invalid`);
      }
      if (count === 0) break;
      length += count;
    }
    const finalStat = fstatImpl(descriptor);
    if (
      length !== openedStat.size ||
      !sameFile(openedStat, finalStat)
    ) {
      throw new Error(`${label} file changed while reading`);
    }
    return buffer.subarray(0, length);
  } finally {
    if (descriptor !== undefined) closeImpl(descriptor);
  }
}
