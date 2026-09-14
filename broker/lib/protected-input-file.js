import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
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
    readFileImpl = readFileSync,
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
  const pathStat = lstatImpl(filePath);
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    !pathStat.isFile() ||
    pathStat.isSymbolicLink() ||
    !sameCanonicalPath(realpathImpl(parent), parent, platform) ||
    !sameCanonicalPath(realpathImpl(filePath), filePath, platform)
  ) {
    throw new Error(`${label} file boundary is unsafe`);
  }

  if (
    platform !== 'win32' &&
    (!Number.isSafeInteger(effectiveUid) ||
      !trustedOwner(parentStat.uid, effectiveUid) ||
      !trustedOwner(pathStat.uid, effectiveUid) ||
      (parentStat.mode & 0o022) !== 0 ||
      (pathStat.mode & (sensitive ? 0o077 : 0o022)) !== 0)
  ) {
    throw new Error(`${label} file permissions are unsafe`);
  }
  if (pathStat.size < 1 || pathStat.size > maxBytes) {
    throw new Error(`${label} file size is invalid`);
  }

  let descriptor;
  try {
    const flags = constants.O_RDONLY | (platform === 'win32' ? 0 : constants.O_NOFOLLOW);
    descriptor = openImpl(filePath, flags);
    const openedStat = fstatImpl(descriptor);
    if (!openedStat.isFile() || !sameFile(pathStat, openedStat)) {
      throw new Error(`${label} file changed before open`);
    }
    const bytes = readFileImpl(descriptor);
    const finalStat = fstatImpl(descriptor);
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length !== openedStat.size ||
      !sameFile(openedStat, finalStat)
    ) {
      throw new Error(`${label} file changed while reading`);
    }
    return bytes;
  } finally {
    if (descriptor !== undefined) closeImpl(descriptor);
  }
}
