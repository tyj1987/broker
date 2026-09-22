// Uniform random strings over arbitrary byte-sized alphabets.
// Rejection sampling avoids the modulo bias from `byte % alphabet.length`.

import { randomBytes } from 'node:crypto';

export function randomString(alphabet, length, opts = {}) {
  if (typeof alphabet !== 'string' || alphabet.length < 2 || alphabet.length > 256) {
    throw new TypeError('alphabet length must be between 2 and 256');
  }
  if (new Set(alphabet).size !== alphabet.length) {
    throw new TypeError('alphabet characters must be unique');
  }
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError('length must be a non-negative safe integer');
  }
  if (length === 0) return '';

  const randomBytesFn = opts.randomBytesFn || randomBytes;
  const cutoff = 256 - (256 % alphabet.length);
  let output = '';

  while (output.length < length) {
    const remaining = length - output.length;
    // Slightly over-request to offset rejected bytes while keeping allocations bounded.
    const batchSize = Math.max(16, Math.ceil((remaining * 256) / cutoff));
    const bytes = randomBytesFn(batchSize);
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
      throw new TypeError('randomBytesFn must return bytes');
    }
    if (bytes.length === 0) throw new Error('randomBytesFn returned no bytes');

    for (const byte of bytes) {
      if (byte >= cutoff) continue;
      output += alphabet[byte % alphabet.length];
      if (output.length === length) break;
    }
  }
  return output;
}
