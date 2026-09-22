// broker-test/test-random.js — unbiased cryptographic alphabet sampling

import { readFileSync } from 'node:fs';
import { randomString } from '../broker/lib/random.js';

let passed = 0;
let failed = 0;

function ok(name, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL  ${name}`);
  }
}

console.log('[rejection sampling]');
{
  // For a 62-character alphabet the unbiased cutoff is 248. Bytes 248-255
  // must be rejected rather than folded onto the first eight symbols.
  const alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const source = Buffer.from([248, 255, 0, 61, 62, 123]);
  const value = randomString(alphabet, 4, { randomBytesFn: () => source });
  ok('bytes above cutoff are rejected', value === '0Z0Z');
}
{
  const alphabet = 'ABC';
  const value = randomString(alphabet, 3, {
    randomBytesFn: () => Buffer.from([255, 0, 1, 2]),
  });
  ok('255 is rejected for three-symbol alphabet', value === 'ABC');
}

console.log('\n[validation]');
{
  ok('zero length returns empty string', randomString('AB', 0) === '');
  let duplicateRejected = false;
  try {
    randomString('AAB', 2);
  } catch (error) {
    duplicateRejected = /unique/.test(error.message);
  }
  ok('duplicate alphabet is rejected', duplicateRejected);

  let badLengthRejected = false;
  try {
    randomString('AB', -1);
  } catch (error) {
    badLengthRejected = /length/.test(error.message);
  }
  ok('negative output length is rejected', badLengthRejected);

  let emptySourceRejected = false;
  try {
    randomString('AB', 1, { randomBytesFn: () => Buffer.alloc(0) });
  } catch (error) {
    emptySourceRejected = /no bytes/.test(error.message);
  }
  ok('empty entropy source fails closed', emptySourceRejected);
}

console.log('\n[real entropy source]');
{
  const value = randomString('abcdef0123456789', 128);
  ok('requested length is exact', value.length === 128);
  ok('output contains only alphabet symbols', /^[a-f0-9]+$/.test(value));
}

console.log('\n[consumer wiring]');
{
  const apiKeys = readFileSync(new URL('../broker/api-keys.js', import.meta.url), 'utf8');
  const totp = readFileSync(new URL('../broker/totp.js', import.meta.url), 'utf8');
  ok(
    'API key generation uses shared unbiased sampler',
    apiKeys.includes('randomString(alphabet, len)'),
  );
  ok(
    'recovery-code generation uses shared unbiased sampler',
    totp.includes('randomString(RECOVERY_CODE_ALPHABET, RECOVERY_CODE_LEN)'),
  );
  ok(
    'API key generation no longer applies byte modulo directly',
    !apiKeys.includes('buf[i] % alphabet.length'),
  );
  ok(
    'recovery-code generation no longer applies byte modulo directly',
    !totp.includes('buf[j] % RECOVERY_CODE_ALPHABET.length'),
  );
}

console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
