// broker-test/test-auth-flow.js — MFA pending state and recovery-code transactions

import {
  createMfaPending,
  getMfaPending,
  consumeMfaPending,
  verifyMfaCode,
  verifyStepUp,
  mfaClientBinding,
  restoreConsumedRecoveryCode,
  isMfaRequired,
  MAX_MFA_PENDING,
  _resetMfaPendingForTests,
} from '../broker/auth-flow.js';
import { computeCode, generateSecret, hashPassword, hashRecoveryCode } from '../broker/totp.js';
import { createMutationGate } from '../broker/lib/mutation-gate.js';
import { validateBrokerConfig } from '../broker/lib/config-validate.js';
import {
  createPendingTotp,
  isPendingTotpExpired,
  TOTP_SETUP_TTL_MS,
} from '../broker/lib/totp-pending.js';

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

console.log('[MFA pending token lifecycle]');
{
  const token = createMfaPending('client.alice', 'AA:BB');
  const pending = getMfaPending(token);
  ok('pending token resolves once', pending?.clientName === 'client.alice');
  ok('pending token preserves certificate fingerprint', pending?.fp === 'AA:BB');
  ok('consume succeeds', consumeMfaPending(token) === true);
  ok('consumed token cannot be read', getMfaPending(token) === null);
  ok('consumed token cannot be consumed twice', consumeMfaPending(token) === false);
  ok('missing token is rejected', getMfaPending('') === null);
}

console.log('\n[bounded MFA pending pool]');
{
  _resetMfaPendingForTests();
  const first = createMfaPending('first', '', { maxEntries: 2 });
  const second = createMfaPending('second', '', { maxEntries: 2 });
  const third = createMfaPending('third', '', { maxEntries: 2 });
  ok('default pending capacity is bounded', MAX_MFA_PENDING === 10_000);
  ok('oldest pending challenge is evicted at capacity', getMfaPending(first) === null);
  ok('second challenge remains', getMfaPending(second)?.clientName === 'second');
  ok('new challenge is admitted', getMfaPending(third)?.clientName === 'third');
  _resetMfaPendingForTests();
}

console.log('\n[recovery-code consumption and rollback]');
{
  const codes = ['AAAA-BBBB', 'CCCC-DDDD', 'EEEE-FFFF'];
  const originalHashes = codes.map(hashRecoveryCode);
  const client = { totp_recovery_codes_hash: [...originalHashes] };
  const verification = verifyMfaCode(client, 'ccccdddd');

  ok('matching recovery code succeeds', verification.ok === true);
  ok('method is recovery', verification.method === 'recovery');
  ok('used recovery hash is removed immediately', client.totp_recovery_codes_hash.length === 2);
  ok(
    'unrelated recovery hashes keep their order',
    client.totp_recovery_codes_hash[0] === originalHashes[0] &&
      client.totp_recovery_codes_hash[1] === originalHashes[2],
  );
  ok(
    'transaction metadata identifies removed hash and index',
    verification._recovery_index === 1 && verification._recovery_hash === originalHashes[1],
  );

  ok('rollback reports restoration', restoreConsumedRecoveryCode(client, verification) === true);
  ok(
    'rollback restores exact original order',
    JSON.stringify(client.totp_recovery_codes_hash) === JSON.stringify(originalHashes),
  );
  ok('rollback clears internal hash metadata', !('_recovery_hash' in verification));
  ok('rollback clears internal index metadata', !('_recovery_index' in verification));
  ok('second rollback is a no-op', restoreConsumedRecoveryCode(client, verification) === false);

  const invalidBefore = [...client.totp_recovery_codes_hash];
  ok('invalid recovery code is denied', verifyMfaCode(client, 'ZZZZ-ZZZZ').ok === false);
  ok(
    'invalid recovery code does not mutate list',
    JSON.stringify(client.totp_recovery_codes_hash) === JSON.stringify(invalidBefore),
  );
}

console.log('\n[TOTP verification does not enter recovery transaction]');
{
  const secret = generateSecret();
  const code = computeCode(secret);
  const client = {
    totp_secret: secret,
    totp_recovery_codes_hash: [hashRecoveryCode('ABCD-EFGH')],
  };
  const before = [...client.totp_recovery_codes_hash];
  const verification = verifyMfaCode(client, code);
  ok('current TOTP code succeeds', verification.ok === true && verification.method === 'totp');
  ok(
    'TOTP leaves recovery codes untouched',
    JSON.stringify(client.totp_recovery_codes_hash) === JSON.stringify(before),
  );
  ok(
    'TOTP result cannot be recovery-restored',
    restoreConsumedRecoveryCode(client, verification) === false,
  );
}

console.log('\n[unified step-up verification]');
{
  const secret = generateSecret();
  const totpCode = computeCode(secret);
  const client = {
    totp_secret: secret,
    totp_recovery_codes_hash: [hashRecoveryCode('ABCD-EFGH')],
    password: hashPassword('correct horse battery staple'),
  };
  ok('step-up accepts current TOTP', verifyStepUp(client, totpCode).method === 'totp');
  const recovery = verifyStepUp(client, 'ABCD-EFGH');
  ok('step-up accepts recovery code', recovery.method === 'recovery');
  ok(
    'step-up recovery code is consumed transactionally',
    client.totp_recovery_codes_hash.length === 0,
  );
  restoreConsumedRecoveryCode(client, recovery);
  ok(
    'step-up recovery code can be restored on persistence failure',
    client.totp_recovery_codes_hash.length === 1,
  );
  ok(
    'MFA-enabled step-up rejects first-factor password alone',
    verifyStepUp(client, 'correct horse battery staple').ok === false,
  );
  ok(
    'password fallback can be disabled',
    verifyStepUp(client, 'correct horse battery staple', { allowPassword: false }).ok === false,
  );
  ok(
    'non-MFA client can still step up using password',
    verifyStepUp({ password: client.password }, 'correct horse battery staple').method ===
      'password',
  );
  ok(
    'first-factor binding changes after password change',
    mfaClientBinding(client) !== mfaClientBinding({ ...client, password: 'changed' }),
  );
  ok(
    'first-factor binding changes after certificate change',
    mfaClientBinding(client) !==
      mfaClientBinding({ ...client, cert_fingerprint_sha256: 'changed' }),
  );
  ok('invalid step-up credential is denied', verifyStepUp(client, 'invalid-value').ok === false);
  ok('missing client is denied', verifyStepUp(null, totpCode).ok === false);
}

console.log('\n[ephemeral TOTP enrollment state]');
{
  const hashes = [hashRecoveryCode('AAAA-BBBB'), hashRecoveryCode('CCCC-DDDD')];
  const pending = createPendingTotp('BASE32SECRET', hashes, { now: 1_000, ttlMs: 5_000 });
  ok('pending enrollment stores secret', pending.secret === 'BASE32SECRET');
  ok('pending enrollment copies recovery hashes', pending.recovery_hashes !== hashes);
  ok('pending enrollment stores no plaintext recovery codes', !('recovery_codes_plain' in pending));
  ok('pending enrollment is valid before expiry', !isPendingTotpExpired(pending, { now: 5_999 }));
  ok('pending enrollment expires at boundary', isPendingTotpExpired(pending, { now: 6_000 }));
  ok('default setup TTL is ten minutes', TOTP_SETUP_TTL_MS === 10 * 60 * 1000);

  const legacy = { setup_at: new Date(10_000).toISOString() };
  ok(
    'legacy pending state uses setup_at fallback',
    !isPendingTotpExpired(legacy, { now: 10_001, ttlMs: 5_000 }),
  );
  ok(
    'legacy pending state expires with fallback TTL',
    isPendingTotpExpired(legacy, { now: 15_000, ttlMs: 5_000 }),
  );
  ok('invalid pending state fails closed', isPendingTotpExpired({ setup_at: 'bad' }));
}

console.log('\n[MFA requirement policy compatibility]');
{
  ok('TOTP-enabled password client requires MFA', isMfaRequired({ totp_secret: 'x' }, 'password'));
  ok(
    'explicit mfa_required=false overrides TOTP',
    !isMfaRequired({ totp_secret: 'x', mfa_required: false }, 'password'),
  );
  ok('mTLS CI client without TOTP is exempt', !isMfaRequired({ role: 'ci' }, 'mtls'));
  ok('null client is exempt', !isMfaRequired(null, 'password'));
}

console.log('\n[configuration transaction ordering]');
{
  const gate = createMutationGate();
  const seen = [];
  const one = gate
    .run(async () => {
      seen.push('start');
      await new Promise((r) => setTimeout(r, 10));
      seen.push('rollback');
      throw new Error('injected');
    })
    .catch(() => {});
  const two = gate.run(async () => {
    seen.push('next');
  });
  await Promise.all([one, two]);
  await gate.idle();
  ok(
    'next mutation starts only after previous rollback and failure releases gate',
    seen.join(',') === 'start,rollback,next' && gate.pending === 0,
  );
}
console.log('\n[dedicated proxy configuration]');
{
  const fp = Array(32).fill('AA').join(':');
  const base = { clients: { admin: { role: 'admin' } }, services: {} };
  ok(
    'explicit exact proxy binding accepted',
    validateBrokerConfig({
      ...base,
      trusted_proxies: [{ addresses: ['172.30.0.2'], cert_fingerprint_sha256: fp }],
    }).ok,
  );
  ok(
    'CIDR trust rejected',
    !validateBrokerConfig({
      ...base,
      trusted_proxies: [{ addresses: ['172.30.0.0/16'], cert_fingerprint_sha256: fp }],
    }).ok,
  );
  ok(
    'shared transport and business certificate rejected',
    !validateBrokerConfig({
      ...base,
      clients: { admin: { role: 'admin', cert_fingerprint_sha256: fp } },
      trusted_proxies: [{ addresses: ['127.0.0.1'], cert_fingerprint_sha256: fp }],
    }).ok,
  );
}
console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
