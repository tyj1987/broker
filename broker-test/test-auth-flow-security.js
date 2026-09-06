import {
  createMfaPending, getMfaPending, consumeMfaPending, recordMfaFailure, verifyMfaCode,
  isMfaRequired, _dumpMfaPending,
  isMfaLocked, clearMfaFailures,
} from '../broker/auth-flow.js';
import { hashRecoveryCode, computeCode } from '../broker/totp.js';

let passed = 0;
function ok(name, value) { if (!value) throw new Error(`FAIL: ${name}`); passed++; console.log(`  PASS  ${name}`); }

const token = createMfaPending('client.a', 'AA');
ok('pending transaction is certificate-bound', getMfaPending(token)?.fp === 'AA');
for (let i = 0; i < 4; i++) ok(`failure ${i + 1} recorded`, recordMfaFailure(token));
ok('token remains before maximum', !!getMfaPending(token));
ok('fifth failure recorded', recordMfaFailure(token));
ok('maximum failures invalidates token', getMfaPending(token) === null);
ok('client-wide MFA lock engaged', isMfaLocked('client.a'));
ok('locked client cannot mint fresh MFA token', createMfaPending('client.a') === null);
clearMfaFailures('client.a');
ok('successful flow can clear client lock', !isMfaLocked('client.a') && !!createMfaPending('client.a'));
ok('unknown failure token rejected', !recordMfaFailure('missing'));
ok('invalid failure policy rejected', !recordMfaFailure(createMfaPending('x'), 0));

const oneUse = createMfaPending('client.b');
ok('pending token consumed', consumeMfaPending(oneUse));
ok('consumed token cannot replay', getMfaPending(oneUse) === null && !consumeMfaPending(oneUse));

const hashes = [hashRecoveryCode('ABCD-EFGH')];
const result = verifyMfaCode({ totp_recovery_codes_hash: hashes }, 'ABCD-EFGH');
ok('recovery match returns transaction index', result.ok && result.method === 'recovery' && result.recovery_index === 0);
ok('verification does not mutate recovery state', hashes.length === 1);
ok('invalid recovery code rejected', !verifyMfaCode({ totp_recovery_codes_hash: hashes }, 'ZZZZ-ZZZZ').ok);
ok('missing MFA code rejected', !verifyMfaCode({}, '').ok);
const totpSecret = 'JBSWY3DPEHPK3PXP';
const currentCode = computeCode(totpSecret);
const totpResult = verifyMfaCode({ totp_secret: totpSecret }, currentCode);
ok('current TOTP accepted with counter', totpResult.method === 'totp' && Number.isSafeInteger(totpResult.totp_counter));
ok('same TOTP counter cannot replay', !verifyMfaCode({ totp_secret: totpSecret, totp_last_used_counter: totpResult.totp_counter }, currentCode).ok);
ok('future-stored TOTP counter rejects older code', !verifyMfaCode({ totp_secret: totpSecret, totp_last_used_counter: totpResult.totp_counter + 1 }, currentCode).ok);
ok('malformed stored counter fails closed', !verifyMfaCode({ totp_secret: totpSecret, totp_last_used_counter: 'invalid' }, currentCode).ok);
ok('numeric code without TOTP secret rejected', !verifyMfaCode({}, '123456').ok);
ok('null client has no legacy MFA', !isMfaRequired(null, 'password'));
ok('explicit MFA exemption honored', !isMfaRequired({ mfa_required: false, totp_secret: totpSecret }, 'password'));
ok('configured TOTP requires MFA', isMfaRequired({ totp_secret: totpSecret }, 'password'));
ok('CI mTLS without TOTP is exempt', !isMfaRequired({ role: 'ci' }, 'mtls'));
ok('ordinary client without TOTP has no legacy MFA', !isMfaRequired({ role: 'developer' }, 'password'));
ok('debug dump redacts full token', _dumpMfaPending().every(entry => entry.token.endsWith('...') && entry.token.length < 20));

console.log(`\n${passed} passed, 0 failed`);
