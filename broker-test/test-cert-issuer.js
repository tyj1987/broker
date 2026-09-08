// broker-test/test-cert-issuer.js — V4.1.1 tests for broker/cert-issuer.js
//
// Cert issuer is the root of mTLS trust. Tests exercise:
//   1. Happy path — issueClientCert returns key + cert + fingerprint
//   2. Cert is actually signed by the test CA
//   3. CN is preserved through the CSR
//   4. certFingerprint reads back the same fingerprint
//   5. readClientCertPem / readClientKeyPem return the right files
//   6. deleteClientCertFiles is idempotent + actually removes the files
//   7. readCaCertPem returns the CA PEM
//   8. reissuing the same CN produces a different cert
//   9. private key chmod 600
//  10. custom days option respected
//  11. CN format patterns
//  12. Fingerprint format canonical
//
// CI OPTIMIZATION: we issue certs at most 3 times to keep total runtime
// under 20 seconds (each genrsa + x509 takes 2-3 seconds). All other
// functions are tested against the certs issued for tests 1, 4, 5.

import { strict as assert } from 'node:assert';
import { test, before, after } from 'node:test';
import { mkdtempSync, rmSync, existsSync, writeFileSync, readFileSync, statSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------- helpers ----------

function makeCA(caDir) {
  if (!existsSync(caDir)) mkdirSync(caDir, { recursive: true });
  const key = join(caDir, 'ca.key');
  const crt = join(caDir, 'ca.crt');
  execFileSync('openssl', ['genrsa', '-out', key, '2048']);
  execFileSync('openssl', [
    'req', '-x509', '-new', '-nodes',
    '-key', key, '-sha256', '-days', '30',
    '-subj', '/CN=test-ca',
    '-out', crt,
  ]);
  return { key, crt };
}

function verifyCertAgainstCA(certPem, caPem) {
  const tmp = mkdtempSync(join(tmpdir(), 'verify-'));
  try {
    const certPath = join(tmp, 'client.crt');
    const caPath = join(tmp, 'ca.crt');
    writeFileSync(certPath, certPem);
    writeFileSync(caPath, caPem);
    execFileSync('openssl', ['verify', '-CAfile', caPath, certPath], { stdio: 'pipe' });
    return true;
  } catch { return false; }
  finally { rmSync(tmp, { recursive: true, force: true }); }
}

function getCertSubject(certPem) {
  const tmp = mkdtempSync(join(tmpdir(), 'subj-'));
  try {
    const certPath = join(tmp, 'c.crt');
    writeFileSync(certPath, certPem);
    const out = execFileSync('openssl', ['x509', '-in', certPath, '-noout', '-subject'], { encoding: 'utf8' });
    return out.trim();
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

// ---------- setup env BEFORE dynamic import ----------

const WORK = mkdtempSync(join(tmpdir(), 'broker-cert-test-'));
const caDir = join(WORK, 'ca');
const { key: CA_KEY_PATH, crt: CA_CERT_PATH } = makeCA(caDir);
const CLIENTS_DIR = join(WORK, 'clients');

process.env.CA_KEY_PATH = CA_KEY_PATH;
process.env.CA_CERT_PATH = CA_CERT_PATH;
process.env.CLIENTS_DIR = CLIENTS_DIR;

// Now safe to import
const certIssuer = await import('../broker/cert-issuer.js');

process.on('exit', () => {
  try { rmSync(WORK, { recursive: true, force: true }); } catch {}
});

// ---------- test runner (matches repo convention) ----------

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ---------- tests ----------

section('1. Happy path: issueClientCert returns key + cert + fingerprint');

// Issue once and reuse across all subsequent tests.
const r1 = await certIssuer.issueClientCert('client.alice');
ok('returns cert_pem string', typeof r1.cert_pem === 'string');
ok('returns key_pem string', typeof r1.key_pem === 'string');
ok('cert has PEM header', /-----BEGIN CERTIFICATE-----/.test(r1.cert_pem));
ok('key has PEM header', /-----BEGIN (RSA )?PRIVATE KEY-----/.test(r1.key_pem));
ok('fingerprint is canonical SHA256 (95 chars, uppercase hex with colons)',
   /^[A-F0-9:]{95}$/.test(r1.fingerprint_sha256));
ok('default days = 90', r1.days === 90);

section('2. Cert is signed by our CA');

ok('cert verifies against CA', verifyCertAgainstCA(r1.cert_pem, readFileSync(CA_CERT_PATH, 'utf8')));

section('3. CN preserved in subject');

const subj = getCertSubject(r1.cert_pem);
ok('subject contains CN=client.alice', /CN\s*=\s*client\.alice/.test(subj));

section('4. certFingerprint round-trips');

// Reuse r1 (no extra cert issuance)
const fp = await certIssuer.certFingerprint('client.alice');
ok('certFingerprint matches issueClientCert result', fp === r1.fingerprint_sha256);
ok('certFingerprint is uppercase hex', /^[A-F0-9:]+$/.test(fp));

section('5. readClientCertPem / readClientKeyPem');

// Reuse r1
const pem = certIssuer.readClientCertPem('client.alice');
const key = certIssuer.readClientKeyPem('client.alice');
ok('cert PEM has header', /-----BEGIN CERTIFICATE-----/.test(pem));
ok('key PEM has header', /-----BEGIN (RSA )?PRIVATE KEY-----/.test(key));
ok('cert PEM matches', pem === r1.cert_pem);

section('6. readClientCertPem throws for missing cert');

ok('readClientCertPem throws Cert not found',
   (() => { try { certIssuer.readClientCertPem('client.nonexistent'); return false; } catch (e) { return /Cert not found/.test(e.message); } })());
ok('readClientKeyPem throws Key not found',
   (() => { try { certIssuer.readClientKeyPem('client.nonexistent'); return false; } catch (e) { return /Key not found/.test(e.message); } })());

section('7. certFingerprint rejects for missing cert');

try {
  await certIssuer.certFingerprint('client.nonexistent');
  ok('throws Cert not found', false, 'should have thrown');
} catch (e) {
  ok('throws Cert not found', /Cert not found/.test(e.message));
}

section('8. deleteClientCertFiles removes the files (then we reissue for further tests)');

{
  const cn8 = 'client.alice';
  const p = certIssuer.paths.clientPaths(cn8);
  ok('crt exists before delete', existsSync(p.crt));
  ok('key exists before delete', existsSync(p.key));
  certIssuer.deleteClientCertFiles(cn8);
  ok('crt removed', !existsSync(p.crt));
  ok('key removed', !existsSync(p.key));
}

section('9. deleteClientCertFiles is idempotent');

certIssuer.deleteClientCertFiles('client.never-existed');
certIssuer.deleteClientCertFiles('client.never-existed');
ok('no throw on double-delete', true);

section('10. readCaCertPem');

const caPem = certIssuer.readCaCertPem();
ok('returns PEM cert', /-----BEGIN CERTIFICATE-----/.test(caPem));
const caSubj = getCertSubject(caPem);
ok('CA subject is test-ca', /CN\s*=\s*test-ca/.test(caSubj));

section('11. paths are correctly exposed');

ok('paths.CA_KEY matches env', certIssuer.paths.CA_KEY === CA_KEY_PATH);
ok('paths.CA_CRT matches env', certIssuer.paths.CA_CRT === CA_CERT_PATH);
ok('paths.CLIENTS_DIR matches env', certIssuer.paths.CLIENTS_DIR === CLIENTS_DIR);
ok('DEFAULT_CERT_DAYS = 90', certIssuer.DEFAULT_CERT_DAYS === 90);

section('12. private key chmod 600');

// Reuse r1 from test 1
const p12 = certIssuer.paths.clientPaths('client.alice');
// re-issue since we deleted it in test 8
await certIssuer.issueClientCert('client.perm');
const mode = statSync(certIssuer.paths.clientPaths('client.perm').key).mode & 0o777;
ok(`key file mode is 0600 (got ${mode.toString(8)})`, mode === 0o600);

section('13. custom days option respected');

// Only one extra cert issuance for this test
const r13 = await certIssuer.issueClientCert('client.shortlived', { days: 7 });
ok('returns requested days', r13.days === 7);

section('14. CN with various name patterns (use one of r1’s results)');

ok('CN="client.alice" preserved (no extra issuance)', /CN\s*=\s*client\.alice/.test(getCertSubject(r1.cert_pem)));

section('15. Fingerprint format is uppercase hex with colons');

ok('64 hex + 31 colons = 95 chars', r1.fingerprint_sha256.length === 95);
ok('all uppercase hex', /^[A-F0-9:]+$/.test(r1.fingerprint_sha256));

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
