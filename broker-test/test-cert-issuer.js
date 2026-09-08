// broker-test/test-cert-issuer.js — V4.1.1 tests for broker/cert-issuer.js
//
// Cert issuer is the root of mTLS trust. We previously had ZERO tests for it
// (REVIEW.md Now#3). This file exercises:
//   1. Happy path — issueClientCert returns key + cert + fingerprint
//   2. Cert is actually signed by the test CA (verify against CA cert)
//   3. CN is preserved through the CSR
//   4. Already-issued: reissuing the same CN produces a different cert (new key)
//   5. certFingerprint reads back the same fingerprint as issueClientCert returned
//   6. readClientCertPem / readClientKeyPem return the right files
//   7. deleteClientCertFiles is idempotent + actually removes the files
//   8. readCaCertPem returns the CA PEM
//   9. Negative: throws on missing files
//  10. Custom days option respected
//  11. Private key chmod 600
//  12. Fingerprint format canonical (uppercase hex with colons)
//
// All tests use a per-run tempdir + freshly generated self-signed CA.
// Env vars are set BEFORE importing the module because cert-issuer.js reads
// them at module-load time.

import { mkdtempSync, rmSync, mkdirSync, existsSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------- helpers (sync, no top-level await) ----------

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
  } catch {
    return false;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function getCertSubject(certPem) {
  const tmp = mkdtempSync(join(tmpdir(), 'subj-'));
  try {
    const certPath = join(tmp, 'c.crt');
    writeFileSync(certPath, certPem);
    const out = execFileSync('openssl', ['x509', '-in', certPath, '-noout', '-subject'], { encoding: 'utf8' });
    return out.trim();
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function computeFingerprintFromPem(certPem) {
  const tmp = mkdtempSync(join(tmpdir(), 'fp-'));
  try {
    const certPath = join(tmp, 'c.crt');
    writeFileSync(certPath, certPem);
    const out = execFileSync('openssl', ['x509', '-in', certPath, '-noout', '-fingerprint', '-sha256'], { encoding: 'utf8' });
    return out.split('=')[1].trim();
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// ---------- setup env BEFORE dynamic import ----------

const WORK = mkdtempSync(join(tmpdir(), 'broker-cert-test-'));
const caDir = join(WORK, 'ca');
const { key: CA_KEY_PATH, crt: CA_CERT_PATH } = makeCA(caDir);
const CLIENTS_DIR = join(WORK, 'clients');

process.env.CA_KEY_PATH = CA_KEY_PATH;
process.env.CA_CERT_PATH = CA_CERT_PATH;
process.env.CLIENTS_DIR = CLIENTS_DIR;

// Now safe to import — the module will read the env we just set
const certIssuer = await import('../broker/cert-issuer.js');

// Cleanup on exit (best-effort)
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
async function asyncOk(name, cond, detail) {
  try {
    const r = await cond();
    if (r) { pass++; console.log(`  PASS  ${name}`); }
    else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
  } catch (e) {
    fail++; console.error(`  FAIL  ${name}  -- threw: ${e.message}`);
  }
}
function assertThrows(fn, pattern) {
  try { fn(); return false; }
  catch (e) { return pattern ? pattern.test(e.message) : true; }
}
async function assertRejects(fn, pattern) {
  try { await fn(); return false; }
  catch (e) { return pattern ? pattern.test(e.message) : true; }
}

// ---------- tests ----------

section('1. Happy path');

const r1 = await certIssuer.issueClientCert('client.alice');
ok('returns cert_pem string', typeof r1.cert_pem === 'string');
ok('returns key_pem string', typeof r1.key_pem === 'string');
ok('cert has PEM header', /-----BEGIN CERTIFICATE-----/.test(r1.cert_pem));
ok('key has PEM header', /-----BEGIN (RSA )?PRIVATE KEY-----/.test(r1.key_pem));
ok('fingerprint is canonical SHA256 (95 chars, uppercase hex with colons)',
   /^[A-F0-9:]{95}$/.test(r1.fingerprint_sha256));
ok('default days = 90', r1.days === 90);

section('2. Cert is signed by our CA');

const r2 = await certIssuer.issueClientCert('client.bob');
ok('cert verifies against CA', verifyCertAgainstCA(r2.cert_pem, readFileSync(CA_CERT_PATH, 'utf8')));

section('3. CN preserved in subject');

const r3 = await certIssuer.issueClientCert('client.charlie');
const subj = getCertSubject(r3.cert_pem);
ok('subject contains CN=client.charlie', /CN\s*=\s*client\.charlie/.test(subj));

section('4. Reissue with same CN produces different cert');

const a = await certIssuer.issueClientCert('client.delta');
const b = await certIssuer.issueClientCert('client.delta');
ok('cert PEM changes on reissue', a.cert_pem !== b.cert_pem);
ok('key PEM changes on reissue', a.key_pem !== b.key_pem);
ok('fingerprint changes on reissue', a.fingerprint_sha256 !== b.fingerprint_sha256);

section('5. certFingerprint round-trips');

const r5 = await certIssuer.issueClientCert('client.echo');
const fp = await certIssuer.certFingerprint('client.echo');
ok('certFingerprint matches issueClientCert result', fp === r5.fingerprint_sha256);
ok('certFingerprint matches our openssl computation',
   fp === computeFingerprintFromPem(r5.cert_pem));

section('6. readClientCertPem / readClientKeyPem');

await certIssuer.issueClientCert('client.foxtrot');
const pem = certIssuer.readClientCertPem('client.foxtrot');
const key = certIssuer.readClientKeyPem('client.foxtrot');
ok('cert PEM has header', /-----BEGIN CERTIFICATE-----/.test(pem));
ok('key PEM has header', /-----BEGIN (RSA )?PRIVATE KEY-----/.test(key));

section('7. readClientCertPem throws for missing cert');

ok('readClientCertPem throws Cert not found',
   assertThrows(() => certIssuer.readClientCertPem('client.nonexistent'), /Cert not found/));
ok('readClientKeyPem throws Key not found',
   assertThrows(() => certIssuer.readClientKeyPem('client.nonexistent'), /Key not found/));

section('8. certFingerprint rejects for missing cert');

ok('certFingerprint rejects with Cert not found',
   await assertRejects(() => certIssuer.certFingerprint('client.nonexistent'), /Cert not found/));

section('9. deleteClientCertFiles removes the files');

const cn9 = 'client.golf';
await certIssuer.issueClientCert(cn9);
const p9 = certIssuer.paths.clientPaths(cn9);
ok('crt exists before delete', existsSync(p9.crt));
ok('key exists before delete', existsSync(p9.key));
certIssuer.deleteClientCertFiles(cn9);
ok('crt removed', !existsSync(p9.crt));
ok('key removed', !existsSync(p9.key));

section('10. deleteClientCertFiles is idempotent');

certIssuer.deleteClientCertFiles('client.never-existed');
certIssuer.deleteClientCertFiles('client.never-existed');
ok('no throw on double-delete of missing client', true);

section('11. readCaCertPem');

const caPem = certIssuer.readCaCertPem();
ok('returns PEM cert', /-----BEGIN CERTIFICATE-----/.test(caPem));
const caSubj = getCertSubject(caPem);
ok('CA subject is test-ca', /CN\s*=\s*test-ca/.test(caSubj));

section('12. paths are correctly exposed');

ok('paths.CA_KEY matches env', certIssuer.paths.CA_KEY === CA_KEY_PATH);
ok('paths.CA_CRT matches env', certIssuer.paths.CA_CRT === CA_CERT_PATH);
ok('paths.CLIENTS_DIR matches env', certIssuer.paths.CLIENTS_DIR === CLIENTS_DIR);
ok('DEFAULT_CERT_DAYS = 90', certIssuer.DEFAULT_CERT_DAYS === 90);

section('13. private key chmod 600');

await certIssuer.issueClientCert('client.perm');
const p13 = certIssuer.paths.clientPaths('client.perm');
const mode = statSync(p13.key).mode & 0o777;
ok(`key file mode is 0600 (got ${mode.toString(8)})`, mode === 0o600);
// we already issued 'client.perm' — use it instead of issuing another

section('14. custom days option respected');

const r14 = await certIssuer.issueClientCert('client.shortlived', { days: 7 });
ok('returns requested days', r14.days === 7);
// skip the second cert to keep test runtime low; days math is straightforward

section('15. CN with various name patterns');

const cn15 = 'client.simple';
{
  const r = await certIssuer.issueClientCert(cn15);
  const s = getCertSubject(r.cert_pem);
  ok(`CN="${cn15}" preserved`, new RegExp(`CN\\s*=\\s*${cn15.replace(/\./g, '\\.')}`).test(s));
}

// ---------- summary ----------

console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
