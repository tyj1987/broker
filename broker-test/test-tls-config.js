// broker-test/test-tls-config.js — TLS_CA is required; TLS material is validated at startup.
//
// Coverage:
//   unit (broker/lib/tls-config.js)
//     1. TLS_CA unset / empty → TlsConfigError (no fallback to PKI_DIR/ca/ca.crt)
//     2. TLS_CERT / TLS_KEY default to PKI_DIR/server/*; explicit values win
//     3. missing CA / cert / key file → error naming the variable and path
//     4. unparseable CA / cert / key → error
//     5. key that does not match cert → error
//     6. expired server cert → error
//     7. valid material → buffers + summary (subject, sha256, CRL)
//     8. server/CA cert expiring within 14 days → non-fatal warning; >14 days → none
//     9. not-yet-valid server cert; expired / not-yet-valid CA in TLS_CA bundle → error
//    10. material OpenSSL rejects (truncated cert PEM, malformed / empty CRL) → error
//    11. Dockerfile dev stage does not create an empty crl.pem
//   integration (spawn broker/server.js)
//    12. TLS_CA unset → non-zero exit, clear message, no banner
//    13. TLS_CA points at a missing file → non-zero exit
//    14. valid material → banner shows real checks and server listens
//    15. cert expiring within 14 days → [tls] WARNING logged, server still listens
//    16. truncated cert PEM / malformed CRL / not-yet-valid cert → exit 78 before the banner

import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  resolveTlsPaths, loadTlsMaterials, formatTlsSummary, expiryWarnings, TlsConfigError, EXPIRY_WARN_DAYS,
} from '../broker/lib/tls-config.js';

const OPENSSL_BIN = process.env.OPENSSL_BIN
  || (process.platform === 'win32' && existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
    ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
    : 'openssl');
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SERVER_JS = join(REPO_ROOT, 'broker', 'server.js');

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(t) { console.log(`\n[${t}]`); }
function throwsTls(fn, re) {
  try { fn(); return false; } catch (e) { return e instanceof TlsConfigError && re.test(e.message); }
}

// ---------- fixtures ----------
const dir = mkdtempSync(join(tmpdir(), 'broker-tls-'));
const p = (n) => join(dir, n);
const ossl = (...args) => execFileSync(OPENSSL_BIN, args, { stdio: 'pipe' });
ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
  '-keyout', p('ca.key'), '-out', p('ca.crt'), '-days', '2', '-subj', '/CN=tls-config-test-ca');
ossl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
  '-keyout', p('server.key'), '-out', p('server.csr'), '-subj', '/CN=localhost');
writeFileSync(p('srv.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
ossl('x509', '-req', '-in', p('server.csr'), '-CA', p('ca.crt'), '-CAkey', p('ca.key'),
  '-CAcreateserial', '-out', p('server.crt'), '-days', '2', '-extfile', p('srv.ext'));
ossl('genpkey', '-algorithm', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', p('other.key'));
writeFileSync(p('garbage.pem'), 'not a pem\n');
writeFileSync(p('bad-cert.pem'), '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n');
writeFileSync(p('empty.pem'), '');
writeFileSync(p('malformed-crl.pem'), '-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n');
// Minimal `openssl ca` setup (works on OpenSSL 1.1/3.x, no -not_before needed):
// a real CRL, plus a server cert whose validity starts in the future.
writeFileSync(p('index.txt'), '');
writeFileSync(p('crlnumber'), '01\n');
writeFileSync(p('ca.cnf'), [
  '[ ca ]', 'default_ca = test_ca', '[ test_ca ]',
  `dir = ${dir.replace(/\\/g, '/')}`,
  'database = $dir/index.txt', 'new_certs_dir = $dir', 'serial = $dir/ca.srl', 'crlnumber = $dir/crlnumber',
  'certificate = $dir/ca.crt', 'private_key = $dir/ca.key',
  'default_md = sha256', 'default_days = 2', 'default_crl_days = 2', 'policy = any_policy',
  'unique_subject = no', 'copy_extensions = copy',
  '[ any_policy ]', 'commonName = supplied', '',
].join('\n'));
ossl('ca', '-batch', '-config', p('ca.cnf'), '-gencrl', '-out', p('crl.pem'));
const future = new Date(Date.now() + 5 * 86_400_000);
const asn1Time = (d) => d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'; // YYMMDDHHMMSSZ
ossl('ca', '-batch', '-notext', '-config', p('ca.cnf'), '-in', p('server.csr'), '-out', p('server-future.crt'),
  '-startdate', asn1Time(future), '-enddate', asn1Time(new Date(future.getTime() + 30 * 86_400_000)));
// Truncated PEM: a valid cert followed by a cut-off second block (no END line).
// The PEM regex skips the partial block, but OpenSSL rejects the file.
{
  const pem = readFileSync(p('server.crt'), 'utf8');
  writeFileSync(p('server-truncated.crt'), pem + pem.slice(0, Math.floor(pem.length / 2)));
}
// Long-lived (30-day) CA + server cert: must produce no expiry warning.
ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
  '-keyout', p('ca30.key'), '-out', p('ca30.crt'), '-days', '30', '-subj', '/CN=tls-config-test-ca30');
ossl('x509', '-req', '-in', p('server.csr'), '-CA', p('ca30.crt'), '-CAkey', p('ca30.key'),
  '-CAcreateserial', '-out', p('server30.crt'), '-days', '30', '-extfile', p('srv.ext'));
const good = { ca: p('ca.crt'), cert: p('server.crt'), key: p('server.key'), crl: p('missing-crl.pem') };

// ---------- unit ----------
section('resolveTlsPaths');
ok('TLS_CA unset → error', throwsTls(() => resolveTlsPaths({}, '/pki'), /TLS_CA is not set/));
ok('TLS_CA empty/whitespace → error', throwsTls(() => resolveTlsPaths({ TLS_CA: '  ' }, '/pki'), /TLS_CA is not set/));
ok('PKI_DIR alone never implies a CA', throwsTls(() => resolveTlsPaths({ PKI_DIR: dir }, dir), /no default/));
{
  const r = resolveTlsPaths({ TLS_CA: '/x/ca.crt' }, '/pki');
  ok('cert/key/crl default under PKI_DIR', r.ca === '/x/ca.crt'
    && r.cert === join('/pki', 'server/server.crt') && r.key === join('/pki', 'server/server.key')
    && r.crl === join('/pki', 'ca/crl.pem'));
  const e = resolveTlsPaths({ TLS_CA: '/x/ca.crt', TLS_CERT: '/c', TLS_KEY: '/k', TLS_CRL: '/r' }, '/pki');
  ok('explicit cert/key/crl win', e.cert === '/c' && e.key === '/k' && e.crl === '/r');
}

section('loadTlsMaterials — failures');
ok('missing CA file', throwsTls(() => loadTlsMaterials({ ...good, ca: p('nope.crt') }), /TLS_CA .*nope\.crt.*does not exist/));
ok('missing cert file', throwsTls(() => loadTlsMaterials({ ...good, cert: p('nope.crt') }), /TLS_CERT .*does not exist/));
ok('missing key file', throwsTls(() => loadTlsMaterials({ ...good, key: p('nope.key') }), /TLS_KEY .*does not exist/));
ok('unreadable (EACCES) reported', throwsTls(() => loadTlsMaterials(good, {
  readFileSync: () => { const e = new Error('x'); e.code = 'EACCES'; throw e; },
}), /permission denied/));
ok('other read error reported', throwsTls(() => loadTlsMaterials(good, {
  readFileSync: () => { throw new Error('boom'); },
}), /not readable: boom/));
ok('empty CA file', throwsTls(() => loadTlsMaterials({ ...good, ca: p('empty.pem') }), /TLS_CA .* is empty/));
ok('CA without PEM certificate', throwsTls(() => loadTlsMaterials({ ...good, ca: p('garbage.pem') }), /no PEM certificate/));
ok('CA that fails to parse', throwsTls(() => loadTlsMaterials({ ...good, ca: p('bad-cert.pem') }), /TLS_CA .*failed to parse/));
ok('cert that fails to parse', throwsTls(() => loadTlsMaterials({ ...good, cert: p('bad-cert.pem') }), /TLS_CERT .*failed to parse/));
ok('key that fails to parse', throwsTls(() => loadTlsMaterials({ ...good, key: p('garbage.pem') }), /TLS_KEY .*failed to parse/));
ok('key/cert mismatch', throwsTls(() => loadTlsMaterials({ ...good, key: p('other.key') }), /does not match TLS_CERT/));
ok('expired cert', throwsTls(() => loadTlsMaterials(good, { now: Date.now() + 10 * 86_400_000 }), /expired/));

section('loadTlsMaterials — valid');
{
  const m = loadTlsMaterials(good);
  ok('returns buffers', Buffer.isBuffer(m.cert) && Buffer.isBuffer(m.key) && Buffer.isBuffer(m.ca));
  ok('summary has CA subject + fingerprint', /CN=tls-config-test-ca/.test(m.summary.ca.subject)
    && /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(m.summary.ca.fingerprint256));
  ok('no CRL when file absent', m.crl === null && m.summary.crl === null);
  const lines = formatTlsSummary(m.summary).join('\n');
  ok('banner reports real checks', /TLS cert: +OK .*CN=localhost/.test(lines)
    && /TLS key: +OK .*matches cert/.test(lines) && /CA: +OK .*sha256/.test(lines) && /CRL: +\(none\)/.test(lines)
    && !/configured/.test(lines));
  const withCrl = loadTlsMaterials({ ...good, crl: p('crl.pem') });
  ok('CRL loaded when present', Buffer.isBuffer(withCrl.crl) && /CRL: +OK/.test(formatTlsSummary(withCrl.summary).join('\n')));
  writeFileSync(p('bundle.crt'), `${m.ca.toString()}${m.ca.toString()}`);
  const bundle = loadTlsMaterials({ ...good, ca: p('bundle.crt') });
  ok('CA bundle counted', bundle.summary.ca.count === 2 && /\+1 more/.test(formatTlsSummary(bundle.summary).join('\n')));
}

section('loadTlsMaterials — expiry warning (non-fatal)');
{
  ok('warning window is 14 days', EXPIRY_WARN_DAYS === 14);
  const near = loadTlsMaterials(good); // 2-day CA + cert
  ok('cert expiring within 14 days → warning', near.warnings.some((w) => /^TLS_CERT .*server\.crt.*expires in [01] day\(s\).*< 14 days/.test(w)),
    JSON.stringify(near.warnings));
  ok('CA expiring within 14 days → warning', near.warnings.some((w) => /^TLS_CA .*ca\.crt.*expires in/.test(w)));
  const far = loadTlsMaterials({ ...good, ca: p('ca30.crt'), cert: p('server30.crt') });
  ok('>14 days → no warning', Array.isArray(far.warnings) && far.warnings.length === 0, JSON.stringify(far.warnings));
  const at13 = loadTlsMaterials({ ...good, ca: p('ca30.crt'), cert: p('server30.crt') }, { now: Date.now() + 17 * 86_400_000 });
  ok('30-day cert viewed 17 days later → warns for cert and CA', at13.warnings.length === 2
    && /^TLS_CERT /.test(at13.warnings[0]) && /^TLS_CA /.test(at13.warnings[1]), JSON.stringify(at13.warnings));
  writeFileSync(p('bundle-mixed.crt'), `${far.ca.toString()}${near.ca.toString()}`);
  const mixed = loadTlsMaterials({ ...good, ca: p('bundle-mixed.crt'), cert: p('server30.crt') });
  ok('CA bundle: only the expiring CA entry warns', mixed.warnings.length === 1 && /^TLS_CA\[1\] /.test(mixed.warnings[0]),
    JSON.stringify(mixed.warnings));
  ok('expiryWarnings: empty input → none', expiryWarnings([]).length === 0);
}

section('loadTlsMaterials — validity windows');
{
  ok('not-yet-valid server cert → error', throwsTls(() => loadTlsMaterials({ ...good, cert: p('server-future.crt') }),
    /TLS_CERT .*server-future\.crt.* is not yet valid \(valid from /));
  ok('server cert viewed before validFrom → error', throwsTls(() => loadTlsMaterials(good, { now: Date.now() - 86_400_000 }),
    /TLS_CERT .* is not yet valid/));
  // 30-day CA + 2-day CA in one bundle; 10 days later only the 2-day CA is expired.
  writeFileSync(p('bundle-expiring.crt'), `${readFileSync(p('ca30.crt'), 'utf8')}${readFileSync(p('ca.crt'), 'utf8')}`);
  ok('expired CA in TLS_CA bundle → error naming entry', throwsTls(() => loadTlsMaterials(
    { ...good, ca: p('bundle-expiring.crt'), cert: p('server30.crt') }, { now: Date.now() + 10 * 86_400_000 },
  ), /TLS_CA\[1\] .*bundle-expiring\.crt.* expired at /));
  ok('expired single TLS_CA → error', throwsTls(() => loadTlsMaterials(
    { ...good, cert: p('server30.crt'), ca: p('ca.crt') }, { now: Date.now() + 10 * 86_400_000 },
  ), /^TLS_CA \(.*\) expired at /));
  // Real future-dated CA (self-signed via `openssl ca -selfsign -startdate`) in a bundle.
  ossl('req', '-new', '-key', p('ca30.key'), '-out', p('ca-future.csr'), '-subj', '/CN=tls-config-test-ca-future');
  ossl('ca', '-batch', '-notext', '-selfsign', '-config', p('ca.cnf'), '-keyfile', p('ca30.key'),
    '-in', p('ca-future.csr'), '-out', p('ca-future.crt'),
    '-startdate', asn1Time(future), '-enddate', asn1Time(new Date(future.getTime() + 30 * 86_400_000)));
  writeFileSync(p('bundle-future.crt'), `${readFileSync(p('ca30.crt'), 'utf8')}${readFileSync(p('ca-future.crt'), 'utf8')}`);
  ok('not-yet-valid CA in TLS_CA bundle → error naming entry', throwsTls(() => loadTlsMaterials(
    { ...good, ca: p('bundle-future.crt'), cert: p('server30.crt') },
  ), /TLS_CA\[1\] .*bundle-future\.crt.* is not yet valid \(valid from /));
  ok('same bundle once the CA is valid → loads', loadTlsMaterials(
    { ...good, ca: p('bundle-future.crt'), cert: p('server30.crt') }, { now: future.getTime() + 86_400_000 },
  ).summary.ca.count === 2);
}

section('loadTlsMaterials — OpenSSL secure-context gate');
{
  ok('truncated cert PEM → TlsConfigError', throwsTls(() => loadTlsMaterials({ ...good, cert: p('server-truncated.crt') }),
    /server-truncated\.crt.*rejected by OpenSSL/));
  ok('malformed CRL → TlsConfigError naming TLS_CRL', throwsTls(() => loadTlsMaterials({ ...good, crl: p('malformed-crl.pem') }),
    /^TLS_CRL \(.*malformed-crl\.pem\) rejected by OpenSSL: .*CRL/));
  ok('empty CRL file → TlsConfigError naming TLS_CRL', throwsTls(() => loadTlsMaterials({ ...good, crl: p('empty.pem') }),
    /^TLS_CRL \(.*empty\.pem\) is empty/));
  let seen = null;
  loadTlsMaterials({ ...good, crl: p('crl.pem') }, { createSecureContext: (o) => { seen = o; } });
  ok('secure context built from the same buffers (+crl when set)', seen && Buffer.isBuffer(seen.cert)
    && Buffer.isBuffer(seen.key) && Buffer.isBuffer(seen.ca) && Buffer.isBuffer(seen.crl));
  seen = null;
  loadTlsMaterials(good, { createSecureContext: (o) => { seen = o; } });
  ok('no crl key passed when CRL absent', seen && !('crl' in seen));
  ok('any secure-context error → TlsConfigError', throwsTls(() => loadTlsMaterials(good, {
    createSecureContext: () => { throw new Error('boom'); },
  }), /rejected by OpenSSL: boom/));
}

section('Dockerfile dev stage');
{
  const dockerfile = readFileSync(join(REPO_ROOT, 'Dockerfile'), 'utf8');
  const runLines = dockerfile.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
  ok('does not create an empty crl.pem', !/touch\s+\S*crl\.pem/.test(runLines) && !/>\s*\S*crl\.pem/.test(runLines));
  ok('does not set TLS_CA', !/\bTLS_CA=/.test(runLines));
}

// ---------- integration ----------
writeFileSync(p('broker.yaml'), 'services: {}\nclients: {}\n');
function baseEnv(extra) {
  const env = { ...process.env };
  for (const k of ['TLS_CA', 'TLS_CERT', 'TLS_KEY', 'TLS_CRL', 'PKI_DIR']) delete env[k];
  return {
    ...env,
    NODE_ENV: 'test',
    SOPS_SKIP: '1',
    HOST: '127.0.0.1',
    PORT: '0',
    PKI_DIR: dir,
    CONFIG_PATH: p('broker.yaml'),
    SECRETS_PATH: p('common.env'),
    SECRETS_DETAIL_PATH: p('secrets-detail.json'),
    AUDIT_DIR: p('audit'),
    BROKER_HEALTH_DISABLE: '1',
    ...extra,
  };
}
function runServer(env, { waitFor, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVER_JS], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); resolve({ ...r, out }); };
    const onData = (d) => {
      out += d.toString();
      if (waitFor && waitFor.test(out)) { child.kill('SIGTERM'); finish({ matched: true, code: null }); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => finish({ matched: false, code }));
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish({ matched: false, code: 'timeout' }); }, timeoutMs);
  });
}

section('server.js startup');
{
  const r = await runServer(baseEnv({ TLS_CERT: p('server.crt'), TLS_KEY: p('server.key') }));
  ok('TLS_CA unset → non-zero exit', typeof r.code === 'number' && r.code !== 0, `code=${r.code}`);
  ok('TLS_CA unset → clear error', /\[tls\] FATAL: TLS_CA is not set/.test(r.out), r.out.slice(0, 300));
  ok('TLS_CA unset → no banner, no listen', !/Secret Broker v/.test(r.out) && !/listening/.test(r.out));
}
{
  const r = await runServer(baseEnv({ TLS_CA: p('missing-ca.crt'), TLS_CERT: p('server.crt'), TLS_KEY: p('server.key') }));
  ok('missing TLS_CA file → non-zero exit', typeof r.code === 'number' && r.code !== 0, `code=${r.code}`);
  ok('missing TLS_CA file → names path', /TLS_CA .*missing-ca\.crt.*does not exist/.test(r.out), r.out.slice(0, 300));
}
{
  const r = await runServer(baseEnv({ TLS_CA: p('ca.crt') }));
  ok('default TLS_CERT under PKI_DIR missing → non-zero exit', typeof r.code === 'number' && r.code !== 0
    && /TLS_CERT .*server[\\/]server\.crt.*does not exist/.test(r.out), r.out.slice(0, 300));
}
{
  const r = await runServer(
    baseEnv({ TLS_CA: p('ca.crt'), TLS_CERT: p('server.crt'), TLS_KEY: p('server.key') }),
    { waitFor: /mTLS HTTPS listening/ },
  );
  ok('valid material → server listens', r.matched, `code=${r.code} out=${r.out.slice(-500)}`);
  ok('valid material → banner shows CA subject', /CA: +OK .*CN=tls-config-test-ca.*sha256/.test(r.out));
  ok('banner no longer prints bare "configured"', !/TLS cert: +configured/.test(r.out));
  ok('2-day cert → startup logs [tls] WARNING but still listens', r.matched
    && /\[tls\] WARNING: TLS_CERT .*expires in/.test(r.out), r.out.slice(0, 800));
}
{
  const r = await runServer(
    baseEnv({ TLS_CA: p('ca30.crt'), TLS_CERT: p('server30.crt'), TLS_KEY: p('server.key') }),
    { waitFor: /mTLS HTTPS listening/ },
  );
  ok('30-day cert → listens with no expiry warning', r.matched && !/\[tls\] WARNING/.test(r.out), r.out.slice(-500));
}

for (const [name, extra, re] of [
  ['truncated cert PEM', { TLS_CERT: p('server-truncated.crt') }, /\[tls\] FATAL: .*server-truncated\.crt.*rejected by OpenSSL/],
  ['malformed CRL', { TLS_CRL: p('malformed-crl.pem') }, /\[tls\] FATAL: TLS_CRL .*malformed-crl\.pem.*rejected by OpenSSL/],
  ['not-yet-valid cert', { TLS_CERT: p('server-future.crt') }, /\[tls\] FATAL: TLS_CERT .* is not yet valid/],
]) {
  const r = await runServer(baseEnv({ TLS_CA: p('ca.crt'), TLS_CERT: p('server.crt'), TLS_KEY: p('server.key'), ...extra }));
  ok(`${name} → exit 78 (EX_CONFIG)`, r.code === 78, `code=${r.code} out=${r.out.slice(0, 300)}`);
  ok(`${name} → clear FATAL, no banner`, re.test(r.out) && !/Secret Broker v/.test(r.out) && !/listening/.test(r.out),
    r.out.slice(0, 300));
}
{
  const r = await runServer(
    baseEnv({ TLS_CA: p('ca.crt'), TLS_CERT: p('server.crt'), TLS_KEY: p('server.key'), TLS_CRL: p('crl.pem') }),
    { waitFor: /mTLS HTTPS listening/ },
  );
  ok('valid CRL → server listens, banner shows CRL OK', r.matched && /CRL: +OK .*crl\.pem/.test(r.out), r.out.slice(-500));
}

rmSync(dir, { recursive: true, force: true });
console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
