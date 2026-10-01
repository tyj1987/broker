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
//   integration (spawn broker/server.js)
//     8. TLS_CA unset → non-zero exit, clear message, no banner
//     9. TLS_CA points at a missing file → non-zero exit
//    10. valid material → banner shows real checks and server listens

import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { resolveTlsPaths, loadTlsMaterials, formatTlsSummary, TlsConfigError } from '../broker/lib/tls-config.js';

const OPENSSL_BIN = process.env.OPENSSL_BIN
  || (process.platform === 'win32' && existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
    ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
    : 'openssl');
const SERVER_JS = join(dirname(fileURLToPath(import.meta.url)), '..', 'broker', 'server.js');

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
writeFileSync(p('crl.pem'), '-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n');
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
}

rmSync(dir, { recursive: true, force: true });
console.log(`\n=== ${pass} pass / ${fail} fail ===`);
process.exit(fail === 0 ? 0 : 1);
