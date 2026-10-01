// broker/lib/tls-config.js — fail-fast resolution and validation of TLS material.
//
// TLS_CA is REQUIRED. There is intentionally no implicit default: falling back
// to a CA file shipped in the repository would silently trust whatever CA was
// committed there. TLS_CERT / TLS_KEY may default to PKI_DIR/server/server.{crt,key},
// but every path is checked (exists, readable, parses) before the server starts.

import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFileSync as fsReadFileSync, existsSync as fsExistsSync } from 'node:fs';
import { join } from 'node:path';

export class TlsConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TlsConfigError';
  }
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Resolve TLS paths from env. Throws TlsConfigError when TLS_CA is unset. */
export function resolveTlsPaths(env, pkiDir) {
  const ca = typeof env.TLS_CA === 'string' ? env.TLS_CA.trim() : '';
  if (!ca) {
    throw new TlsConfigError(
      'TLS_CA is not set. Set TLS_CA to the absolute path of the CA certificate that '
      + 'signs trusted client certificates (e.g. TLS_CA=/etc/secret-broker/pki/ca/ca.crt). '
      + 'There is no default: the broker will not fall back to a CA file in the repository.',
    );
  }
  return {
    ca,
    cert: env.TLS_CERT || join(pkiDir, 'server/server.crt'),
    key: env.TLS_KEY || join(pkiDir, 'server/server.key'),
    crl: env.TLS_CRL || join(pkiDir, 'ca/crl.pem'),
  };
}

function readRequired(label, path, readFileSync) {
  let buf;
  try {
    buf = readFileSync(path);
  } catch (e) {
    const reason = e && e.code === 'ENOENT' ? 'file does not exist'
      : e && e.code === 'EACCES' ? 'permission denied'
        : (e && (e.code || e.message)) || 'unreadable';
    throw new TlsConfigError(`${label} (${path}) is not readable: ${reason}`);
  }
  if (!buf || buf.length === 0) throw new TlsConfigError(`${label} (${path}) is empty`);
  return buf;
}

function parseCerts(label, path, buf) {
  const pems = buf.toString('utf8').match(PEM_CERT_RE) || [];
  if (pems.length === 0) throw new TlsConfigError(`${label} (${path}) contains no PEM certificate`);
  return pems.map((pem) => {
    try { return new X509Certificate(pem); } catch (e) {
      throw new TlsConfigError(`${label} (${path}) failed to parse: ${e.message}`);
    }
  });
}

function describe(x509) {
  return {
    subject: x509.subject.replace(/\n/g, ', '),
    fingerprint256: x509.fingerprint256,
    validTo: x509.validTo,
  };
}

/**
 * Read and validate TLS material. Returns buffers for https.createServer plus a
 * non-secret summary for the startup banner. Throws TlsConfigError on any problem.
 */
export function loadTlsMaterials(paths, { readFileSync = fsReadFileSync, existsSync = fsExistsSync, now = Date.now() } = {}) {
  const caBuf = readRequired('TLS_CA', paths.ca, readFileSync);
  const caCerts = parseCerts('TLS_CA', paths.ca, caBuf);
  const certBuf = readRequired('TLS_CERT', paths.cert, readFileSync);
  const leaf = parseCerts('TLS_CERT', paths.cert, certBuf)[0];
  const keyBuf = readRequired('TLS_KEY', paths.key, readFileSync);
  let key;
  try { key = createPrivateKey(keyBuf); } catch (e) {
    throw new TlsConfigError(`TLS_KEY (${paths.key}) failed to parse: ${e.message}`);
  }
  if (!leaf.checkPrivateKey(key)) {
    throw new TlsConfigError(`TLS_KEY (${paths.key}) does not match TLS_CERT (${paths.cert})`);
  }
  if (Date.parse(leaf.validTo) <= now) {
    throw new TlsConfigError(`TLS_CERT (${paths.cert}) expired at ${leaf.validTo}`);
  }
  let crl = null;
  if (paths.crl && existsSync(paths.crl)) crl = readRequired('TLS_CRL', paths.crl, readFileSync);
  return {
    cert: certBuf,
    key: keyBuf,
    ca: caBuf,
    crl,
    summary: {
      ca: { path: paths.ca, count: caCerts.length, ...describe(caCerts[0]) },
      cert: { path: paths.cert, ...describe(leaf) },
      key: { path: paths.key, type: key.asymmetricKeyType, matchesCert: true },
      crl: crl ? paths.crl : null,
    },
  };
}

/** Banner lines reflecting the checks that actually passed. */
export function formatTlsSummary(summary) {
  return [
    `  TLS cert:       OK ${summary.cert.path} (${summary.cert.subject}; expires ${summary.cert.validTo})`,
    `  TLS key:        OK ${summary.key.path} (${summary.key.type}, matches cert)`,
    `  CA:             OK ${summary.ca.path} (${summary.ca.subject}; sha256 ${summary.ca.fingerprint256}${summary.ca.count > 1 ? `; +${summary.ca.count - 1} more` : ''})`,
    `  CRL:            ${summary.crl ? `OK ${summary.crl}` : '(none)'}`,
  ];
}
