import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { parseDocument } from 'yaml';
import { createAuditAnchorExporter } from './audit-anchor-exporter.js';

const PURPOSE = 'secret-broker.audit-anchor-exporter';
const ALGORITHM = 'ecdsa-p256-sha256';
const CONFIG_PATH = '/etc/secret-broker/audit/exporter.json';
const AUDIT_DIRECTORY = '/var/lib/secret-broker/audit';
const MAX_CONFIG_BYTES = 32 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST_RE = /^[a-f0-9]{64}$/;
const TOP_LEVEL_KEYS = new Set([
  'version',
  'purpose',
  'audit_directory',
  'stream_id',
  'algorithm',
  'active_key_id',
  'trusted_keys',
  'revoked_key_ids',
  'signer_timeout_ms',
  'store_timeout_ms',
  'export_deadline_ms',
  'interval_ms',
]);
const TRUSTED_KEY_KEYS = new Set(['key_id', 'public_key_spki_der_base64', 'public_key_sha256']);
const parsedConfigs = new WeakMap();

export class AuditAnchorExporterRuntimeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AuditAnchorExporterRuntimeError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditAnchorExporterRuntimeError(code, message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function safeInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function parsePublicKey(entry) {
  if (!exactKeys(entry, TRUSTED_KEY_KEYS) || !ID_RE.test(entry.key_id || '')) {
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  if (
    typeof entry.public_key_spki_der_base64 !== 'string' ||
    entry.public_key_spki_der_base64.length < 1 ||
    entry.public_key_spki_der_base64.length > 1_024 ||
    !DIGEST_RE.test(entry.public_key_sha256 || '')
  ) {
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  let encoded;
  let key;
  try {
    encoded = Buffer.from(entry.public_key_spki_der_base64, 'base64');
    if (
      encoded.length < 1 ||
      encoded.length > 512 ||
      encoded.toString('base64') !== entry.public_key_spki_der_base64 ||
      createHash('sha256').update(encoded).digest('hex') !== entry.public_key_sha256
    ) {
      fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
    }
    key = createPublicKey({ key: encoded, format: 'der', type: 'spki' });
    const canonical = key.export({ format: 'der', type: 'spki' });
    if (
      key.asymmetricKeyType !== 'ec' ||
      key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      !Buffer.from(canonical).equals(encoded)
    ) {
      fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
    }
  } catch (error) {
    if (error instanceof AuditAnchorExporterRuntimeError) throw error;
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  return Object.freeze({ keyId: entry.key_id, publicKey: key });
}

export function parseAuditAnchorExporterConfig(value) {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) < 1 ||
    Buffer.byteLength(value) > MAX_CONFIG_BYTES
  ) {
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  let document;
  try {
    const syntax = parseDocument(value, { schema: 'json', strict: true, uniqueKeys: true });
    if (syntax.errors.length !== 0 || syntax.warnings.length !== 0) {
      fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
    }
    document = JSON.parse(value);
  } catch (error) {
    if (error instanceof AuditAnchorExporterRuntimeError) throw error;
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  if (
    !exactKeys(document, TOP_LEVEL_KEYS) ||
    document.version !== 1 ||
    document.purpose !== PURPOSE ||
    document.audit_directory !== AUDIT_DIRECTORY ||
    !isAbsolute(document.audit_directory) ||
    !ID_RE.test(document.stream_id || '') ||
    document.algorithm !== ALGORITHM ||
    !ID_RE.test(document.active_key_id || '') ||
    !Array.isArray(document.trusted_keys) ||
    document.trusted_keys.length < 1 ||
    document.trusted_keys.length > 8 ||
    !Array.isArray(document.revoked_key_ids) ||
    document.revoked_key_ids.length > 8 ||
    !safeInteger(document.signer_timeout_ms, 100, 10_000) ||
    !safeInteger(document.store_timeout_ms, 100, 60_000) ||
    !safeInteger(document.export_deadline_ms, 1_000, 60_000) ||
    !safeInteger(document.interval_ms, 60_000, 3_600_000) ||
    document.export_deadline_ms >= document.interval_ms
  ) {
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  const trustedKeys = new Map();
  for (const entry of document.trusted_keys) {
    const parsed = parsePublicKey(entry);
    if (trustedKeys.has(parsed.keyId)) {
      fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
    }
    trustedKeys.set(parsed.keyId, parsed.publicKey);
  }
  const revokedKeyIds = new Set();
  for (const keyId of document.revoked_key_ids) {
    if (!ID_RE.test(keyId || '') || revokedKeyIds.has(keyId)) {
      fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
    }
    revokedKeyIds.add(keyId);
  }
  if (!trustedKeys.has(document.active_key_id) || revokedKeyIds.has(document.active_key_id)) {
    fail('anchor_exporter_config_invalid', 'Audit anchor exporter configuration is invalid');
  }
  const config = Object.freeze({
    auditDirectory: document.audit_directory,
    streamId: document.stream_id,
    algorithm: document.algorithm,
    activeKeyId: document.active_key_id,
    get trustedKeyIds() {
      return new Set(trustedKeys.keys());
    },
    get revokedKeyIds() {
      return new Set(revokedKeyIds);
    },
    signerTimeoutMs: document.signer_timeout_ms,
    storeTimeoutMs: document.store_timeout_ms,
    exportDeadlineMs: document.export_deadline_ms,
    intervalMs: document.interval_ms,
  });
  parsedConfigs.set(config, Object.freeze({ trustedKeys, revokedKeyIds }));
  return config;
}

async function validateTrustedDirectory(path, { statPath, resolvePath, ownerUid }) {
  const metadata = await statPath(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== ownerUid ||
    (metadata.mode & 0o022) !== 0 ||
    (await resolvePath(path)) !== path
  ) {
    fail('anchor_exporter_config_untrusted', 'Audit anchor exporter configuration is unavailable');
  }
}

export async function readAuditAnchorExporterConfig(
  path,
  {
    processGroups = typeof process.getgroups === 'function' ? process.getgroups() : [],
    ownerUid = 0,
    statPath = lstat,
    resolvePath = realpath,
    openFile = open,
  } = {},
) {
  if (
    path !== CONFIG_PATH ||
    !Array.isArray(processGroups) ||
    !Number.isSafeInteger(ownerUid) ||
    ownerUid < 0 ||
    typeof statPath !== 'function' ||
    typeof resolvePath !== 'function' ||
    typeof openFile !== 'function'
  ) {
    fail('anchor_exporter_config_untrusted', 'Audit anchor exporter configuration is unavailable');
  }
  let handle;
  try {
    for (const directory of ['/etc', '/etc/secret-broker', '/etc/secret-broker/audit']) {
      await validateTrustedDirectory(directory, { statPath, resolvePath, ownerUid });
    }
    handle = await openFile(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.uid !== ownerUid ||
      !processGroups.includes(metadata.gid) ||
      (metadata.mode & 0o777) !== 0o440 ||
      metadata.size < 1 ||
      metadata.size > MAX_CONFIG_BYTES
    ) {
      fail(
        'anchor_exporter_config_untrusted',
        'Audit anchor exporter configuration is unavailable',
      );
    }
    return parseAuditAnchorExporterConfig(await handle.readFile({ encoding: 'utf8' }));
  } catch (error) {
    if (error instanceof AuditAnchorExporterRuntimeError) throw error;
    fail('anchor_exporter_config_untrusted', 'Audit anchor exporter configuration is unavailable');
  } finally {
    await handle?.close().catch(() => {});
  }
}

function createVerifier(config) {
  const state = parsedConfigs.get(config);
  return ({ algorithm, keyId, signingInput, signature }) => {
    const key = state?.trustedKeys.get(keyId);
    if (algorithm !== ALGORITHM || !key) return false;
    try {
      return verify('sha256', signingInput, key, signature);
    } catch {
      return false;
    }
  };
}

export function createAuditAnchorExporterRuntime({
  config,
  signer,
  store,
  loadChainState,
  loadChainProof,
  now = () => Date.now(),
} = {}) {
  const state = parsedConfigs.get(config);
  if (!state) {
    throw new TypeError('Audit anchor exporter runtime configuration is invalid');
  }
  const exporter = createAuditAnchorExporter({
    streamId: config.streamId,
    signer,
    store,
    loadChainState,
    loadChainProof,
    trustedKeyIds: new Set(state.trustedKeys.keys()),
    revokedKeyIds: new Set(state.revokedKeyIds),
    verifySignature: createVerifier(config),
    now,
  });
  return Object.freeze({
    async exportOnce({ signal } = {}) {
      return exporter.exportAnchor({ signal });
    },
  });
}

function safeFailure(error) {
  const code =
    typeof error?.code === 'string' && /^[a-z][a-z0-9_]{1,63}$/.test(error.code)
      ? error.code
      : 'anchor_export_failed';
  return new AuditAnchorExporterRuntimeError(code, 'Audit anchor export failed');
}

function waitForInterval(intervalMs, signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(finish, intervalMs);
    function finish() {
      clearTimeout(timer);
      signal.removeEventListener('abort', finish);
      resolve();
    }
    signal.addEventListener('abort', finish, { once: true });
  });
}

export async function runAuditAnchorExporterService({
  runtime,
  intervalMs,
  exportDeadlineMs = 50_000,
  signal,
  writeStatus = (value) => console.log(JSON.stringify(value)),
} = {}) {
  if (
    !runtime ||
    typeof runtime.exportOnce !== 'function' ||
    !safeInteger(intervalMs, 60_000, 3_600_000) ||
    !safeInteger(exportDeadlineMs, 1_000, 60_000) ||
    exportDeadlineMs >= intervalMs ||
    !(signal instanceof AbortSignal) ||
    typeof writeStatus !== 'function'
  ) {
    throw new TypeError('Audit anchor exporter service configuration is invalid');
  }
  do {
    try {
      const deadline = AbortSignal.timeout(exportDeadlineMs);
      const result = await runtime.exportOnce({ signal: AbortSignal.any([signal, deadline]) });
      writeStatus(
        Object.freeze({
          status: result.status,
          stream_id: result.envelope.payload.stream_id,
          sequence: result.envelope.payload.sequence,
          payload_digest: result.envelope.payload_digest,
        }),
      );
    } catch (error) {
      if (signal.aborted) return;
      throw safeFailure(error);
    }
    if (!signal.aborted) await waitForInterval(intervalMs, signal);
  } while (!signal.aborted);
}

export const AUDIT_ANCHOR_EXPORTER_RUNTIME_CONTRACT = Object.freeze({
  purpose: PURPOSE,
  config_path: CONFIG_PATH,
  audit_directory: AUDIT_DIRECTORY,
  algorithm: ALGORITHM,
  maximum_config_bytes: MAX_CONFIG_BYTES,
  accepts_credentials: false,
  accepts_provider_endpoints: false,
  accepts_private_keys: false,
});
