import { createPublicKey, timingSafeEqual, verify } from 'node:crypto';

import { canonicalJson } from './operations-v2.js';

const SHA256_RE = /^[a-f0-9]{64}$/u;
const RELEASE_RE = /^[a-f0-9]{40}$/u;
const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iu;
const SAFE_ID_RE = /^[a-z0-9][a-z0-9._:-]{2,63}$/u;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const MAX_VALIDITY_MS = 15 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60_000;
const CHECKS = Object.freeze([
  'tool_discovery',
  'authority_identity',
  'authority_match',
  'bounded_read',
  'safe_output',
  'wrong_account_denied',
  'wrong_resource_denied',
]);
const ROOT_KEYS = new Set([
  'version',
  'evidence_id',
  'key_id',
  'release_sha',
  'binding_generation_sha256',
  'signer_authority_generation_sha256',
  'issued_at',
  'expires_at',
  'receipts',
]);
const RECEIPT_KEYS = new Set([
  'version',
  'provider',
  'operation_id',
  'environment',
  'status',
  'checks',
  'plan_sha256',
  'provider_audit_sha256',
]);
const KEYRING_KEYS = new Set(['version', 'keys']);
const KEY_KEYS = new Set(['key_id', 'algorithm', 'public_key_spki_der', 'not_before', 'not_after']);
const PROVIDERS = Object.freeze([
  Object.freeze({ provider: 'github', operationId: 'repo.read' }),
  Object.freeze({ provider: 'aliyun', operationId: 'ecs.instances.list' }),
]);

export const PROVIDER_CONTRACT_EVIDENCE_PATHS = Object.freeze({
  evidenceRoot: '/var/lib/secret-broker/provider-contract-evidence',
  keyring: '/etc/secret-broker/provider-contract-evidence-keyring.json',
  signerConfigs: Object.freeze({
    github: '/etc/secret-broker/providers/github-signer.json',
    aliyun: '/etc/secret-broker/providers/aliyun-signer.json',
  }),
});

function exactObject(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function parseCanonicalJson(bytes, maxBytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > maxBytes) return null;
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    return null;
  }
  const expected = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  return expected.length === bytes.length && timingSafeEqual(expected, bytes) ? value : null;
}

function timestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP_RE.test(value)) return Number.NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().replace('.000Z', 'Z') === value
    ? parsed
    : Number.NaN;
}

function validReceipt(receipt, expected) {
  return (
    exactObject(receipt, RECEIPT_KEYS) &&
    receipt.version === 2 &&
    receipt.provider === expected.provider &&
    receipt.operation_id === expected.operationId &&
    receipt.environment === 'production' &&
    receipt.status === 'passed' &&
    Array.isArray(receipt.checks) &&
    receipt.checks.length === CHECKS.length &&
    receipt.checks.every((check, index) => check === CHECKS[index]) &&
    SHA256_RE.test(receipt.plan_sha256 || '') &&
    SHA256_RE.test(receipt.provider_audit_sha256 || '')
  );
}

function decodeBase64Url(value, minBytes, maxBytes) {
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length >= minBytes &&
      decoded.length <= maxBytes &&
      decoded.toString('base64url') === value
      ? decoded
      : null;
  } catch {
    return null;
  }
}

export function verifyProviderContractEvidence({
  evidenceBytes,
  signatureBytes,
  keyringBytes,
  expectedReleaseSha,
  expectedBindingGeneration,
  expectedSignerAuthorityGeneration,
  now = Date.now(),
} = {}) {
  if (
    !RELEASE_RE.test(expectedReleaseSha || '') ||
    !SHA256_RE.test(expectedBindingGeneration || '') ||
    !exactObject(expectedSignerAuthorityGeneration, new Set(['github', 'aliyun'])) ||
    !SHA256_RE.test(expectedSignerAuthorityGeneration?.github || '') ||
    !SHA256_RE.test(expectedSignerAuthorityGeneration?.aliyun || '') ||
    !Number.isSafeInteger(now) ||
    now < 0
  ) {
    return false;
  }
  const evidence = parseCanonicalJson(evidenceBytes, 32 * 1024);
  const keyring = parseCanonicalJson(keyringBytes, 32 * 1024);
  if (!exactObject(evidence, ROOT_KEYS) || !exactObject(keyring, KEYRING_KEYS)) return false;
  const issuedAt = timestamp(evidence.issued_at);
  const expiresAt = timestamp(evidence.expires_at);
  if (
    evidence.version !== 1 ||
    !UUID_RE.test(evidence.evidence_id || '') ||
    !SAFE_ID_RE.test(evidence.key_id || '') ||
    evidence.release_sha !== expectedReleaseSha ||
    evidence.binding_generation_sha256 !== expectedBindingGeneration ||
    !exactObject(evidence.signer_authority_generation_sha256, new Set(['github', 'aliyun'])) ||
    evidence.signer_authority_generation_sha256.github !==
      expectedSignerAuthorityGeneration.github ||
    evidence.signer_authority_generation_sha256.aliyun !==
      expectedSignerAuthorityGeneration.aliyun ||
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    issuedAt > now + MAX_FUTURE_SKEW_MS ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_VALIDITY_MS ||
    !Array.isArray(evidence.receipts) ||
    evidence.receipts.length !== PROVIDERS.length ||
    !evidence.receipts.every((receipt, index) => validReceipt(receipt, PROVIDERS[index])) ||
    keyring.version !== 1 ||
    !Array.isArray(keyring.keys) ||
    keyring.keys.length < 1 ||
    keyring.keys.length > 16
  ) {
    return false;
  }
  const matches = keyring.keys.filter((entry) => entry?.key_id === evidence.key_id);
  if (
    matches.length !== 1 ||
    new Set(keyring.keys.map((entry) => entry?.key_id)).size !== keyring.keys.length ||
    !keyring.keys.every(
      (entry) =>
        exactObject(entry, KEY_KEYS) &&
        SAFE_ID_RE.test(entry.key_id || '') &&
        entry.algorithm === 'ed25519' &&
        Number.isSafeInteger(timestamp(entry.not_before)) &&
        Number.isSafeInteger(timestamp(entry.not_after)) &&
        timestamp(entry.not_after) > timestamp(entry.not_before) &&
        decodeBase64Url(entry.public_key_spki_der, 32, 256) !== null,
    )
  ) {
    return false;
  }
  const trusted = matches[0];
  const notBefore = timestamp(trusted.not_before);
  const notAfter = timestamp(trusted.not_after);
  const publicKeyBytes = decodeBase64Url(trusted.public_key_spki_der, 32, 256);
  const signature = decodeBase64Url(signatureBytes?.toString('utf8').trim(), 64, 64);
  if (
    trusted.algorithm !== 'ed25519' ||
    !Number.isSafeInteger(notBefore) ||
    !Number.isSafeInteger(notAfter) ||
    issuedAt < notBefore ||
    expiresAt > notAfter ||
    publicKeyBytes === null ||
    signature === null ||
    signatureBytes.toString('utf8') !== `${signature.toString('base64url')}\n`
  ) {
    return false;
  }
  try {
    const publicKey = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    return (
      publicKey.asymmetricKeyType === 'ed25519' && verify(null, evidenceBytes, publicKey, signature)
    );
  } catch {
    return false;
  }
}

export const PROVIDER_CONTRACT_EVIDENCE_CONTRACT = Object.freeze({
  version: 1,
  maxValidityMs: MAX_VALIDITY_MS,
  providers: PROVIDERS.map(({ provider }) => provider),
  checks: CHECKS,
});
