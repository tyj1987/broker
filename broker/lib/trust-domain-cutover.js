const ID_RE = /^[a-z][a-z0-9._:-]{2,127}$/;
const HOST_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA_RE = /^[a-f0-9]{40}$/;
const CLIENT_ID_RE = /^[a-z][a-z0-9.-]{2,63}$/;
const EXACT_KEYS = Object.freeze({
  root: new Set([
    'version',
    'change_id',
    'environment',
    'maintenance_window',
    'authorities',
    'management_paths',
    'proxy',
    'clients',
    'rollback',
    'evidence',
    'authorization',
  ]),
  maintenance: new Set(['starts_at', 'ends_at']),
  authorities: new Set(['legacy_ca_sha256', 'replacement_ca_sha256', 'replacement_authority']),
  managementPath: new Set(['id', 'kind', 'verified', 'evidence_ref']),
  proxy: new Set([
    'public_hostname',
    'backend_server_name',
    'nginx_workload_cert_sha256',
    'trusted_proxy_cert_sha256',
  ]),
  client: new Set(['client_id', 'owner_ref', 'new_cert_sha256', 'enrollment_status']),
  rollback: new Set([
    'point',
    'release_sha',
    'config_sha256',
    'legacy_domain_restore_allowed',
    'rehearsal_evidence_ref',
  ]),
  evidence: new Set([
    'pre_cutover_snapshot_verified',
    'ssh_host_identity_verified',
    'new_proxy_binding_staged',
    'rollback_rehearsal_passed',
    'secret_free_audit_test_passed',
  ]),
  authorization: new Set(['status', 'approval_ref']),
});

const EVIDENCE_CODES = Object.freeze({
  pre_cutover_snapshot_verified: 'pre_cutover_snapshot',
  ssh_host_identity_verified: 'ssh_host_identity',
  new_proxy_binding_staged: 'new_proxy_binding',
  rollback_rehearsal_passed: 'rollback_rehearsal',
  secret_free_audit_test_passed: 'secret_free_audit',
});

export class TrustDomainCutoverError extends Error {
  constructor(code) {
    super(code);
    this.name = 'TrustDomainCutoverError';
    this.code = code;
  }
}

function fail(code) {
  throw new TrustDomainCutoverError(code);
}

function exactObject(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string') return null;
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch) || new Date(epoch).toISOString() !== value) return null;
  return epoch;
}

function safeId(value) {
  return typeof value === 'string' && ID_RE.test(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function validateManagementPaths(paths) {
  if (!Array.isArray(paths) || paths.length < 2 || paths.length > 4) fail('cutover_plan_invalid');
  const ids = new Set();
  const kinds = new Set();
  for (const path of paths) {
    if (
      !exactObject(path, EXACT_KEYS.managementPath) ||
      !safeId(path.id) ||
      !['ssh', 'cloud_console', 'serial_console', 'out_of_band'].includes(path.kind) ||
      path.verified !== true ||
      !safeId(path.evidence_ref) ||
      ids.has(path.id)
    ) {
      fail('cutover_plan_invalid');
    }
    ids.add(path.id);
    kinds.add(path.kind);
  }
  if (kinds.size < 2) fail('cutover_plan_invalid');
}

function validateClients(clients, reservedFingerprints) {
  if (!Array.isArray(clients) || clients.length < 1 || clients.length > 128) {
    fail('cutover_plan_invalid');
  }
  const ids = new Set();
  const fingerprints = new Set();
  for (const client of clients) {
    if (
      !exactObject(client, EXACT_KEYS.client) ||
      typeof client.client_id !== 'string' ||
      !CLIENT_ID_RE.test(client.client_id) ||
      !safeId(client.owner_ref) ||
      !SHA256_RE.test(client.new_cert_sha256 || '') ||
      client.enrollment_status !== 'verified' ||
      ids.has(client.client_id) ||
      fingerprints.has(client.new_cert_sha256) ||
      reservedFingerprints.has(client.new_cert_sha256)
    ) {
      fail('cutover_plan_invalid');
    }
    ids.add(client.client_id);
    fingerprints.add(client.new_cert_sha256);
  }
}

export function validateTrustDomainCutoverPlan(input) {
  if (
    !exactObject(input, EXACT_KEYS.root) ||
    input.version !== 1 ||
    !safeId(input.change_id) ||
    input.environment !== 'production'
  ) {
    fail('cutover_plan_invalid');
  }
  if (!exactObject(input.maintenance_window, EXACT_KEYS.maintenance)) fail('cutover_plan_invalid');
  const startsAt = canonicalTimestamp(input.maintenance_window.starts_at);
  const endsAt = canonicalTimestamp(input.maintenance_window.ends_at);
  const durationMinutes = (endsAt - startsAt) / 60_000;
  if (startsAt === null || endsAt === null || durationMinutes < 15 || durationMinutes > 180) {
    fail('cutover_plan_invalid');
  }

  const authorities = input.authorities;
  if (
    !exactObject(authorities, EXACT_KEYS.authorities) ||
    !SHA256_RE.test(authorities.legacy_ca_sha256 || '') ||
    !SHA256_RE.test(authorities.replacement_ca_sha256 || '') ||
    authorities.legacy_ca_sha256 === authorities.replacement_ca_sha256 ||
    !['offline_ca', 'cloud_hsm'].includes(authorities.replacement_authority)
  ) {
    fail('cutover_plan_invalid');
  }
  validateManagementPaths(input.management_paths);

  const proxy = input.proxy;
  if (
    !exactObject(proxy, EXACT_KEYS.proxy) ||
    !HOST_RE.test(proxy.public_hostname || '') ||
    !HOST_RE.test(proxy.backend_server_name || '') ||
    proxy.public_hostname === proxy.backend_server_name ||
    !SHA256_RE.test(proxy.nginx_workload_cert_sha256 || '') ||
    proxy.nginx_workload_cert_sha256 === authorities.legacy_ca_sha256 ||
    proxy.nginx_workload_cert_sha256 === authorities.replacement_ca_sha256 ||
    proxy.trusted_proxy_cert_sha256 !== proxy.nginx_workload_cert_sha256
  ) {
    fail('cutover_plan_invalid');
  }
  validateClients(
    input.clients,
    new Set([
      authorities.legacy_ca_sha256,
      authorities.replacement_ca_sha256,
      proxy.nginx_workload_cert_sha256,
    ]),
  );

  const rollback = input.rollback;
  if (
    !exactObject(rollback, EXACT_KEYS.rollback) ||
    rollback.point !== 'before_first_new_identity_acceptance' ||
    !GIT_SHA_RE.test(rollback.release_sha || '') ||
    !SHA256_RE.test(rollback.config_sha256 || '') ||
    rollback.legacy_domain_restore_allowed !== false ||
    !safeId(rollback.rehearsal_evidence_ref)
  ) {
    fail('cutover_plan_invalid');
  }

  if (
    !exactObject(input.evidence, EXACT_KEYS.evidence) ||
    Object.values(input.evidence).some((value) => typeof value !== 'boolean')
  ) {
    fail('cutover_plan_invalid');
  }
  if (
    !exactObject(input.authorization, EXACT_KEYS.authorization) ||
    !['pending', 'approved'].includes(input.authorization.status) ||
    (input.authorization.status === 'pending' && input.authorization.approval_ref !== null) ||
    (input.authorization.status === 'approved' && !safeId(input.authorization.approval_ref))
  ) {
    fail('cutover_plan_invalid');
  }

  return deepFreeze(structuredClone(input));
}

export function evaluateTrustDomainCutoverReadiness(input, { now = () => Date.now() } = {}) {
  const plan = validateTrustDomainCutoverPlan(input);
  if (typeof now !== 'function') fail('cutover_evaluation_invalid');
  const current = now();
  if (!Number.isFinite(current)) fail('cutover_evaluation_invalid');
  const startsAt = Date.parse(plan.maintenance_window.starts_at);
  const missing = [];
  if (startsAt - current < 15 * 60_000) missing.push('maintenance_notice');
  for (const [field, code] of Object.entries(EVIDENCE_CODES)) {
    if (!plan.evidence[field]) missing.push(code);
  }
  if (plan.authorization.status !== 'approved') missing.push('change_authorization');
  return Object.freeze({
    ready: missing.length === 0,
    missing: Object.freeze(missing),
    plan,
  });
}

export function renderTrustDomainCutoverReport(input, options) {
  const result = evaluateTrustDomainCutoverReadiness(input, options);
  const plan = result.plan;
  const duration =
    (Date.parse(plan.maintenance_window.ends_at) - Date.parse(plan.maintenance_window.starts_at)) /
    60_000;
  return (
    [
      'DQ-009 TRUST DOMAIN CUTOVER',
      `change_id=${plan.change_id}`,
      `maintenance_window_utc=${plan.maintenance_window.starts_at}/${plan.maintenance_window.ends_at}`,
      `duration_minutes=${duration}`,
      `release_sha=${plan.rollback.release_sha}`,
      `client_count=${plan.clients.length}`,
      `management_path_count=${plan.management_paths.length}`,
      'impact=new sessions and protected operations may be briefly unavailable; existing legacy identities are revoked at the irreversible boundary',
      'rollback_point=before_first_new_identity_acceptance',
      'rollback_after_new_identity_acceptance=forbidden',
      `ready_for_cutover=${result.ready ? 'yes' : 'no'}`,
      `missing_controls=${result.missing.length === 0 ? 'none' : result.missing.join(',')}`,
    ].join('\n') + '\n'
  );
}
