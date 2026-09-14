import assert from 'node:assert/strict';

import {
  TrustDomainCutoverError,
  evaluateTrustDomainCutoverReadiness,
  renderTrustDomainCutoverReport,
  validateTrustDomainCutoverPlan,
} from '../broker/lib/trust-domain-cutover.js';

const sha = (value) => value.repeat(64);
const plan = () => ({
  version: 1,
  change_id: 'dq009-2026-09',
  environment: 'production',
  maintenance_window: {
    starts_at: '2026-09-13T02:00:00.000Z',
    ends_at: '2026-09-13T03:00:00.000Z',
  },
  authorities: {
    legacy_ca_sha256: sha('a'),
    replacement_ca_sha256: sha('b'),
    replacement_authority: 'offline_ca',
  },
  management_paths: [
    { id: 'primary-ssh', kind: 'ssh', verified: true, evidence_ref: 'evidence:ssh-host-key' },
    {
      id: 'cloud-console',
      kind: 'cloud_console',
      verified: true,
      evidence_ref: 'evidence:console-test',
    },
  ],
  proxy: {
    public_hostname: 'broker.52trz.com',
    backend_server_name: 'broker.internal.52trz.com',
    nginx_workload_cert_sha256: sha('c'),
    trusted_proxy_cert_sha256: sha('c'),
  },
  clients: [
    {
      client_id: 'client.tyj-laptop',
      owner_ref: 'owner:primary',
      new_cert_sha256: sha('d'),
      enrollment_status: 'verified',
    },
    {
      client_id: 'client.recovery',
      owner_ref: 'owner:recovery',
      new_cert_sha256: sha('e'),
      enrollment_status: 'verified',
    },
  ],
  rollback: {
    point: 'before_first_new_identity_acceptance',
    release_sha: 'f'.repeat(40),
    config_sha256: sha('1'),
    legacy_domain_restore_allowed: false,
    rehearsal_evidence_ref: 'evidence:rollback-rehearsal',
  },
  evidence: {
    pre_cutover_snapshot_verified: true,
    ssh_host_identity_verified: true,
    new_proxy_binding_staged: true,
    rollback_rehearsal_passed: true,
    secret_free_audit_test_passed: true,
  },
  authorization: { status: 'approved', approval_ref: 'approval:dq009-window' },
});

const valid = plan();
assert.deepEqual(validateTrustDomainCutoverPlan(valid), valid);
const ready = evaluateTrustDomainCutoverReadiness(valid, {
  now: () => Date.parse('2026-09-13T01:00:00.000Z'),
});
assert.equal(ready.ready, true);
assert.deepEqual(ready.missing, []);
assert.throws(() => {
  ready.plan.evidence.rollback_rehearsal_passed = false;
}, TypeError);
const report = renderTrustDomainCutoverReport(valid, {
  now: () => Date.parse('2026-09-13T01:00:00.000Z'),
});
assert.match(report, /ready_for_cutover=yes/);
assert.match(report, /rollback_after_new_identity_acceptance=forbidden/);
assert.match(report, new RegExp(`release_sha=${'f'.repeat(40)}`));
assert.doesNotMatch(report, new RegExp(sha('a')));
assert.doesNotMatch(report, /ssh-host-key|console-test|approval:dq009-window/);

const pending = plan();
pending.evidence.rollback_rehearsal_passed = false;
pending.authorization = { status: 'pending', approval_ref: null };
const notReady = evaluateTrustDomainCutoverReadiness(pending, {
  now: () => Date.parse('2026-09-13T01:50:00.001Z'),
});
assert.equal(notReady.ready, false);
assert.deepEqual(notReady.missing, [
  'maintenance_notice',
  'rollback_rehearsal',
  'change_authorization',
]);
assert.match(
  renderTrustDomainCutoverReport(pending, {
    now: () => Date.parse('2026-09-13T01:50:00.001Z'),
  }),
  /ready_for_cutover=no/,
);

const expectInvalid = (mutate) => {
  const candidate = plan();
  mutate(candidate);
  assert.throws(
    () => validateTrustDomainCutoverPlan(candidate),
    (error) => error instanceof TrustDomainCutoverError && error.code === 'cutover_plan_invalid',
  );
};

for (const mutate of [
  (value) => {
    value.secret = 'must-not-be-accepted';
  },
  (value) => {
    value.environment = 'staging';
  },
  (value) => {
    value.maintenance_window.ends_at = '2026-09-13T02:05:00.000Z';
  },
  (value) => {
    value.maintenance_window.ends_at = '2026-09-13T06:00:00.000Z';
  },
  (value) => {
    value.maintenance_window.starts_at = '2026-09-13T02:00:00Z';
  },
  (value) => {
    value.authorities.replacement_ca_sha256 = value.authorities.legacy_ca_sha256;
  },
  (value) => {
    value.authorities.private_key = 'forbidden';
  },
  (value) => {
    value.management_paths = value.management_paths.slice(0, 1);
  },
  (value) => {
    value.management_paths[1].kind = 'ssh';
  },
  (value) => {
    value.management_paths[1].verified = false;
  },
  (value) => {
    value.management_paths[1].id = value.management_paths[0].id;
  },
  (value) => {
    value.proxy.public_hostname = value.proxy.backend_server_name;
  },
  (value) => {
    value.proxy.trusted_proxy_cert_sha256 = sha('9');
  },
  (value) => {
    value.proxy.nginx_workload_cert_sha256 = value.authorities.replacement_ca_sha256;
    value.proxy.trusted_proxy_cert_sha256 = value.authorities.replacement_ca_sha256;
  },
  (value) => {
    value.clients = [];
  },
  (value) => {
    value.clients[1].client_id = value.clients[0].client_id;
  },
  (value) => {
    value.clients[1].new_cert_sha256 = value.clients[0].new_cert_sha256;
  },
  (value) => {
    value.clients[0].new_cert_sha256 = value.proxy.nginx_workload_cert_sha256;
  },
  (value) => {
    value.clients[0].enrollment_status = 'pending';
  },
  (value) => {
    value.rollback.point = 'after_cutover';
  },
  (value) => {
    value.rollback.legacy_domain_restore_allowed = true;
  },
  (value) => {
    value.evidence.extra = true;
  },
  (value) => {
    value.evidence.pre_cutover_snapshot_verified = 'yes';
  },
  (value) => {
    value.authorization = { status: 'pending', approval_ref: 'approval:stale' };
  },
  (value) => {
    value.authorization = { status: 'approved', approval_ref: null };
  },
])
  expectInvalid(mutate);

assert.throws(
  () => evaluateTrustDomainCutoverReadiness(plan(), { now: null }),
  (error) => error.code === 'cutover_evaluation_invalid',
);
assert.throws(
  () => evaluateTrustDomainCutoverReadiness(plan(), { now: () => Number.NaN }),
  (error) => error.code === 'cutover_evaluation_invalid',
);
assert.throws(
  () => renderTrustDomainCutoverReport({}),
  (error) => error.code === 'cutover_plan_invalid',
);

console.log('trust-domain cutover: strict plan, readiness and safe report checks passed');
