import assert from 'node:assert/strict';

import {
  runTrustDomainCutoverCheck,
  safeTrustDomainCutoverErrorCode,
} from '../broker/bin/trust-domain-cutover-check.js';
import { TrustDomainCutoverError } from '../broker/lib/trust-domain-cutover.js';

const sha = (value) => value.repeat(64);
const validPlan = () => ({
  version: 1,
  change_id: 'dq009-2026-09',
  environment: 'production',
  maintenance_window: {
    starts_at: '2026-09-16T02:00:00.000Z',
    ends_at: '2026-09-16T03:00:00.000Z',
  },
  authorities: {
    legacy_ca_sha256: sha('a'),
    replacement_ca_sha256: sha('b'),
    replacement_authority: 'cloud_hsm',
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
  authorization: { status: 'pending', approval_ref: null },
});

const planPath = '/protected/dq009-plan.json';
const input = Buffer.from(JSON.stringify(validPlan()));
const reads = [];
let output = '';
const report = runTrustDomainCutoverCheck(
  ['node', 'trust-domain-cutover-check.js', '--plan-file', planPath],
  {
    readProtectedFileImpl: (...args) => {
      reads.push(args);
      return input;
    },
    now: () => Date.parse('2026-09-16T01:00:00.000Z'),
    writeOutput: (value) => {
      output += value;
    },
  },
);
assert.equal(report, output);
assert.match(report, /ready_for_cutover=no/);
assert.match(report, /missing_controls=change_authorization/);
assert.doesNotMatch(report, /evidence:|owner:|[a-d]{64}/);
assert.deepEqual(reads, [[planPath, 'Trust-domain cutover plan', 64 * 1024, { sensitive: true }]]);

let defaultOutput = '';
const originalStdoutWrite = process.stdout.write;
try {
  process.stdout.write = (value) => {
    defaultOutput += value;
    return true;
  };
  runTrustDomainCutoverCheck(['node', 'cli', '--plan-file', planPath], {
    readProtectedFileImpl: () => input,
  });
} finally {
  process.stdout.write = originalStdoutWrite;
}
assert.match(defaultOutput, /DQ-009 TRUST DOMAIN CUTOVER/);

for (const argv of [
  ['node', 'cli', '--plan-file', planPath, '--private-key-file', '/forbidden'],
  ['node', 'cli'],
]) {
  let read = false;
  assert.throws(() =>
    runTrustDomainCutoverCheck(argv, {
      readProtectedFileImpl: () => {
        read = true;
        return input;
      },
    }),
  );
  assert.equal(read, false);
}

for (const invalidInput of [
  Buffer.from('{'),
  Buffer.alloc(0),
  Buffer.alloc(64 * 1024 + 1),
  'not-a-buffer',
]) {
  assert.throws(() =>
    runTrustDomainCutoverCheck(['node', 'cli', '--plan-file', planPath], {
      readProtectedFileImpl: () => invalidInput,
    }),
  );
}

assert.equal(
  safeTrustDomainCutoverErrorCode(new TrustDomainCutoverError('cutover_plan_invalid')),
  'cutover_plan_invalid',
);
assert.equal(
  safeTrustDomainCutoverErrorCode(new TrustDomainCutoverError('private_material_exposed')),
  'trust_domain_cutover_check_failed',
);
assert.equal(
  safeTrustDomainCutoverErrorCode(new Error('path and secret must stay hidden')),
  'trust_domain_cutover_check_failed',
);

console.log('trust-domain cutover CLI: protected input and safe report checks passed');
