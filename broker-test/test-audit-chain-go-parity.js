import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  GENESIS_HASH,
  loadAuditChainProofSync,
  loadAuditChainStateSync,
  sealEvent,
} from '../broker/lib/audit-hash-chain.js';

const repository = resolve(fileURLToPath(new URL('..', import.meta.url)));
const core = join(repository, 'core');
const work = mkdtempSync(join(tmpdir(), 'broker-audit-go-parity-'));
const auditDir = join(work, 'audit');
const executable = join(
  work,
  process.platform === 'win32' ? 'audit-chain-check.exe' : 'audit-chain-check',
);
const go = process.env.BROKER_GO_BINARY || 'go';
const canary = 'synthetic-canary-must-not-appear';

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: repository,
    encoding: 'utf8',
    windowsHide: true,
    ...options,
  });
}

function runChecker(directory) {
  return run(executable, [], {
    env: { ...process.env, AUDIT_DIR: directory },
  });
}

function runGoProof(directory, proof) {
  return run(go, ['test', './auditchain', '-run', '^TestNodeParityFixture$', '-count=1'], {
    cwd: core,
    env: {
      ...process.env,
      BROKER_AUDIT_PARITY_DIR: directory,
      BROKER_AUDIT_PARITY_ANCHOR_COUNT: String(proof.anchoredEventCount),
      BROKER_AUDIT_PARITY_ANCHOR_FILES: String(proof.filesAtAnchor),
      BROKER_AUDIT_PARITY_ANCHOR_HASH: proof.hashAtAnchor,
    },
  });
}

function assertRedacted(result) {
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  assert.equal(output.includes(canary), false, 'checker disclosed event content');
  assert.equal(output.includes(auditDir), false, 'checker disclosed the audit path');
  for (const match of readFileSync(join(auditDir, 'audit-chain-2026-09-13.jsonl'), 'utf8').matchAll(
    /[a-f0-9]{64}/g,
  )) {
    assert.equal(output.includes(match[0]), false, 'checker disclosed a chain digest');
  }
}

try {
  const build = run(go, ['build', '-trimpath', '-o', executable, './cmd/audit-chain-check'], {
    cwd: core,
  });
  assert.equal(build.status, 0, `Go checker build failed: ${build.stderr}`);

  const first = sealEvent(
    {
      action: 'inventory.read',
      canary,
      text: '<>&\u2028\u2029中文😀',
      controls: '\b\f\n\r\t\u0000',
      nested: {
        array: [null, true, false, -0, 1e-7, 1e21, 333333333.33333329, 1e-27],
        '\u{10000}': 'astral-key',
        '\uE000': 'bmp-key',
      },
    },
    GENESIS_HASH,
  );
  const second = sealEvent(
    {
      action: 'anchor.capture',
      roundedSafeBoundary: 9007199254740993,
      result: { allowed: true },
    },
    first.hash,
  );
  const third = sealEvent({ action: 'inventory.complete', result: { count: 2 } }, second.hash);

  mkdirSync(auditDir, { mode: 0o700 });
  writeFileSync(
    join(auditDir, 'audit-chain-2026-09-12.jsonl'),
    `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`,
    { mode: 0o600 },
  );
  writeFileSync(join(auditDir, 'audit-chain-2026-09-13.jsonl'), `${JSON.stringify(third)}\n`, {
    mode: 0o600,
  });
  writeFileSync(join(auditDir, 'audit-legacy.jsonl'), '{"ignored":true}\n', { mode: 0o600 });

  const nodeState = loadAuditChainStateSync(auditDir, { chainOnly: true });
  assert.deepEqual(nodeState, { files: 2, count: 3, lastHash: third.hash });
  const nodeProof = loadAuditChainProofSync(auditDir, 2);
  assert.equal(nodeProof.hashAtAnchor, second.hash);
  assert.equal(nodeProof.filesAtAnchor, 1);
  const goProof = runGoProof(auditDir, nodeProof);
  assert.equal(goProof.status, 0, 'Go historical proof rejected the Node anchor');

  const valid = runChecker(auditDir);
  assert.equal(valid.status, 0, `Go checker rejected the Node chain: ${valid.stderr}`);
  assert.equal(valid.stdout, 'audit_chain_verified=yes files=2 events=3\n');
  assert.equal(valid.stderr, '');
  assertRedacted(valid);

  writeFileSync(
    join(auditDir, 'audit-chain-2026-09-13.jsonl'),
    `${JSON.stringify({ ...third, action: 'inventory.tampered' })}\n`,
    { mode: 0o600 },
  );
  assert.throws(() => loadAuditChainProofSync(auditDir, 2), /verification failed/);
  const corruptProof = runGoProof(auditDir, nodeProof);
  assert.notEqual(corruptProof.status, 0, 'Go proof accepted a corrupt retained chain');
  assert.equal(`${corruptProof.stdout}${corruptProof.stderr}`.includes(canary), false);
  assert.equal(`${corruptProof.stdout}${corruptProof.stderr}`.includes(auditDir), false);
  const corrupt = runChecker(auditDir);
  assert.equal(corrupt.status, 65);
  assert.equal(corrupt.stdout, '');
  assert.equal(corrupt.stderr, 'audit_chain_verified=no\n');
  assertRedacted(corrupt);

  const strictDir = join(work, 'strict-ijson');
  mkdirSync(strictDir, { mode: 0o700 });
  const nodeOnly = sealEvent({ action: 'invalid-unicode', value: '\ud800' }, GENESIS_HASH);
  writeFileSync(join(strictDir, 'audit-chain-2026-09-13.jsonl'), `${JSON.stringify(nodeOnly)}\n`, {
    mode: 0o600,
  });
  assert.equal(loadAuditChainStateSync(strictDir, { chainOnly: true }).count, 1);
  const strict = runChecker(strictDir);
  assert.equal(strict.status, 65, 'Go must fail closed on non-I-JSON Unicode');
  assert.equal(strict.stdout, '');
  assert.equal(strict.stderr, 'audit_chain_verified=no\n');

  console.log(`PASS ${basename(import.meta.url)}: Node and Go audit-chain compatibility`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
