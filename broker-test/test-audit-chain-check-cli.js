import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildAuditEvent, sealEvent } from '../broker/lib/audit-hash-chain.js';

const cli = fileURLToPath(new URL('../broker/bin/audit-chain-check.js', import.meta.url));
const run = (auditDir) => spawnSync(process.execPath, [cli], {
  encoding: 'utf8',
  env: { ...process.env, AUDIT_DIR: auditDir },
});

const validDir = mkdtempSync(join(tmpdir(), 'broker-audit-valid-'));
const event = sealEvent(buildAuditEvent({ action: 'test', status: 'ok' }, {
  now: () => 0,
  idFactory: () => 'event-1',
}));
writeFileSync(join(validDir, 'audit-chain-1970-01-01.jsonl'), `${JSON.stringify(event)}\n`);

const valid = run(validDir);
assert.equal(valid.status, 0, valid.stderr);
assert.match(valid.stdout, /^audit_chain_verified=yes files=1 events=1\s*$/);
assert.doesNotMatch(valid.stdout + valid.stderr, /event-1|action|hash/);

const corruptDir = mkdtempSync(join(tmpdir(), 'broker-audit-corrupt-'));
writeFileSync(join(corruptDir, 'audit-chain-1970-01-01.jsonl'), '{"sensitive":"canary-secret"}\n');
const corrupt = run(corruptDir);
assert.equal(corrupt.status, 65);
assert.equal(corrupt.stdout, '');
assert.match(corrupt.stderr, /^audit_chain_verified=no\s*$/);
assert.doesNotMatch(corrupt.stdout + corrupt.stderr, /canary-secret|sensitive/);

const relative = run('relative/audit');
assert.equal(relative.status, 64);
assert.match(relative.stderr, /requires an absolute AUDIT_DIR/);

console.log('audit chain deploy check: valid, corrupt, redacted, absolute-path enforcement passed');
