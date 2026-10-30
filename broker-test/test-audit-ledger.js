// Real filesystem regressions for the production audit route and checkpoint.
// All corruption/failure injection is confined to generated temporary directories.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createAuditRoutes } from '../broker/routes/audit.js';
import { redactDeep } from '../broker/lib/redact.js';
import {
  sealEvent,
  verifyChain,
  verifyAuditDir,
  createChainWriter,
} from '../broker/lib/audit-hash-chain.js';
import {
  createAuditLedger,
  pruneAuditLedger,
  LEDGER_STATE,
  LEDGER_LOCK,
} from '../broker/lib/audit-ledger.js';
import { pruneAuditFiles } from '../broker/lib/audit-policy.js';

let checks = 0;
const dirs = [];
const dir = () => {
  const p = fs.mkdtempSync(join(tmpdir(), 'broker-ledger-'));
  dirs.push(p);
  return p;
};
const state = (p) => JSON.parse(fs.readFileSync(join(p, LEDGER_STATE), 'utf8'));
const route = (p, opts = {}) =>
  createAuditRoutes({
    auditDir: p,
    getConfig: () => ({ clients: {}, services: {} }),
    redact: redactDeep,
    ledgerOptions: opts,
  });
function check(name, condition) {
  assert.ok(condition, name);
  checks++;
  console.log('PASS ' + name);
}
function fails(fn, code) {
  try {
    fn();
    return false;
  } catch (error) {
    return code ? error.code === code : true;
  }
}
try {
  const sealed = sealEvent({
    action: 'roundtrip',
    hash: 'caller-hash',
    missing: undefined,
    nested: { x: undefined, a: [undefined, NaN] },
    at: new Date(0),
  });
  check(
    'sealing follows persisted JSON normalization',
    verifyChain([JSON.parse(JSON.stringify(sealed))]).ok,
  );
  check('caller-supplied hash cannot poison the stored hash', sealed.hash !== 'caller-hash');
  const writer = createChainWriter({
    onEvent: () => {
      throw new Error('fixture-sink-failure');
    },
  });
  check(
    'failed sink does not advance in-memory chain',
    fails(() => writer.write({ action: 'denied' })) && writer.count === 0,
  );

  const primary = dir();
  const a = route(primary, { maxSegmentBytes: 900 });
  const events = [];
  for (let i = 0; i < 8; i++)
    events.push(
      a.audit({
        action: 'login',
        cn: i === 0 ? 'older-user' : 'current-user',
        n: i,
        missing: undefined,
      }),
    );
  let verified = await verifyAuditDir(primary);
  check(
    'real route writes a fully verifiable fresh chain',
    verified.ok && verified.full_history_verified && verified.count === 8,
  );
  check('small segment threshold creates multiple verified files', verified.files > 1);
  check(
    'disk events have monotonic sequence and matching previous hash',
    events.every(
      (e, i) => e.audit_sequence === i + 1 && (!i || e.prev_hash === events[i - 1].hash),
    ),
  );
  check(
    'filtered reads include matching events older than the ring fast-path limit',
    a.readAuditFiltered({ cn: 'older-user', limit: 1 })[0]?.n === 0,
  );
  check(
    'future since filter does not accidentally return cached events',
    a.readAuditFiltered({ since: '2999-01-01T00:00:00Z', limit: 1 }).length === 0,
  );
  const checkpoint = state(primary);
  const restarted = route(primary, { maxSegmentBytes: 900 });
  const next = restarted.audit({ action: 'after-restart' });
  check(
    'new writer instance resumes exact durable chain',
    next.prev_hash === checkpoint.head_hash && next.audit_sequence === 9,
  );
  check('resumed ledger verifies across all rotated segments', (await verifyAuditDir(primary)).ok);
  const beforeClear = fs.readdirSync(primary).sort().join(',');
  check(
    'audit clear API is disabled rather than erasing chain evidence',
    fails(() => restarted.clearAuditLogs(), 'AUDIT_CLEAR_DISABLED'),
  );
  check(
    'disabled clear preserves every file and verified chain',
    fs.readdirSync(primary).sort().join(',') === beforeClear && (await verifyAuditDir(primary)).ok,
  );

  const corruption = dir();
  const corrupted = route(corruption);
  corrupted.audit({ action: 'one' });
  corrupted.audit({ action: 'two' });
  const snapshot = state(corruption);
  const active = join(corruption, snapshot.segments.at(-1).name);
  const original = fs.readFileSync(active);
  fs.appendFileSync(active, '{broken-json}\n');
  check('malformed extra record is not silently skipped', !(await verifyAuditDir(corruption)).ok);
  const corruptBytes = fs.readFileSync(active);
  check(
    'writer rejects an uncommitted tail without repairing it',
    fails(() => corrupted.audit({ action: 'must-not-append' }), 'AUDIT_UNAVAILABLE') &&
      fs.readFileSync(active).equals(corruptBytes),
  );
  fs.writeFileSync(active, original.subarray(0, original.length - 1));
  check('truncated record is rejected', !(await verifyAuditDir(corruption)).ok);
  fs.writeFileSync(active, original.toString().replace('one', 'ONE'));
  check('same-length event tampering is detected', !(await verifyAuditDir(corruption)).ok);
  fs.writeFileSync(active, original);
  const lines = original.toString().trimEnd().split('\n');
  fs.writeFileSync(active, lines[0] + '\n');
  check(
    'removing complete last event is detected by durable checkpoint',
    !(await verifyAuditDir(corruption)).ok,
  );
  fs.unlinkSync(active);
  check('removing entire active file is detected', !(await verifyAuditDir(corruption)).ok);
  fs.writeFileSync(active, original);
  const savedCheckpoint = fs.readFileSync(join(corruption, LEDGER_STATE));
  fs.unlinkSync(join(corruption, LEDGER_STATE));
  check(
    'missing checkpoint cannot downgrade a managed chain to legacy mode',
    !(await verifyAuditDir(corruption)).ok && fails(() => route(corruption)),
  );
  fs.writeFileSync(join(corruption, LEDGER_STATE), savedCheckpoint);
  fs.writeFileSync(join(corruption, 'audit-unexpected.jsonl'), '{}\n');
  check('unexpected uncheckpointed audit file is detected', !(await verifyAuditDir(corruption)).ok);
  fs.unlinkSync(join(corruption, 'audit-unexpected.jsonl'));
  fs.writeFileSync(join(corruption, LEDGER_STATE), '{invalid-json');
  check(
    'malformed checkpoint fails closed',
    !(await verifyAuditDir(corruption)).ok && fails(() => route(corruption)),
  );
  fs.writeFileSync(join(corruption, LEDGER_STATE), savedCheckpoint);
  check('explicit test-fixture restoration verifies again', (await verifyAuditDir(corruption)).ok);

  const legacy = dir();
  const historicalName = 'audit-2020-01-01.jsonl.1';
  const historical = Buffer.from('{"action":"historical-unsigned"}\n');
  fs.writeFileSync(join(legacy, historicalName), historical);
  check('unsigned pre-migration logs are not falsely verified', !(await verifyAuditDir(legacy)).ok);
  route(legacy).audit({ action: 'first-managed' });
  verified = await verifyAuditDir(legacy);
  check(
    'migration verifies only new chain and labels legacy history unverified',
    verified.ok &&
      verified.legacy_files === 1 &&
      !verified.legacy_history_verified &&
      !verified.full_history_verified,
  );
  check(
    'migration preserves legacy bytes without adding historical hashes',
    fs.readFileSync(join(legacy, historicalName)).equals(historical),
  );
  check(
    'rotated legacy file remains readable in audit history',
    route(legacy)
      .readAudit({ limit: 20 })
      .some((e) => e.action === 'historical-unsigned'),
  );
  fs.appendFileSync(join(legacy, historicalName), '{"action":"untracked-change"}\n');
  check('legacy baseline drift is detected after migration', !(await verifyAuditDir(legacy)).ok);
  fs.writeFileSync(join(legacy, historicalName), historical);
  pruneAuditFiles(legacy, 1);
  check(
    'automatic retention never erases inventoried unsigned history',
    fs.readFileSync(join(legacy, historicalName)).equals(historical),
  );

  const retention = dir();
  let now = Date.parse('2020-01-01T00:00:00Z');
  const ledger = createAuditLedger(retention, { now: () => now });
  for (let i = 0; i < 4; i++) {
    ledger.append({ ts: new Date(now).toISOString(), action: 'retention-fixture', n: i });
    now += 86400000;
  }
  now = Date.parse('2020-04-01T00:00:00Z');
  const retired = pruneAuditLedger(retention, 30, { now: () => now });
  verified = await verifyAuditDir(retention);
  check(
    'retention removes only closed prefix after persisting checkpoints',
    retired.deleted.length === 3 && verified.ok && verified.pruned_events === 3,
  );
  check(
    'retained verification does not claim deleted payload integrity',
    !verified.full_history_verified &&
      verified.verification_scope.includes('retention-checkpoints'),
  );
  check(
    'retention records an explicit chained intent',
    route(retention)
      .readAudit({ limit: 50 })
      .some((e) => e.action === 'audit_retention'),
  );
  createAuditLedger(retention, { now: () => now }).append({ action: 'after-retention-restart' });
  check(
    'restart after retention resumes rather than resetting genesis',
    (await verifyAuditDir(retention)).ok && state(retention).total_events === 6,
  );
  check(
    'invalid retention settings cannot erase the journal',
    fails(() => pruneAuditFiles(retention, -1)),
  );

  const diskFailure = dir();
  let failAppend = true;
  const faultIo = {
    ...fs,
    appendFileSync: (...args) => {
      if (failAppend) throw Object.assign(new Error('fixture-disk-full'), { code: 'ENOSPC' });
      return fs.appendFileSync(...args);
    },
  };
  const failingRoute = route(diskFailure, { io: faultIo });
  let published = 0;
  failingRoute.bus.on('event', () => published++);
  check(
    'append failure propagates instead of pretending to succeed',
    fails(() => failingRoute.audit({ action: 'failed' }), 'AUDIT_UNAVAILABLE'),
  );
  await new Promise((r) => setImmediate(r));
  check(
    'failed event enters neither ring nor SSE',
    published === 0 &&
      failingRoute.health().ring_buffer_size === 0 &&
      state(diskFailure).total_events === 0,
  );
  failAppend = false;
  failingRoute.audit({ action: 'recovered' });
  check(
    'retry after pre-write failure has no gap or duplicate',
    (await verifyAuditDir(diskFailure)).ok && state(diskFailure).total_events === 1,
  );
  const checkpointFailure = dir();
  let failCheckpoint = false;
  const faulty = createAuditLedger(checkpointFailure, {
    io: {
      ...fs,
      renameSync: (...args) => {
        if (failCheckpoint) throw new Error('fixture-checkpoint-failure');
        return fs.renameSync(...args);
      },
    },
  });
  faulty.append({ action: 'first' });
  failCheckpoint = true;
  check(
    'checkpoint failure returns an uncertain failed transaction',
    fails(() => faulty.append({ action: 'uncommitted' }), 'AUDIT_UNAVAILABLE'),
  );
  check(
    'uncheckpointed persisted tail is retained and fails verification',
    !(await verifyAuditDir(checkpointFailure)).ok &&
      fs
        .readFileSync(join(checkpointFailure, state(checkpointFailure).segments[0].name), 'utf8')
        .includes('uncommitted'),
  );
  check(
    'restart does not silently accept or discard uncommitted evidence',
    fails(() => createAuditLedger(checkpointFailure)),
  );
  check(
    'checkpoint failure cleans only its own temporary state file',
    !fs.readdirSync(checkpointFailure).some((n) => n.endsWith('.tmp')),
  );

  const locked = dir();
  createAuditLedger(locked).append({ action: 'before-lock' });
  fs.writeFileSync(join(locked, LEDGER_LOCK), 'crash-evidence\n');
  check(
    'crash-left lock is not stolen',
    fails(() => createAuditLedger(locked), 'AUDIT_UNAVAILABLE') &&
      fs.readFileSync(join(locked, LEDGER_LOCK), 'utf8') === 'crash-evidence\n',
  );
  check(
    'locked verifier returns an explicit non-success state',
    (await verifyAuditDir(locked)).retryable === true,
  );
  fs.unlinkSync(join(locked, LEDGER_LOCK));
  check(
    'explicit test lock reconciliation restores availability',
    (await verifyAuditDir(locked)).ok,
  );

  const oldChain = dir();
  const first = sealEvent({ action: 'old-rotation' });
  const second = sealEvent({ action: 'old-current' }, first.hash);
  fs.writeFileSync(join(oldChain, 'audit-2020-01-01.jsonl.1'), JSON.stringify(first) + '\n');
  fs.writeFileSync(join(oldChain, 'audit-2020-01-01.jsonl'), JSON.stringify(second) + '\n');
  check(
    'legacy chain verifier includes numbered rotations in correct order',
    (await verifyAuditDir(oldChain)).ok,
  );
  fs.appendFileSync(join(oldChain, 'audit-2020-01-01.jsonl'), '{malformed}\n');
  check(
    'legacy verifier no longer ignores malformed JSON lines',
    !(await verifyAuditDir(oldChain)).ok,
  );

  const concurrent = dir();
  createAuditLedger(concurrent).append({ action: 'seed' });
  const moduleUrl = new URL('../broker/lib/audit-ledger.js', import.meta.url).href;
  const source = `import {createAuditLedger} from ${JSON.stringify(moduleUrl)};let success=0,denied=0;try{const a=createAuditLedger(process.argv[1]);for(let i=0;i<20;i++){try{a.append({action:'parallel',i});success++}catch(e){if(e.code!=='AUDIT_UNAVAILABLE')throw e;denied++}}}catch(e){if(e.code!=='AUDIT_UNAVAILABLE')throw e;denied=20}console.log(JSON.stringify({success,denied}));`;
  function worker() {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--input-type=module', '-e', source, concurrent], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = '';
      child.stdout.on('data', (b) => (out += b));
      child.stderr.resume();
      child.once('error', reject);
      child.once('close', (code) =>
        code ? reject(new Error('worker failed')) : resolve(JSON.parse(out)),
      );
    });
  }
  const results = await Promise.all([worker(), worker()]);
  verified = await verifyAuditDir(concurrent);
  check(
    'concurrent real processes serialize commits or explicitly reject contention',
    verified.ok && verified.total_events === 1 + results.reduce((n, r) => n + r.success, 0),
  );
  check(
    'concurrent writers leave no persistent transaction lock',
    !fs.existsSync(join(concurrent, LEDGER_LOCK)),
  );
  console.log(`audit-ledger: ${checks} passed, 0 failed`);
} finally {
  for (const p of dirs)
    fs.rmSync(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
