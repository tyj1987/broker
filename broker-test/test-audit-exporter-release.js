import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const read = name => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const require = createRequire(new URL('../broker/package.json', import.meta.url));
const { parse } = require('yaml');
const ci = parse(read('.github/workflows/ci.yml'));
const release = parse(read('.github/workflows/deploy-ecs.yml'));
const helper = read('deploy/bin/secret-broker-deploy');
const image = read('Dockerfile');
const unit = read('deploy/systemd/secret-broker-audit-exporter.service');
assert.deepEqual(release.on.workflow_run.branches, ['master']);
assert.match(release.jobs.build.if, /head_branch == 'master'/);
assert.equal(release.jobs.deploy.environment, 'production-aliyun');
assert.equal(release.jobs.deploy.needs, 'build');
assert.ok(ci.jobs['go-core'].steps.some(s => s.run?.includes('go test -race -coverprofile=audit-exporter-process-coverage.out ./cmd/audit-exporter')));
assert.ok(ci.jobs['go-core'].steps.some(s => s.run?.includes('$3 < 90')));
assert.ok(release.jobs.build.steps.some(s => s.run?.includes('-o ../broker/bin/secret-broker-audit-exporter ./cmd/audit-exporter') && s.run.includes('node ../broker/bin/package-audit-exporter.js')));
assert.match(image, /-o \/out\/secret-broker-audit-exporter \.\/cmd\/audit-exporter/);
assert.doesNotMatch(image, /COPY --from=core-build \/out\/secret-broker-audit-exporter \/app/);
assert.match(image, /rm -f[^\n]*bin\/audit-exporter-service-check\.js/);
assert.match(image, /rm -rf exporter-runtime recovery-runtime/);
for(const text of ['Type=notify','NotifyAccess=main','WatchdogSec=3700s','TimeoutStartSec=75s','KillMode=control-group',
  'PrivateNetwork=true','RestrictAddressFamilies=AF_UNIX','MemoryDenyWriteExecute=true','NoNewPrivileges=true',
  'SupplementaryGroups=broker-audit-signer broker-audit-store','Requires=secret-broker-audit-signer.service secret-broker-audit-store.service']) assert.ok(unit.includes(text),text);
assert.doesNotMatch(unit,/^Environment(File)?=/m);
assert.match(helper, /-x "\$PAYLOAD\/bin\/secret-broker-audit-exporter"/);
assert.match(helper, /"\$NODE_RUNTIME" "\$PAYLOAD\/bin\/package-audit-exporter\.js" --verify/);
assert.match(helper, /chmod 0500 "\$PAYLOAD\/bin\/secret-broker-audit-exporter"/);
assert.match(helper, /u:broker-audit-exporter:r-x,m::r-x "\$PAYLOAD\/bin\/secret-broker-audit-exporter"/);
assert.match(helper, /find "\$PAYLOAD\/exporter-runtime" -type f -exec chmod 0400/);
assert.match(helper, /find "\$PAYLOAD\/exporter-runtime" -type f -exec "\$SETFACL" -m u:broker-audit-exporter:r--,m::r--/);
assert.ok(helper.indexOf('package-audit-exporter.js" --verify') < helper.indexOf('mv -- "$PAYLOAD" "$RELEASE"'));
assert.doesNotMatch(helper, /^chmod\s+[0-7]{3,4}\s*$/m, 'permission commands require targets');
console.log('audit exporter release: fixed native process, closed runtime ACL and unchanged approval gates passed');

// Exercise the real wire decoder, not the higher-level store API projection.
const { EventEmitter } = await import('node:events');
const { fixtureReadPage } = await import('./audit-fixture-protocol.mjs');
const { createLocalAuditAnchorStoreClient } = await import('../broker/lib/local-audit-anchor-store-client.js');
function fixtureClient(project) {
  return createLocalAuditAnchorStoreClient({ streamId: 'synthetic-wire', processUid: 1001,
    processGroups: [2001], timeoutMs: 100,
    stat: async path => ({ uid: 0, gid: 2001, mode: path.endsWith('.sock') ? 0o140660 : 0o040750,
      isDirectory: () => !path.endsWith('.sock'), isSocket: () => path.endsWith('.sock'), isSymbolicLink: () => false }),
    connect: (_options, connected) => {
      const socket = new EventEmitter();
      socket.setTimeout = () => {}; socket.destroy = () => {};
      socket.end = body => {
        const request = JSON.parse(body);
        const response = JSON.stringify({ version: 1, purpose: request.purpose, request_id: request.request_id,
          operation: request.operation, status: 'ok', stream_id: request.stream_id, result: project(request.parameters) }) + '\n';
        queueMicrotask(() => { socket.emit('data', response); socket.emit('end'); });
      };
      queueMicrotask(connected);
      return socket;
    },
  });
}
const query = { streamId: 'synthetic-wire', afterSequence: 0, throughSequence: 1, limit: 1 };
await assert.rejects(fixtureClient(() => ({ anchors: [] })).readPage(query), { code: 'anchor_store_response_invalid' });
assert.deepEqual(await fixtureClient(parameters => fixtureReadPage([], parameters)).readPage(query), { anchors: [] });
const records = [1, 2, 3].map(sequence => ({ payload: { sequence } }));
assert.deepEqual(fixtureReadPage(records, { after_sequence: 1, through_sequence: 3, limit: 1 }),
  { after_sequence: 1, through_sequence: 3, anchors: [records[1]] });
assert.throws(() => fixtureReadPage(records, { after_sequence: 3, through_sequence: 1, limit: 1 }));
console.log('audit fixture wire: missing range binding rejected; complete wire page accepted by real client decoder');
