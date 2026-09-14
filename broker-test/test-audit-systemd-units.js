import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const deployHelper = read('../deploy/bin/secret-broker-deploy');
const productionPreflight = read('../deploy/bin/secret-broker-production-preflight.mjs');
const dockerfile = read('../Dockerfile');
const mirrorWorker = read('../deploy/systemd/secret-broker-audit-mirror-worker.service');
const mirrorSocket = read('../deploy/systemd/secret-broker-audit-mirror-worker.socket');
const mirrorTmpfiles = read('../deploy/tmpfiles.d/secret-broker-audit-mirror.conf');
const signerSocket = read('../deploy/systemd/secret-broker-audit-signer.socket');
const signerTmpfiles = read('../deploy/tmpfiles.d/secret-broker-audit-signer.conf');

const services = Object.freeze({
  signer: {
    network: 'AF_UNIX AF_INET AF_INET6',
    exec: 'secret-broker-audit-signer',
  },
  exporter: {
    network: 'AF_UNIX',
    exec: 'secret-broker-audit-exporter',
  },
  store: {
    network: 'AF_UNIX AF_INET AF_INET6',
    exec: 'secret-broker-audit-store',
  },
  recovery: {
    network: 'AF_UNIX AF_INET AF_INET6',
    exec: 'secret-broker-audit-recovery',
  },
});

for (const [name, contract] of Object.entries(services)) {
  const unitName = `secret-broker-audit-${name}`;
  const unit = read(`../deploy/systemd/${unitName}.service`);
  assert.match(unit, new RegExp(`^User=broker-audit-${name}$`, 'm'));
  assert.match(unit, new RegExp(`^Group=broker-audit-${name}$`, 'm'));
  assert.match(
    unit,
    new RegExp(
      `^ExecStart=/opt/secret-broker/broker/bin/${contract.exec} --config /etc/secret-broker/audit/${name}\\.json$`,
      'm',
    ),
  );
  assert.match(unit, /^AmbientCapabilities=$/m);
  assert.match(unit, /^CapabilityBoundingSet=$/m);
  assert.match(unit, /^LockPersonality=true$/m);
  assert.match(unit, /^MemoryDenyWriteExecute=true$/m);
  assert.match(unit, /^NoNewPrivileges=true$/m);
  assert.match(unit, /^PrivateDevices=true$/m);
  assert.match(unit, /^PrivateTmp=true$/m);
  assert.match(unit, /^ProtectSystem=strict$/m);
  assert.match(unit, /^ProtectProc=invisible$/m);
  assert.match(unit, /^RestrictNamespaces=true$/m);
  assert.match(unit, /^RestrictSUIDSGID=true$/m);
  assert.match(unit, /^SystemCallFilter=@system-service$/m);
  assert.match(unit, new RegExp(`^RestrictAddressFamilies=${contract.network}$`, 'm'));
  assert.doesNotMatch(unit, /^DynamicUser=/m);
  assert.doesNotMatch(unit, /^Environment(File)?=/m);
  assert.doesNotMatch(unit, /^LoadCredential=/m);
  assert.match(
    deployHelper,
    new RegExp(`${unitName}\\.service broker-audit-${name} broker-audit-${name}`),
  );
}

const exporter = read('../deploy/systemd/secret-broker-audit-exporter.service');
assert.match(exporter, /^PrivateNetwork=true$/m);
assert.match(exporter, /^SupplementaryGroups=broker-audit-signer broker-audit-store$/m);
assert.match(
  exporter,
  /^Requires=secret-broker-audit-signer\.service secret-broker-audit-store\.service$/m,
);
const signer = read('../deploy/systemd/secret-broker-audit-signer.service');
assert.match(signer, /^Requires=secret-broker-audit-signer\.socket$/m);
assert.match(signer, /^IPAddressDeny=any$/m);
for (const address of ['100.100.100.200/32', '100.100.2.136/32', '100.100.2.138/32']) {
  assert.match(signer, new RegExp(`^IPAddressAllow=${address.replaceAll('.', '\\.')}$`, 'm'));
}
assert.match(signerSocket, /^ListenStream=\/run\/secret-broker-audit-anchor\/signer\.sock$/m);
assert.match(signerSocket, /^FileDescriptorName=audit-signer$/m);
assert.match(signerSocket, /^SocketUser=root$/m);
assert.match(signerSocket, /^SocketGroup=broker-audit-signer$/m);
assert.match(signerSocket, /^SocketMode=0660$/m);
assert.equal(signerTmpfiles.trim(), 'd /run/secret-broker-audit-anchor 0750 root broker-audit-signer -');
const recovery = read('../deploy/systemd/secret-broker-audit-recovery.service');
assert.match(recovery, /^SupplementaryGroups=broker-audit-store$/m);
assert.doesNotMatch(read('../deploy/systemd/secret-broker-audit-store.service'), /^SupplementaryGroups=broker-audit-mirror$/m);
assert.match(mirrorWorker, /^User=broker-audit-mirror$/m);
assert.match(mirrorWorker, /^Group=broker-audit-mirror$/m);
assert.match(mirrorWorker, /^ExecStart=\/opt\/secret-broker\/broker\/bin\/secret-broker-audit-mirror-worker --config \/etc\/secret-broker\/audit\/mirror-worker\.json$/m);
assert.match(mirrorWorker, /^IPAddressDeny=any$/m);
assert.match(mirrorWorker, /^PrivateNetwork=true$/m);
assert.match(mirrorWorker, /^RestrictAddressFamilies=AF_UNIX$/m);
for (const setting of [
  'AmbientCapabilities=',
  'CapabilityBoundingSet=',
  'LockPersonality=true',
  'MemoryDenyWriteExecute=true',
  'NoNewPrivileges=true',
  'PrivateDevices=true',
  'PrivateTmp=true',
  'ProtectClock=true',
  'ProtectHome=true',
  'ProtectProc=invisible',
  'ProtectSystem=strict',
  'RestrictNamespaces=true',
  'RestrictSUIDSGID=true',
  'SystemCallFilter=@system-service',
]) {
  assert.match(mirrorWorker, new RegExp(`^${setting.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
}
assert.doesNotMatch(mirrorWorker, /^IPAddressAllow=/m);
assert.doesNotMatch(mirrorWorker, /^Restart=/m);
assert.doesNotMatch(mirrorWorker, /^\[Install\]$/m);
assert.doesNotMatch(mirrorWorker, /^Environment(File)?=/m);
assert.doesNotMatch(mirrorWorker, /^LoadCredential=/m);
assert.doesNotMatch(mirrorWorker, /^SupplementaryGroups=/m);
assert.doesNotMatch(mirrorWorker, /^DynamicUser=/m);
assert.match(mirrorSocket, /^ListenStream=\/run\/secret-broker-audit-mirror\/mirror\.sock$/m);
assert.match(mirrorSocket, /^FileDescriptorName=audit-mirror$/m);
assert.match(mirrorSocket, /^SocketUser=root$/m);
assert.match(mirrorSocket, /^SocketGroup=broker-audit-store$/m);
assert.match(mirrorSocket, /^SocketMode=0660$/m);
assert.doesNotMatch(mirrorSocket, /^\[Install\]$/m);
assert.equal(mirrorTmpfiles.trim(), 'd /run/secret-broker-audit-mirror 0750 root broker-audit-store -');
for (const name of ['signer', 'store', 'recovery']) {
  assert.doesNotMatch(
    read(`../deploy/systemd/secret-broker-audit-${name}.service`),
    /^PrivateNetwork=true$/m,
  );
}

assert.match(deployHelper, /audit service identity does not match the pinned contract/);
assert.doesNotMatch(deployHelper, /audit_user.*!= broker/);

for (const binary of ['secret-broker-audit-store', 'secret-broker-audit-store-health']) {
  assert.match(
    dockerfile,
    new RegExp(`-o /out/${binary} \\.\\/cmd\\/${binary.replace('secret-broker-', '')}`),
  );
  assert.doesNotMatch(
    dockerfile,
    new RegExp(`COPY --from=core-build /out/${binary} /app/bin/${binary}`),
  );
}
assert.match(
  dockerfile,
  /-o \/out\/secret-broker-audit-signer \.\/cmd\/audit-signer/,
);
assert.match(
  dockerfile,
  /-o \/out\/secret-broker-audit-mirror-worker \.\/cmd\/audit-mirror-worker/,
);
assert.doesNotMatch(
  dockerfile,
  /COPY --from=core-build \/out\/secret-broker-audit-mirror-worker \/app\/bin\/secret-broker-audit-mirror-worker/,
);
for (const [binary, identity] of [
  ['secret-broker-audit-signer', 'broker-audit-signer'],
  ['secret-broker-audit-store', 'broker-audit-store'],
  ['secret-broker-audit-store-health', 'broker-audit-recovery'],
  ['secret-broker-audit-mirror-worker', 'broker-audit-mirror'],
]) {
  assert.match(deployHelper, new RegExp(`chmod 0500 .*${binary}`));
  assert.match(deployHelper, new RegExp(`u:${identity}:r-x[^\\n]*${binary}`));
}
assert.doesNotMatch(dockerfile, /COPY --from=core-build \/out\/secret-broker-audit-signer \/app\/bin\/secret-broker-audit-signer/);
assert.doesNotMatch(deployHelper, /secret-broker-audit-mirror-worker\.service/);
assert.doesNotMatch(productionPreflight, /secret-broker-audit-mirror-worker/);

console.log('audit systemd contracts: isolated services and fail-closed mirror worker socket passed');
