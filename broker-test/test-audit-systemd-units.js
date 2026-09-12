import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const deployHelper = read('../deploy/bin/secret-broker-deploy');

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
assert.match(
  exporter,
  /^Requires=secret-broker-audit-signer\.service secret-broker-audit-store\.service$/m,
);
for (const name of ['signer', 'store', 'recovery']) {
  assert.doesNotMatch(
    read(`../deploy/systemd/secret-broker-audit-${name}.service`),
    /^PrivateNetwork=true$/m,
  );
}

assert.match(deployHelper, /audit service identity does not match the pinned contract/);
assert.doesNotMatch(deployHelper, /audit_user.*!= broker/);

console.log('audit systemd contracts: four pinned identities and fail-closed sandboxes passed');
