import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { LOCAL_ALIYUN_SIGNING_CONTRACT } from '../broker/lib/local-aliyun-signing-client.js';
import { LOCAL_SIGNER_CONTRACT } from '../broker/lib/local-signer-client.js';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const preflight = read('../deploy/bin/secret-broker-production-preflight.mjs');
const tmpfiles = read('../deploy/tmpfiles.d/secret-broker-provider-signers.conf');

const signers = Object.freeze({
  github: {
    user: 'broker-github-signer',
    directory: '/run/secret-broker-github-signer',
    socket: '/run/secret-broker-github-signer/signer.sock',
    config: '/etc/secret-broker/providers/github-signer.json',
    contract: LOCAL_SIGNER_CONTRACT,
  },
  aliyun: {
    user: 'broker-aliyun-signer',
    directory: '/run/secret-broker-aliyun-signer',
    socket: '/run/secret-broker-aliyun-signer/signer.sock',
    config: '/etc/secret-broker/providers/aliyun-signer.json',
    contract: LOCAL_ALIYUN_SIGNING_CONTRACT,
  },
});

for (const [provider, expected] of Object.entries(signers)) {
  const binary = `secret-broker-${provider}-signer`;
  const unit = read(`../deploy/systemd/${binary}.service`);
  const socketUnit = read(`../deploy/systemd/${binary}.socket`);
  assert.match(unit, new RegExp(`^User=${expected.user}$`, 'm'));
  assert.match(unit, new RegExp(`^Group=${expected.user}$`, 'm'));
  assert.match(
    unit,
    new RegExp(
      `^ExecStart=/opt/secret-broker/broker/bin/${binary} --config ${expected.config.replaceAll('.', '\\.')}$`,
      'm',
    ),
  );
  assert.match(unit, new RegExp(`^Requires=${binary}\\.socket$`, 'm'));
  assert.match(unit, new RegExp(`^After=.*${binary}\\.socket$`, 'm'));
  assert.match(unit, /^UMask=0007$/m);
  assert.match(unit, /^AmbientCapabilities=$/m);
  assert.match(unit, /^CapabilityBoundingSet=$/m);
  assert.match(unit, /^LockPersonality=true$/m);
  assert.match(unit, /^MemoryDenyWriteExecute=true$/m);
  assert.match(unit, /^NoNewPrivileges=true$/m);
  assert.match(unit, /^PrivateDevices=true$/m);
  assert.match(unit, /^PrivateTmp=true$/m);
  assert.match(unit, /^ProtectProc=invisible$/m);
  assert.match(unit, /^ProtectSystem=strict$/m);
  assert.match(unit, /^RestrictNamespaces=true$/m);
  assert.match(unit, /^RestrictSUIDSGID=true$/m);
  assert.match(unit, /^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6$/m);
  assert.match(unit, /^SystemCallFilter=@system-service$/m);
  assert.doesNotMatch(unit, /^DynamicUser=/m);
  assert.doesNotMatch(unit, /^Environment(File)?=/m);
  assert.doesNotMatch(unit, /^LoadCredential=/m);
  assert.doesNotMatch(unit, /^RuntimeDirectory=/m);
  assert.doesNotMatch(unit, /^SupplementaryGroups=/m);
  assert.match(
    socketUnit,
    new RegExp(`^ListenStream=${expected.socket.replaceAll('.', '\\.')}$`, 'm'),
  );
  assert.match(socketUnit, /^Accept=no$/m);
  assert.match(socketUnit, /^After=systemd-tmpfiles-setup\.service$/m);
  assert.match(socketUnit, /^SocketUser=root$/m);
  assert.match(socketUnit, new RegExp(`^SocketGroup=${expected.user}$`, 'm'));
  assert.match(socketUnit, /^SocketMode=0660$/m);
  assert.match(socketUnit, /^DirectoryMode=0750$/m);
  assert.match(socketUnit, /^RemoveOnStop=true$/m);
  assert.match(socketUnit, new RegExp(`^Service=${binary}\\.service$`, 'm'));
  assert.match(tmpfiles, new RegExp(`^d ${expected.directory} 0750 root ${expected.user} -$`, 'm'));
  assert.equal(expected.contract.socket_directory, expected.directory);
  assert.equal(expected.contract.socket_path, expected.socket);
  assert.match(preflight, new RegExp(`service: '${binary}\\.service'`));
  assert.match(preflight, new RegExp(`socketService: '${binary}\\.socket'`));
  assert.match(preflight, new RegExp(`user: '${expected.user}'`));
  assert.match(preflight, new RegExp(`directory: '${expected.directory}'`));
  assert.match(preflight, new RegExp(`socket: '${expected.socket}'`));
}

assert.notEqual(signers.github.user, signers.aliyun.user);
assert.notEqual(signers.github.directory, signers.aliyun.directory);
assert.notEqual(signers.github.socket, signers.aliyun.socket);
assert.doesNotMatch(preflight, /BROKER_REQUIRE_GITHUB_SIGNER/);

console.log('provider signer systemd contracts: isolated identities and fail-closed paths passed');
