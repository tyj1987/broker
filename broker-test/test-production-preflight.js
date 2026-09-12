import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  collectProductionSnapshot,
  evaluateProductionReadiness,
  isDirectExecution,
  renderProductionReadiness,
} from '../deploy/bin/secret-broker-production-preflight.mjs';

const readySnapshot = {
  brokerUser: 'broker',
  brokerGroup: 'broker',
  brokerActive: true,
  policyActive: true,
  managedReleaseSymlink: true,
  deployHelperExecutable: true,
  deployAccountPresent: true,
  nginxConfigValid: true,
  nginxVerifyOnCount: 1,
  nginxVerifyOffCount: 0,
  forbiddenPrivateKeyCount: 0,
  controlPlaneStatePresent: true,
  controlPlaneStateKeyProtected: true,
  policySocketProtected: true,
  githubSignerSocketProtected: true,
  githubSignerRequired: false,
  auditSignerActive: true,
  auditExporterActive: true,
  auditStoreLockActive: true,
  auditRecoveryAuthorityActive: true,
  auditSignerUser: 'broker-audit-signer',
  auditExporterUser: 'broker-audit-exporter',
  auditStoreUser: 'broker-audit-store',
  auditRecoveryUser: 'broker-audit-recovery',
  auditSignerGroup: 'broker-audit-signer',
  auditExporterGroup: 'broker-audit-exporter',
  auditStoreGroup: 'broker-audit-store',
  auditRecoveryGroup: 'broker-audit-recovery',
  loopbackHealth: true,
};

const ready = evaluateProductionReadiness(readySnapshot);
assert.equal(ready.ready, true);
assert.equal(ready.checks.length, 22);
assert.ok(ready.checks.every((check) => check.passed));
assert.match(renderProductionReadiness(ready), /production_cd_ready=yes\n$/);

const signerNotRequired = evaluateProductionReadiness({
  ...readySnapshot,
  githubSignerSocketProtected: false,
});
assert.equal(signerNotRequired.ready, true);
const signerRequired = evaluateProductionReadiness({
  ...readySnapshot,
  githubSignerRequired: true,
  githubSignerSocketProtected: false,
});
assert.equal(signerRequired.ready, false);

for (const [field, unsafeValue] of [
  ['brokerUser', 'root'],
  ['brokerGroup', ''],
  ['brokerActive', false],
  ['policyActive', false],
  ['managedReleaseSymlink', false],
  ['deployHelperExecutable', false],
  ['deployAccountPresent', false],
  ['nginxConfigValid', false],
  ['nginxVerifyOnCount', 0],
  ['nginxVerifyOffCount', 1],
  ['forbiddenPrivateKeyCount', 1],
  ['controlPlaneStatePresent', false],
  ['controlPlaneStateKeyProtected', false],
  ['policySocketProtected', false],
  ['githubSignerSocketProtected', false],
  ['auditSignerActive', false],
  ['auditExporterActive', false],
  ['auditExporterUser', 'broker'],
  ['auditExporterGroup', 'broker'],
  ['auditSignerUser', 'broker-audit-exporter'],
  ['auditSignerGroup', 'broker'],
  ['auditStoreLockActive', false],
  ['auditStoreUser', 'broker'],
  ['auditStoreGroup', 'broker'],
  ['auditRecoveryAuthorityActive', false],
  ['auditRecoveryUser', 'broker'],
  ['auditRecoveryGroup', 'broker'],
  ['loopbackHealth', false],
]) {
  const result = evaluateProductionReadiness({
    ...readySnapshot,
    ...(field === 'githubSignerSocketProtected' ? { githubSignerRequired: true } : {}),
    [field]: unsafeValue,
  });
  assert.equal(result.ready, false, `${field} must block production CD`);
  assert.match(renderProductionReadiness(result), /production_cd_ready=no\n$/);
}

const rendered = renderProductionReadiness(
  evaluateProductionReadiness({
    ...readySnapshot,
    brokerUser: 'unexpected-sensitive-value',
    nginxVerifyOffCount: 4,
    diagnostic: 'proxy_pass https://should-not-be-rendered.example',
  }),
);
assert.doesNotMatch(rendered, /unexpected-sensitive-value/);
assert.doesNotMatch(rendered, /should-not-be-rendered/);

const fakePaths = {
  currentRelease: '/release',
  deployHelper: '/helper',
  controlPlaneState: '/state',
  controlPlaneStateKey: '/state-key',
  policySocket: '/policy.sock',
  githubSignerDirectory: '/signer',
  githubSignerSocket: '/signer/github.sock',
  forbiddenKeyRoots: ['/offline-ca', '/offline-clients'],
};
const fakeStats = new Map([
  ['/release', { isSymbolicLink: () => true }],
  ['/state', { isFile: () => true, isSymbolicLink: () => false }],
  ['/state-key', { isFile: () => true, isSymbolicLink: () => false, uid: 0, mode: 0o100600 }],
  ['/policy.sock', { isSocket: () => true, isSymbolicLink: () => false, mode: 0o140660 }],
  [
    '/signer',
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 2001, gid: 1002, mode: 0o040750 },
  ],
  [
    '/signer/github.sock',
    { isSocket: () => true, isSymbolicLink: () => false, uid: 2001, gid: 1002, mode: 0o140660 },
  ],
]);
const command = (name, args) => {
  const invocation = `${name} ${args.join(' ')}`;
  for (const service of ['signer', 'exporter', 'store', 'recovery']) {
    if (invocation.includes(`secret-broker-audit-${service}.service`)) {
      if (invocation.includes('-p User')) return { ok: true, stdout: `broker-audit-${service}` };
      if (invocation.includes('-p Group')) return { ok: true, stdout: `broker-audit-${service}` };
    }
  }
  if (invocation.includes('-p User')) return { ok: true, stdout: 'broker' };
  if (invocation.includes('-p Group')) return { ok: true, stdout: 'broker' };
  if (name === 'nginx') return { ok: true, stdout: '  proxy_ssl_verify on;\n' };
  if (name === 'id' && args[0] === '-u') return { ok: true, stdout: '1001' };
  if (name === 'id' && args[0] === '-G') return { ok: true, stdout: '1001 1002' };
  return {
    ok: true,
    stdout: name === 'getent' ? 'broker-deploy:x:1002:1002::/nonexistent:/bin/bash' : '',
  };
};
const collectWithStats = (stats) =>
  collectProductionSnapshot({
    command,
    paths: fakePaths,
    pathInfoImpl: async (path) => stats.get(path) ?? null,
    isExecutableImpl: async () => true,
    countPrivateKeysImpl: async () => 0,
    loopbackHealthImpl: async () => true,
  });
const collected = await collectWithStats(fakeStats);
assert.equal(evaluateProductionReadiness(collected).ready, true);
assert.equal(collected.nginxVerifyOnCount, 1);
assert.equal(collected.nginxVerifyOffCount, 0);
assert.equal(collected.githubSignerRequired, false);
for (const [path, replacement] of [
  ['/signer', { ...fakeStats.get('/signer'), gid: 9999 }],
  ['/signer', { ...fakeStats.get('/signer'), mode: 0o040740 }],
  ['/signer/github.sock', { ...fakeStats.get('/signer/github.sock'), uid: 2002 }],
  ['/signer/github.sock', { ...fakeStats.get('/signer/github.sock'), gid: 9999 }],
  ['/signer/github.sock', { ...fakeStats.get('/signer/github.sock'), mode: 0o140640 }],
]) {
  const unsafeStats = new Map(fakeStats);
  unsafeStats.set(path, replacement);
  const unsafe = await collectWithStats(unsafeStats);
  assert.equal(unsafe.githubSignerSocketProtected, false, `${path} boundary must fail closed`);
}
assert.equal(isDirectExecution('-', 'file:///irrelevant'), true);
const scriptPath = fileURLToPath(
  new URL('../deploy/bin/secret-broker-production-preflight.mjs', import.meta.url),
);
assert.equal(
  isDirectExecution(
    scriptPath,
    new URL('../deploy/bin/secret-broker-production-preflight.mjs', import.meta.url).href,
  ),
  true,
);
assert.equal(isDirectExecution('/tmp/other.mjs', 'file:///tmp/preflight.mjs'), false);

console.log('production preflight: 22 fail-closed deployment gates passed');
