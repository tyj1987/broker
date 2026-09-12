import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  collectProductionSnapshot,
  collectStableAuditRuntimeSnapshot,
  evaluateProductionReadiness,
  isDirectExecution,
  parseAuditStoreHealth,
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
  auditStoreActive: true,
  auditSignerReleaseBound: true,
  auditExporterReleaseBound: true,
  auditStoreReleaseBound: true,
  auditRecoveryReleaseBound: true,
  auditStoreHealthReady: true,
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
  ['auditSignerReleaseBound', false],
  ['auditExporterReleaseBound', false],
  ['auditExporterUser', 'broker'],
  ['auditExporterGroup', 'broker'],
  ['auditSignerUser', 'broker-audit-exporter'],
  ['auditSignerGroup', 'broker'],
  ['auditStoreActive', false],
  ['auditStoreReleaseBound', false],
  ['auditStoreHealthReady', false],
  ['auditStoreUser', 'broker'],
  ['auditStoreGroup', 'broker'],
  ['auditRecoveryAuthorityActive', false],
  ['auditRecoveryReleaseBound', false],
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
  auditStoreHealthHelper: '/release/bin/secret-broker-audit-store-health',
  auditStoreSocket: '/audit-store.sock',
  auditExecutables: {
    signer: '/release/bin/secret-broker-audit-signer',
    exporter: '/release/bin/secret-broker-audit-exporter',
    store: '/release/bin/secret-broker-audit-store',
    recovery: '/release/bin/secret-broker-audit-recovery',
  },
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
  for (const [index, service] of ['signer', 'exporter', 'store', 'recovery'].entries()) {
    if (invocation.includes(`secret-broker-audit-${service}.service`)) {
      if (invocation.includes('-p User')) return { ok: true, stdout: `broker-audit-${service}` };
      if (invocation.includes('-p Group')) return { ok: true, stdout: `broker-audit-${service}` };
      if (invocation.includes('-p MainPID')) return { ok: true, stdout: String(3001 + index) };
    }
  }
  if (invocation.includes('-p User')) return { ok: true, stdout: 'broker' };
  if (invocation.includes('-p Group')) return { ok: true, stdout: 'broker' };
  if (name === 'nginx') return { ok: true, stdout: '  proxy_ssl_verify on;\n' };
  if (name === '/usr/sbin/runuser') {
    assert.deepEqual(args, [
      '--user',
      'broker-audit-recovery',
      '--',
      '/usr/bin/env',
      '-i',
      'PATH=/usr/bin:/bin',
      '/release/bin/secret-broker-audit-store-health',
      '--socket',
      '/audit-store.sock',
    ]);
    return {
      ok: true,
      stdout:
        '{"status":"ready","lock_contract":"verified","mirror_state":"in_sync","common_sequence":7,"reason_code":"ok"}',
    };
  }
  if (name === 'id' && args[0] === '-u') return { ok: true, stdout: '1001' };
  if (name === 'id' && args[0] === '-G') return { ok: true, stdout: '1001 1002' };
  return {
    ok: true,
    stdout: name === 'getent' ? 'broker-deploy:x:1002:1002::/nonexistent:/bin/bash' : '',
  };
};
const executableByPid = new Map([
  ['3001', '/release/bin/secret-broker-audit-signer'],
  ['3002', '/release/bin/secret-broker-audit-exporter'],
  ['3003', '/release/bin/secret-broker-audit-store'],
  ['3004', '/release/bin/secret-broker-audit-recovery'],
]);
const processStat = (pid, startTime = Number(pid) + 10_000) =>
  `${pid} (secret-broker-audit) S ${Array(18).fill('0').join(' ')} ${startTime} 0`;
const readFileImpl = async (path) => {
  const pid = /^\/proc\/([1-9][0-9]*)\/stat$/u.exec(path)?.[1];
  if (pid && executableByPid.has(pid)) return processStat(pid);
  throw new Error('unexpected read');
};
const realpathImpl = async (path) => {
  const pid = /^\/proc\/([1-9][0-9]*)\/exe$/u.exec(path)?.[1];
  if (pid) return executableByPid.get(pid) ?? Promise.reject(new Error('missing process'));
  if (path === fakePaths.currentRelease) return path;
  if (path === fakePaths.auditStoreHealthHelper) return path;
  if (Object.values(fakePaths.auditExecutables).includes(path)) return path;
  throw new Error('unexpected realpath');
};
const collectWithStats = (stats) =>
  collectProductionSnapshot({
    command,
    paths: fakePaths,
    pathInfoImpl: async (path) => stats.get(path) ?? null,
    isExecutableImpl: async () => true,
    countPrivateKeysImpl: async () => 0,
    loopbackHealthImpl: async () => true,
    realpathImpl,
    readFileImpl,
  });
const collected = await collectWithStats(fakeStats);
assert.equal(evaluateProductionReadiness(collected).ready, true);
assert.equal(collected.nginxVerifyOnCount, 1);
assert.equal(collected.nginxVerifyOffCount, 0);
assert.equal(collected.githubSignerRequired, false);
assert.equal(collected.auditStoreActive, true);
assert.equal(collected.auditStoreHealthReady, true);
const healthProbeFailure = await collectProductionSnapshot({
  command,
  fetchImpl: async () => ({ ok: true }),
  paths: fakePaths,
  pathInfoImpl: async (path) => fakeStats.get(path) ?? null,
  isExecutableImpl: async () => true,
  countPrivateKeysImpl: async () => 0,
  realpathImpl,
  readFileImpl,
  auditStoreHealthImpl: async () => {
    throw new Error('provider detail must not escape');
  },
});
assert.equal(healthProbeFailure.auditStoreHealthReady, false);
assert.equal(evaluateProductionReadiness(healthProbeFailure).ready, false);
const staleStoreProcess = await collectProductionSnapshot({
  command,
  fetchImpl: async () => ({ ok: true }),
  paths: fakePaths,
  pathInfoImpl: async (path) => fakeStats.get(path) ?? null,
  isExecutableImpl: async () => true,
  countPrivateKeysImpl: async () => 0,
  loopbackHealthImpl: async () => true,
  auditStoreHealthImpl: async () => true,
  realpathImpl: async (path) =>
    path === '/proc/3003/exe' ? '/releases/old/bin/secret-broker-audit-store' : realpathImpl(path),
  readFileImpl,
});
assert.equal(staleStoreProcess.auditStoreReleaseBound, false);
assert.equal(evaluateProductionReadiness(staleStoreProcess).ready, false);
const collectStable = (overrides = {}) =>
  collectStableAuditRuntimeSnapshot({
    command,
    realpathImpl,
    readFileImpl,
    paths: fakePaths,
    healthProbe: async () => true,
    ...overrides,
  });
for (const unsafePid of ['', '0', '-1', '1.5', '4194305', '12\n13']) {
  let healthCalls = 0;
  const invalidPid = await collectStable({
    command: (name, args) =>
      args.includes('MainPID') ? { ok: true, stdout: unsafePid } : command(name, args),
    healthProbe: async () => {
      healthCalls += 1;
      return true;
    },
  });
  assert.equal(invalidPid.auditStoreReleaseBound, false);
  assert.equal(invalidPid.auditStoreHealthReady, false);
  assert.equal(healthCalls, 0);
}
const commandFailure = await collectStable({
  command: () => {
    throw new Error('systemctl failed');
  },
});
assert.equal(commandFailure.auditStoreReleaseBound, false);
const deletedExecutable = await collectStable({
  realpathImpl: async () => {
    throw new Error('deleted executable');
  },
});
assert.equal(deletedExecutable.auditStoreReleaseBound, false);

const mismatchedHealthHelper = await collectStable({
  realpathImpl: async (path) =>
    path === fakePaths.auditStoreHealthHelper
      ? '/releases/old/bin/secret-broker-audit-store-health'
      : realpathImpl(path),
});
assert.equal(mismatchedHealthHelper.auditStoreReleaseBound, false);
assert.equal(mismatchedHealthHelper.auditStoreHealthReady, false);

let releaseReads = 0;
const changedRelease = await collectStable({
  realpathImpl: async (path) => {
    if (path === fakePaths.currentRelease) {
      releaseReads += 1;
      return releaseReads === 1 ? '/release' : '/releases/new';
    }
    return realpathImpl(path);
  },
});
assert.equal(changedRelease.auditStoreReleaseBound, false);
assert.equal(changedRelease.auditStoreHealthReady, false);

let storePidReads = 0;
const changedPid = await collectStable({
  command: (name, args) => {
    if (args.includes('secret-broker-audit-store.service') && args.includes('MainPID')) {
      storePidReads += 1;
      return { ok: true, stdout: storePidReads === 1 ? '3003' : '4003' };
    }
    return command(name, args);
  },
  realpathImpl: async (path) => {
    if (path === '/proc/4003/exe') return '/release/bin/secret-broker-audit-store';
    return realpathImpl(path);
  },
  readFileImpl: async (path, encoding) =>
    path === '/proc/4003/stat' ? processStat('4003') : readFileImpl(path, encoding),
});
assert.equal(changedPid.auditStoreReleaseBound, false);
assert.equal(changedPid.auditStoreHealthReady, false);

let storeStatReads = 0;
const reusedPid = await collectStable({
  readFileImpl: async (path, encoding) => {
    if (path === '/proc/3003/stat') {
      storeStatReads += 1;
      return processStat('3003', storeStatReads === 1 ? 13_003 : 23_003);
    }
    return readFileImpl(path, encoding);
  },
});
assert.equal(reusedPid.auditStoreReleaseBound, false);
assert.equal(reusedPid.auditStoreHealthReady, false);

for (const invalidStat of ['', '3003 malformed', processStat('9999'), '3003 (cmd) S 0']) {
  const unreadableProcess = await collectStable({
    readFileImpl: async (path, encoding) =>
      path === '/proc/3003/stat' ? invalidStat : readFileImpl(path, encoding),
  });
  assert.equal(unreadableProcess.auditStoreReleaseBound, false);
  assert.equal(unreadableProcess.auditStoreHealthReady, false);
}

const missingProcessStat = await collectStable({
  readFileImpl: async (path, encoding) => {
    if (path === '/proc/3003/stat') throw new Error('process exited');
    return readFileImpl(path, encoding);
  },
});
assert.equal(missingProcessStat.auditStoreReleaseBound, false);
assert.equal(missingProcessStat.auditStoreHealthReady, false);

let loopbackCompleted = false;
const releaseChangedDuringLoopback = await collectProductionSnapshot({
  command,
  fetchImpl: async () => ({ ok: true }),
  paths: fakePaths,
  pathInfoImpl: async (path) => fakeStats.get(path) ?? null,
  isExecutableImpl: async () => true,
  countPrivateKeysImpl: async () => 0,
  loopbackHealthImpl: async () => {
    loopbackCompleted = true;
    return true;
  },
  auditStoreHealthImpl: async () => true,
  realpathImpl: async (path) => {
    if (loopbackCompleted && path === fakePaths.currentRelease) return '/releases/new';
    return realpathImpl(path);
  },
  readFileImpl,
});
assert.equal(releaseChangedDuringLoopback.loopbackHealth, true);
assert.equal(releaseChangedDuringLoopback.auditStoreReleaseBound, false);
assert.equal(evaluateProductionReadiness(releaseChangedDuringLoopback).ready, false);
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

const readyStoreHealth =
  '{"status":"ready","lock_contract":"verified","mirror_state":"in_sync","common_sequence":7,"reason_code":"ok"}';
assert.equal(parseAuditStoreHealth(readyStoreHealth), true);
for (const invalid of [
  '',
  'not-json',
  'null',
  '[]',
  '{"status":"ready"}',
  readyStoreHealth.replace('"verified"', '"unverified"'),
  readyStoreHealth.replace('"in_sync"', '"lagging"'),
  readyStoreHealth.replace('"ok"', '"other"'),
  readyStoreHealth.replace('"common_sequence":7', '"common_sequence":-1'),
  readyStoreHealth.replace('"common_sequence":7', '"common_sequence":1.5'),
  readyStoreHealth.slice(0, -1) + ',"extra":true}',
  ' '.repeat(1025),
]) {
  assert.equal(parseAuditStoreHealth(invalid), false, 'invalid store health must fail closed');
}

console.log('production preflight: 22 fail-closed deployment gates passed');
