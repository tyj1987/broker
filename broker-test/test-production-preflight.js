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
  policyUser: 'broker-core',
  policyGroup: 'broker',
  isolatedRuntimeIdentities: true,
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
  providerSignersReady: true,
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

const signerNotReady = evaluateProductionReadiness({
  ...readySnapshot,
  providerSignersReady: false,
});
assert.equal(signerNotReady.ready, false);

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
  ['providerSignersReady', false],
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
  nodeRuntime: '/runtime/node',
  policyExecutable: '/release/bin/secret-broker-policy',
  deployHelper: '/helper',
  controlPlaneState: '/state',
  controlPlaneStateKey: '/state-key',
  policySocket: '/policy.sock',
  providerSigners: {
    github: {
      directory: '/github-signer',
      socket: '/github-signer/signer.sock',
      executable: '/release/bin/secret-broker-github-signer',
    },
    aliyun: {
      directory: '/aliyun-signer',
      socket: '/aliyun-signer/signer.sock',
      executable: '/release/bin/secret-broker-aliyun-signer',
    },
  },
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
    '/github-signer',
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, gid: 1101, mode: 0o040750 },
  ],
  [
    '/github-signer/signer.sock',
    { isSocket: () => true, isSymbolicLink: () => false, uid: 0, gid: 1101, mode: 0o140660 },
  ],
  [
    '/aliyun-signer',
    { isDirectory: () => true, isSymbolicLink: () => false, uid: 0, gid: 1102, mode: 0o040750 },
  ],
  [
    '/aliyun-signer/signer.sock',
    { isSocket: () => true, isSymbolicLink: () => false, uid: 0, gid: 1102, mode: 0o140660 },
  ],
]);
const identityIds = Object.freeze({
  broker: Object.freeze({ uid: 1001, gid: 1002 }),
  'broker-core': Object.freeze({ uid: 1003, gid: 1002 }),
  'broker-audit-signer': Object.freeze({ uid: 2201, gid: 1201 }),
  'broker-audit-exporter': Object.freeze({ uid: 2202, gid: 1202 }),
  'broker-audit-store': Object.freeze({ uid: 2203, gid: 1203 }),
  'broker-audit-recovery': Object.freeze({ uid: 2204, gid: 1204 }),
  'broker-github-signer': Object.freeze({ uid: 2101, gid: 1101 }),
  'broker-aliyun-signer': Object.freeze({ uid: 2102, gid: 1102 }),
  'broker-deploy': Object.freeze({ uid: 2301, gid: 1301 }),
});
const command = (name, args) => {
  const invocation = `${name} ${args.join(' ')}`;
  for (const [index, service] of ['signer', 'exporter', 'store', 'recovery'].entries()) {
    if (invocation.includes(`secret-broker-audit-${service}.service`)) {
      if (invocation.includes('-p User')) return { ok: true, stdout: `broker-audit-${service}` };
      if (invocation.includes('-p Group')) return { ok: true, stdout: `broker-audit-${service}` };
      if (invocation.includes('-p MainPID')) return { ok: true, stdout: String(3001 + index) };
    }
  }
  for (const [index, signer] of ['github', 'aliyun'].entries()) {
    if (invocation.includes(`secret-broker-${signer}-signer.service`)) {
      if (invocation.includes('-p User')) return { ok: true, stdout: `broker-${signer}-signer` };
      if (invocation.includes('-p Group')) return { ok: true, stdout: `broker-${signer}-signer` };
      if (invocation.includes('-p MainPID')) return { ok: true, stdout: String(5001 + index) };
    }
    if (
      invocation.includes(`secret-broker-${signer}-signer.socket`) &&
      invocation.includes('-p Listen')
    ) {
      return { ok: true, stdout: `${fakePaths.providerSigners[signer].socket} (Stream)` };
    }
    if (
      invocation.includes(`secret-broker-${signer}-signer.socket`) &&
      invocation.includes('-p Triggers')
    ) {
      return { ok: true, stdout: `secret-broker-${signer}-signer.service` };
    }
  }
  if (invocation.includes('secret-broker-policy.service')) {
    if (invocation.includes('-p User')) return { ok: true, stdout: 'broker-core' };
    if (invocation.includes('-p Group')) return { ok: true, stdout: 'broker' };
    if (invocation.includes('-p MainPID')) return { ok: true, stdout: '7002' };
  }
  if (args.includes('secret-broker.service') && invocation.includes('-p MainPID')) {
    return { ok: true, stdout: '7001' };
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
  if (name === 'id' && (args[0] === '-u' || args[0] === '-g') && identityIds[args[1]]) {
    return {
      ok: true,
      stdout: String(args[0] === '-u' ? identityIds[args[1]].uid : identityIds[args[1]].gid),
    };
  }
  if (name === 'id' && args[0] === '-G') return { ok: true, stdout: '1001 1002 1101 1102' };
  if (name === 'getent' && args[0] === 'group' && identityIds[args[1]]) {
    return { ok: true, stdout: `${args[1]}:x:${identityIds[args[1]].gid}:` };
  }
  if (name === 'getent' && args[0] === 'passwd' && args[1] === 'broker-deploy') {
    return { ok: true, stdout: 'broker-deploy:x:2301:1301::/nonexistent:/bin/bash' };
  }
  return {
    ok: true,
    stdout: '',
  };
};
const executableByPid = new Map([
  ['3001', '/release/bin/secret-broker-audit-signer'],
  ['3002', '/release/bin/secret-broker-audit-exporter'],
  ['3003', '/release/bin/secret-broker-audit-store'],
  ['3004', '/release/bin/secret-broker-audit-recovery'],
  ['5001', '/release/bin/secret-broker-github-signer'],
  ['5002', '/release/bin/secret-broker-aliyun-signer'],
]);
const processStat = (pid, startTime = Number(pid) + 10_000) =>
  `${pid} (secret-broker-audit) S ${Array(18).fill('0').join(' ')} ${startTime} 0`;
const readFileImpl = async (path) => {
  const pid = /^\/proc\/([1-9][0-9]*)\/stat$/u.exec(path)?.[1];
  if (pid && (executableByPid.has(pid) || pid === '7001' || pid === '7002')) {
    return processStat(pid);
  }
  const statusPid = /^\/proc\/([1-9][0-9]*)\/status$/u.exec(path)?.[1];
  if (statusPid === '5001')
    return 'Name:\tgithub-signer\nUid:\t2101\t2101\t2101\t2101\nGid:\t1101\t1101\t1101\t1101\nGroups:\t1101\n';
  if (statusPid === '5002')
    return 'Name:\taliyun-signer\nUid:\t2102\t2102\t2102\t2102\nGid:\t1102\t1102\t1102\t1102\nGroups:\t1102\n';
  if (statusPid === '7001')
    return 'Name:\tbroker\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002 1101 1102\n';
  if (statusPid === '7002')
    return 'Name:\tpolicy\nUid:\t1003\t1003\t1003\t1003\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002\n';
  if (path === '/proc/7001/cmdline') return '/runtime/node\0/release/server.js\0';
  const auditIndex = Number(statusPid) - 3001;
  if (auditIndex >= 0 && auditIndex < 4) {
    const uid = 2201 + auditIndex;
    const gid = 1201 + auditIndex;
    const groups =
      auditIndex === 1 ? `${gid} 1201 1203` : auditIndex === 3 ? `${gid} 1203` : String(gid);
    return `Name:\taudit\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\nGid:\t${gid}\t${gid}\t${gid}\t${gid}\nGroups:\t${groups}\n`;
  }
  throw new Error('unexpected read');
};
const realpathImpl = async (path) => {
  const pid = /^\/proc\/([1-9][0-9]*)\/exe$/u.exec(path)?.[1];
  if (pid === '7001') return '/runtime/node';
  if (pid === '7002') return '/release/bin/secret-broker-policy';
  if (pid) return executableByPid.get(pid) ?? Promise.reject(new Error('missing process'));
  if (path === '/proc/7001/cwd') return '/release';
  if (path === fakePaths.nodeRuntime || path === fakePaths.policyExecutable) return path;
  if (path === fakePaths.currentRelease) return path;
  if (path === fakePaths.auditStoreHealthHelper) return path;
  if (Object.values(fakePaths.auditExecutables).includes(path)) return path;
  if (Object.values(fakePaths.providerSigners).some((signer) => signer.executable === path)) {
    return path;
  }
  throw new Error('unexpected realpath');
};
const collectWithOverrides = (overrides = {}) =>
  collectProductionSnapshot({
    command,
    paths: fakePaths,
    pathInfoImpl: async (path) => fakeStats.get(path) ?? null,
    isExecutableImpl: async () => true,
    countPrivateKeysImpl: async () => 0,
    loopbackHealthImpl: async () => true,
    realpathImpl,
    readFileImpl,
    providerContractEvidenceImpl: async () => true,
    ...overrides,
  });
const collectWithStats = (stats) =>
  collectWithOverrides({ pathInfoImpl: async (path) => stats.get(path) ?? null });
const collected = await collectWithStats(fakeStats);
assert.equal(evaluateProductionReadiness(collected).ready, true);
assert.equal(collected.nginxVerifyOnCount, 1);
assert.equal(collected.nginxVerifyOffCount, 0);
assert.equal(collected.providerSignersReady, true);
assert.equal(collected.isolatedRuntimeIdentities, true);
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
  ['/github-signer', { ...fakeStats.get('/github-signer'), gid: 9999 }],
  ['/github-signer', { ...fakeStats.get('/github-signer'), mode: 0o040740 }],
  ['/github-signer/signer.sock', { ...fakeStats.get('/github-signer/signer.sock'), uid: 2002 }],
  ['/github-signer/signer.sock', { ...fakeStats.get('/github-signer/signer.sock'), gid: 9999 }],
  [
    '/github-signer/signer.sock',
    { ...fakeStats.get('/github-signer/signer.sock'), mode: 0o140640 },
  ],
  ['/aliyun-signer', { ...fakeStats.get('/aliyun-signer'), uid: 2101 }],
  [
    '/aliyun-signer/signer.sock',
    { ...fakeStats.get('/aliyun-signer/signer.sock'), mode: 0o140666 },
  ],
]) {
  const unsafeStats = new Map(fakeStats);
  unsafeStats.set(path, replacement);
  const unsafe = await collectWithStats(unsafeStats);
  assert.equal(unsafe.providerSignersReady, false, `${path} boundary must fail closed`);
}

for (const commandOverride of [
  (name, args) =>
    args.includes('secret-broker-github-signer.service') && args.includes('is-active')
      ? { ok: false, stdout: '' }
      : command(name, args),
  (name, args) =>
    args.includes('secret-broker-aliyun-signer.service') && args.includes('User')
      ? { ok: true, stdout: 'broker-github-signer' }
      : command(name, args),
  (name, args) =>
    args.includes('secret-broker-aliyun-signer.service') && args.includes('Group')
      ? { ok: true, stdout: 'broker-github-signer' }
      : command(name, args),
  (name, args) =>
    name === 'id' && args[0] === '-u' && args[1] === 'broker-aliyun-signer'
      ? { ok: true, stdout: '1001' }
      : command(name, args),
  (name, args) =>
    name === 'id' && args[0] === '-g' && args[1] === 'broker-aliyun-signer'
      ? { ok: true, stdout: '1101' }
      : command(name, args),
  (name, args) =>
    name === 'id' && args[0] === '-u' && args[1] === 'broker-aliyun-signer'
      ? { ok: true, stdout: '' }
      : command(name, args),
  (name, args) =>
    name === 'id' && args[0] === '-g' && args[1] === 'broker-aliyun-signer'
      ? { ok: true, stdout: '0' }
      : command(name, args),
  (name, args) =>
    name === 'id' && args[0] === '-G' && args[1] === 'broker'
      ? { ok: true, stdout: '1001 1101 malformed' }
      : command(name, args),
  (name, args) =>
    args.includes('secret-broker-aliyun-signer.socket') && args.includes('Listen')
      ? { ok: true, stdout: '/run/untrusted.sock (Stream)' }
      : command(name, args),
]) {
  const unsafe = await collectWithOverrides({ command: commandOverride });
  assert.equal(unsafe.providerSignersReady, false, 'signer identity boundary must fail closed');
}

const staleProviderSigner = await collectWithOverrides({
  realpathImpl: async (path) =>
    path === '/proc/5002/exe'
      ? '/releases/old/bin/secret-broker-aliyun-signer'
      : realpathImpl(path),
});
assert.equal(staleProviderSigner.providerSignersReady, false);

const wrongProviderProcessIdentity = await collectWithOverrides({
  readFileImpl: async (path, encoding) =>
    path === '/proc/5002/status'
      ? 'Name:\taliyun-signer\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t1102\n'
      : readFileImpl(path, encoding),
});
assert.equal(wrongProviderProcessIdentity.providerSignersReady, false);

let githubSignerPidReads = 0;
const replacedProviderSigner = await collectWithOverrides({
  command: (name, args) => {
    if (args.includes('secret-broker-github-signer.service') && args.includes('MainPID')) {
      githubSignerPidReads += 1;
      return { ok: true, stdout: githubSignerPidReads === 1 ? '5001' : '6001' };
    }
    return command(name, args);
  },
  realpathImpl: async (path) =>
    path === '/proc/6001/exe' ? '/release/bin/secret-broker-github-signer' : realpathImpl(path),
  readFileImpl: async (path, encoding) =>
    path === '/proc/6001/stat'
      ? processStat('6001')
      : path === '/proc/6001/status'
        ? 'Name:\tgithub-signer\nUid:\t2101\t2101\t2101\t2101\nGid:\t1101\t1101\t1101\t1101\nGroups:\t1101\n'
        : readFileImpl(path, encoding),
});
assert.equal(replacedProviderSigner.providerSignersReady, false);

for (const brokerUidOutput of ['', 'malformed', '0']) {
  const invalidBrokerIdentity = await collectWithOverrides({
    command: (name, args) =>
      name === 'id' && args[0] === '-u' && args[1] === 'broker'
        ? { ok: true, stdout: brokerUidOutput }
        : command(name, args),
  });
  assert.equal(invalidBrokerIdentity.providerSignersReady, false);
}

const finalStats = new Map(fakeStats);
const endpointChangedDuringProbe = await collectWithOverrides({
  loopbackHealthImpl: async () => {
    finalStats.set('/github-signer/signer.sock', {
      ...fakeStats.get('/github-signer/signer.sock'),
      mode: 0o140666,
    });
    return true;
  },
  pathInfoImpl: async (path) => finalStats.get(path) ?? null,
});
assert.equal(endpointChangedDuringProbe.providerSignersReady, false);

const missingProviderContractEvidence = await collectWithOverrides({
  providerContractEvidenceImpl: undefined,
});
assert.equal(missingProviderContractEvidence.providerSignersReady, false);

for (const [description, overrides] of [
  [
    'broker executable outside the pinned runtime',
    {
      realpathImpl: async (path) =>
        path === '/proc/7001/exe' ? '/usr/bin/node' : realpathImpl(path),
    },
  ],
  [
    'broker working directory outside the active release',
    {
      realpathImpl: async (path) =>
        path === '/proc/7001/cwd' ? '/releases/old' : realpathImpl(path),
    },
  ],
  [
    'broker command line outside the active release',
    {
      readFileImpl: async (path, encoding) =>
        path === '/proc/7001/cmdline'
          ? '/runtime/node\0/releases/old/server.js\0'
          : readFileImpl(path, encoding),
    },
  ],
  [
    'broker command line with an unexpected argument',
    {
      readFileImpl: async (path, encoding) =>
        path === '/proc/7001/cmdline'
          ? '/runtime/node\0/release/server.js\0--inspect\0'
          : readFileImpl(path, encoding),
    },
  ],
  [
    'broker command line above the bounded read contract',
    {
      readFileImpl: async (path, encoding) =>
        path === '/proc/7001/cmdline' ? 'x'.repeat(1025) : readFileImpl(path, encoding),
    },
  ],
  [
    'policy executable outside the active release',
    {
      realpathImpl: async (path) =>
        path === '/proc/7002/exe' ? '/releases/old/bin/secret-broker-policy' : realpathImpl(path),
    },
  ],
]) {
  const staleWorkload = await collectWithOverrides(overrides);
  assert.equal(staleWorkload.providerSignersReady, false, `${description} must fail closed`);
  assert.equal(evaluateProductionReadiness(staleWorkload).ready, false);
}

let brokerPidReads = 0;
const replacedBrokerProcess = await collectWithOverrides({
  command: (name, args) => {
    if (args.includes('secret-broker.service') && args.includes('MainPID')) {
      brokerPidReads += 1;
      return { ok: true, stdout: brokerPidReads === 1 ? '7001' : '8001' };
    }
    return command(name, args);
  },
  realpathImpl: async (path) => {
    if (path === '/proc/8001/exe') return '/runtime/node';
    if (path === '/proc/8001/cwd') return '/release';
    return realpathImpl(path);
  },
  readFileImpl: async (path, encoding) => {
    if (path === '/proc/8001/stat') return processStat('8001');
    if (path === '/proc/8001/status') {
      return 'Name:\tbroker\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002 1101 1102\n';
    }
    if (path === '/proc/8001/cmdline') return '/runtime/node\0/release/server.js\0';
    return readFileImpl(path, encoding);
  },
});
assert.equal(replacedBrokerProcess.providerSignersReady, false);
assert.equal(evaluateProductionReadiness(replacedBrokerProcess).ready, false);

const policyUidCollision = await collectWithOverrides({
  command: (name, args) =>
    name === 'id' && args[0] === '-u' && args[1] === 'broker-core'
      ? { ok: true, stdout: '1001' }
      : command(name, args),
});
assert.equal(policyUidCollision.isolatedRuntimeIdentities, false);
assert.equal(evaluateProductionReadiness(policyUidCollision).ready, false);

const auditProviderGidCollision = await collectWithOverrides({
  command: (name, args) => {
    if (name === 'id' && args[0] === '-g' && args[1] === 'broker-audit-signer') {
      return { ok: true, stdout: '1101' };
    }
    if (name === 'getent' && args[0] === 'group' && args[1] === 'broker-audit-signer') {
      return { ok: true, stdout: 'broker-audit-signer:x:1101:' };
    }
    return command(name, args);
  },
  readFileImpl: async (path, encoding) =>
    path === '/proc/3001/status'
      ? 'Name:\taudit\nUid:\t2201\t2201\t2201\t2201\nGid:\t1101\t1101\t1101\t1101\nGroups:\t1101\n'
      : readFileImpl(path, encoding),
});
assert.equal(auditProviderGidCollision.isolatedRuntimeIdentities, false);
assert.equal(evaluateProductionReadiness(auditProviderGidCollision).ready, false);

for (const [statusPath, unsafeStatus] of [
  [
    '/proc/5001/status',
    'Name:\tgithub-signer\nUid:\t2101\t2101\t2101\t2101\nGid:\t1101\t1101\t1101\t1101\nGroups:\t1101 1201\n',
  ],
  [
    '/proc/5002/status',
    'Name:\taliyun-signer\nUid:\t2102\t2102\t2102\t2102\nGid:\t1102\t1102\t1102\t1102\nGroups:\t1102 1201\n',
  ],
  [
    '/proc/3001/status',
    'Name:\taudit\nUid:\t2201\t2201\t2201\t2201\nGid:\t1201\t1201\t1201\t1201\nGroups:\t1201 1101\n',
  ],
  [
    '/proc/3002/status',
    'Name:\taudit\nUid:\t2202\t2202\t2202\t2202\nGid:\t1202\t1202\t1202\t1202\nGroups:\t1202 1201 1203 1101\n',
  ],
  [
    '/proc/3003/status',
    'Name:\taudit\nUid:\t2203\t2203\t2203\t2203\nGid:\t1203\t1203\t1203\t1203\nGroups:\t1203 1101\n',
  ],
  [
    '/proc/3004/status',
    'Name:\taudit\nUid:\t2204\t2204\t2204\t2204\nGid:\t1204\t1204\t1204\t1204\nGroups:\t1204 1203 1101\n',
  ],
  [
    '/proc/7001/status',
    'Name:\tbroker\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002 1101 1102 1201\n',
  ],
  [
    '/proc/7002/status',
    'Name:\tpolicy\nUid:\t1003\t1003\t1003\t1003\nGid:\t1002\t1002\t1002\t1002\nGroups:\t1002 1101\n',
  ],
]) {
  const excessiveGroups = await collectWithOverrides({
    readFileImpl: async (path, encoding) =>
      path === statusPath ? unsafeStatus : readFileImpl(path, encoding),
  });
  assert.equal(
    evaluateProductionReadiness(excessiveGroups).ready,
    false,
    `${statusPath} unauthorized supplementary group must fail closed`,
  );
}

for (const [statusPath, incompleteStatus] of [
  [
    '/proc/3002/status',
    'Name:\taudit\nUid:\t2202\t2202\t2202\t2202\nGid:\t1202\t1202\t1202\t1202\nGroups:\t1202 1201\n',
  ],
  [
    '/proc/3004/status',
    'Name:\taudit\nUid:\t2204\t2204\t2204\t2204\nGid:\t1204\t1204\t1204\t1204\nGroups:\t1204\n',
  ],
]) {
  const missingRequiredGroup = await collectWithOverrides({
    readFileImpl: async (path, encoding) =>
      path === statusPath ? incompleteStatus : readFileImpl(path, encoding),
  });
  assert.equal(
    evaluateProductionReadiness(missingRequiredGroup).ready,
    false,
    `${statusPath} missing required supplementary group must fail closed`,
  );
}

const deploySignerUidCollision = await collectWithOverrides({
  command: (name, args) =>
    name === 'getent' && args[0] === 'passwd' && args[1] === 'broker-deploy'
      ? { ok: true, stdout: 'broker-deploy:x:2101:1301::/nonexistent:/bin/bash' }
      : command(name, args),
});
assert.equal(deploySignerUidCollision.isolatedRuntimeIdentities, false);
assert.equal(evaluateProductionReadiness(deploySignerUidCollision).ready, false);
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
