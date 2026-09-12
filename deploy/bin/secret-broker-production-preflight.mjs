#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs';
import { access, lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { posix as path } from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_PATHS = Object.freeze({
  currentRelease: '/opt/secret-broker/broker',
  deployHelper: '/usr/local/sbin/secret-broker-deploy',
  controlPlaneState: '/var/lib/secret-broker/control-plane-state.enc',
  controlPlaneStateKey: '/etc/secret-broker/control-plane-state.key',
  policySocket: '/run/secret-broker/core.sock',
  githubSignerDirectory: '/run/secret-broker-signer',
  githubSignerSocket: '/run/secret-broker-signer/github.sock',
  auditStoreHealthHelper: '/opt/secret-broker/broker/bin/secret-broker-audit-store-health',
  auditStoreSocket: '/run/secret-broker-audit-store/store.sock',
  auditExecutables: Object.freeze({
    signer: '/opt/secret-broker/broker/bin/secret-broker-audit-signer',
    exporter: '/opt/secret-broker/broker/bin/secret-broker-audit-exporter',
    store: '/opt/secret-broker/broker/bin/secret-broker-audit-store',
    recovery: '/opt/secret-broker/broker/bin/secret-broker-audit-recovery',
  }),
  forbiddenKeyRoots: [
    '/etc/secret-broker/pki/ca',
    '/etc/secret-broker/pki/clients',
    '/opt/secret-broker/pki',
  ],
});

const AUDIT_IDENTITIES = Object.freeze({
  signer: Object.freeze({ user: 'broker-audit-signer', group: 'broker-audit-signer' }),
  exporter: Object.freeze({ user: 'broker-audit-exporter', group: 'broker-audit-exporter' }),
  store: Object.freeze({ user: 'broker-audit-store', group: 'broker-audit-store' }),
  recovery: Object.freeze({ user: 'broker-audit-recovery', group: 'broker-audit-recovery' }),
});
const AUDIT_SERVICES = Object.freeze(['signer', 'exporter', 'store', 'recovery']);

function exactAuditIdentity(snapshot, service) {
  const expected = AUDIT_IDENTITIES[service];
  const prefix = `audit${service[0].toUpperCase()}${service.slice(1)}`;
  const users = Object.keys(AUDIT_IDENTITIES).map((name) => {
    const key = `audit${name[0].toUpperCase()}${name.slice(1)}User`;
    return snapshot[key];
  });
  return (
    snapshot[`${prefix}User`] === expected.user &&
    snapshot[`${prefix}Group`] === expected.group &&
    new Set(users).size === users.length &&
    !users.includes('broker') &&
    !users.includes('root')
  );
}

const CHECKS = Object.freeze([
  ['broker_user', (snapshot) => snapshot.brokerUser === 'broker'],
  ['broker_group', (snapshot) => snapshot.brokerGroup === 'broker'],
  ['broker_active', (snapshot) => snapshot.brokerActive === true],
  ['policy_core_active', (snapshot) => snapshot.policyActive === true],
  ['managed_release_symlink', (snapshot) => snapshot.managedReleaseSymlink === true],
  ['deploy_helper_executable', (snapshot) => snapshot.deployHelperExecutable === true],
  ['deploy_account_present', (snapshot) => snapshot.deployAccountPresent === true],
  ['nginx_config_valid', (snapshot) => snapshot.nginxConfigValid === true],
  ['nginx_upstream_verification_enabled', (snapshot) => snapshot.nginxVerifyOnCount > 0],
  ['nginx_upstream_verification_never_disabled', (snapshot) => snapshot.nginxVerifyOffCount === 0],
  ['offline_private_key_boundary', (snapshot) => snapshot.forbiddenPrivateKeyCount === 0],
  ['control_plane_state_present', (snapshot) => snapshot.controlPlaneStatePresent === true],
  [
    'control_plane_state_key_protected',
    (snapshot) => snapshot.controlPlaneStateKeyProtected === true,
  ],
  ['policy_socket_protected', (snapshot) => snapshot.policySocketProtected === true],
  [
    'github_signer_socket_protected',
    (snapshot) =>
      snapshot.githubSignerRequired !== true || snapshot.githubSignerSocketProtected === true,
  ],
  [
    'audit_exporter_signer_active',
    (snapshot) =>
      snapshot.auditExporterActive === true &&
      snapshot.auditSignerActive === true &&
      snapshot.auditExporterReleaseBound === true &&
      snapshot.auditSignerReleaseBound === true,
  ],
  [
    'audit_exporter_signer_independent_identities',
    (snapshot) =>
      exactAuditIdentity(snapshot, 'exporter') && exactAuditIdentity(snapshot, 'signer'),
  ],
  [
    'audit_store_lock_ready',
    (snapshot) =>
      snapshot.auditStoreActive === true &&
      snapshot.auditStoreReleaseBound === true &&
      snapshot.auditStoreHealthReady === true,
  ],
  ['audit_store_independent_identity', (snapshot) => exactAuditIdentity(snapshot, 'store')],
  [
    'audit_recovery_authority_active',
    (snapshot) =>
      snapshot.auditRecoveryAuthorityActive === true && snapshot.auditRecoveryReleaseBound === true,
  ],
  ['audit_recovery_independent_identity', (snapshot) => exactAuditIdentity(snapshot, 'recovery')],
  ['loopback_health', (snapshot) => snapshot.loopbackHealth === true],
]);

function commandResult(command, args = []) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    shell: false,
    timeout: 10_000,
    windowsHide: true,
  });
  return {
    ok: result.status === 0,
    stdout: result.stdout?.trim() ?? '',
  };
}

async function pathInfo(path) {
  try {
    return await lstat(path);
  } catch {
    return null;
  }
}

async function isExecutable(path) {
  try {
    await access(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function countPrivateKeys(path) {
  let entries;
  try {
    entries = await readdir(path, { withFileTypes: true });
  } catch (error) {
    return error?.code === 'ENOENT' ? 0 : 1;
  }

  let count = 0;
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      count += 1;
      continue;
    }
    const child = `${path}/${entry.name}`;
    if (entry.isDirectory()) count += await countPrivateKeys(child);
    if (entry.isFile() && entry.name.endsWith('.key')) count += 1;
  }
  return count;
}

async function loopbackHealth(fetchImpl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetchImpl('http://127.0.0.1:9080/health', {
      signal: controller.signal,
      redirect: 'error',
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export function parseAuditStoreHealth(stdout) {
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout, 'utf8') > 1024) return false;
  let value;
  try {
    value = JSON.parse(stdout);
  } catch {
    return false;
  }
  if (value === null || Array.isArray(value) || typeof value !== 'object') return false;
  const expectedKeys = new Set([
    'status',
    'lock_contract',
    'mirror_state',
    'common_sequence',
    'reason_code',
  ]);
  const keys = Object.keys(value);
  return (
    keys.length === expectedKeys.size &&
    keys.every((key) => expectedKeys.has(key)) &&
    value.status === 'ready' &&
    value.lock_contract === 'verified' &&
    value.mirror_state === 'in_sync' &&
    Number.isSafeInteger(value.common_sequence) &&
    value.common_sequence >= 0 &&
    value.reason_code === 'ok'
  );
}

function auditStoreHealth(command, paths) {
  const result = command('/usr/sbin/runuser', [
    '--user',
    AUDIT_IDENTITIES.recovery.user,
    '--',
    '/usr/bin/env',
    '-i',
    'PATH=/usr/bin:/bin',
    paths.auditStoreHealthHelper,
    '--socket',
    paths.auditStoreSocket,
  ]);
  return result.ok && parseAuditStoreHealth(result.stdout);
}

function emptyAuditRuntimeSnapshot() {
  return {
    auditSignerReleaseBound: false,
    auditExporterReleaseBound: false,
    auditStoreReleaseBound: false,
    auditRecoveryReleaseBound: false,
    auditStoreHealthReady: false,
  };
}

function processStartTime(stat, pid) {
  if (typeof stat !== 'string' || !stat.startsWith(`${pid} (`)) return null;
  const commandEnd = stat.lastIndexOf(')');
  if (commandEnd < 3) return null;
  const fields = stat
    .slice(commandEnd + 1)
    .trim()
    .split(/\s+/u);
  const startTime = fields[19];
  return /^[1-9][0-9]*$/u.test(startTime ?? '') ? startTime : null;
}

async function auditProcessSample(command, realpathImpl, readFileImpl, paths, release, service) {
  const executables = paths?.auditExecutables;
  if (
    typeof command !== 'function' ||
    typeof realpathImpl !== 'function' ||
    typeof readFileImpl !== 'function' ||
    !Object.hasOwn(AUDIT_IDENTITIES, service) ||
    executables === null ||
    typeof executables !== 'object' ||
    !Object.hasOwn(executables, service) ||
    typeof executables[service] !== 'string' ||
    executables[service].length === 0
  ) {
    return null;
  }
  let result;
  try {
    result = command('systemctl', [
      'show',
      `secret-broker-audit-${service}.service`,
      '-p',
      'MainPID',
      '--value',
    ]);
  } catch {
    return null;
  }
  if (
    !result?.ok ||
    typeof result.stdout !== 'string' ||
    !/^[1-9][0-9]{0,9}$/u.test(result.stdout)
  ) {
    return null;
  }
  const pid = Number(result.stdout);
  if (!Number.isSafeInteger(pid) || pid > 4_194_304) return null;
  try {
    const [expectedExecutable, runningExecutable, stat] = await Promise.all([
      realpathImpl(executables[service]),
      realpathImpl(`/proc/${pid}/exe`),
      readFileImpl(`/proc/${pid}/stat`, 'utf8'),
    ]);
    const startTime = processStartTime(stat, pid);
    const releaseExecutable = path.join(release, 'bin', path.basename(executables[service]));
    if (
      startTime === null ||
      expectedExecutable !== releaseExecutable ||
      runningExecutable !== expectedExecutable
    ) {
      return null;
    }
    return { pid, startTime, executable: runningExecutable };
  } catch {
    return null;
  }
}

function sameAuditProcess(left, right) {
  return (
    left !== null &&
    right !== null &&
    left.pid === right.pid &&
    left.startTime === right.startTime &&
    left.executable === right.executable
  );
}

export async function collectStableAuditRuntimeSnapshot({
  command,
  realpathImpl,
  readFileImpl,
  paths,
  healthProbe,
}) {
  const rejected = emptyAuditRuntimeSnapshot();
  if (typeof healthProbe !== 'function' || typeof paths?.currentRelease !== 'string') {
    return rejected;
  }
  try {
    const release = await realpathImpl(paths.currentRelease);
    if (typeof release !== 'string' || !release.startsWith('/')) return rejected;
    const healthHelper = path.join(
      release,
      'bin',
      path.basename(paths.auditStoreHealthHelper ?? ''),
    );
    if ((await realpathImpl(paths.auditStoreHealthHelper)) !== healthHelper) return rejected;
    const before = await Promise.all(
      AUDIT_SERVICES.map((service) =>
        auditProcessSample(command, realpathImpl, readFileImpl, paths, release, service),
      ),
    );
    if (before.some((sample) => sample === null)) return rejected;
    const auditStoreHealthReady = (await healthProbe(release)) === true;
    const after = await Promise.all(
      AUDIT_SERVICES.map((service) =>
        auditProcessSample(command, realpathImpl, readFileImpl, paths, release, service),
      ),
    );
    if (after.some((sample) => sample === null)) return rejected;
    const finalRelease = await realpathImpl(paths.currentRelease);
    if (
      release !== finalRelease ||
      before.some((sample, index) => !sameAuditProcess(sample, after[index]))
    ) {
      return rejected;
    }
    return {
      auditSignerReleaseBound: true,
      auditExporterReleaseBound: true,
      auditStoreReleaseBound: true,
      auditRecoveryReleaseBound: true,
      auditStoreHealthReady,
    };
  } catch {
    return rejected;
  }
}

export function evaluateProductionReadiness(snapshot) {
  const checks = CHECKS.map(([name, predicate]) => ({
    name,
    passed: Boolean(predicate(snapshot)),
  }));
  return {
    ready: checks.every((check) => check.passed),
    checks,
  };
}

export function renderProductionReadiness(result) {
  const lines = result.checks.map((check) => `${check.name}=${check.passed ? 'pass' : 'fail'}`);
  lines.push(`production_cd_ready=${result.ready ? 'yes' : 'no'}`);
  return `${lines.join('\n')}\n`;
}

export async function collectProductionSnapshot({
  command = commandResult,
  fetchImpl = globalThis.fetch,
  paths = DEFAULT_PATHS,
  pathInfoImpl = pathInfo,
  isExecutableImpl = isExecutable,
  countPrivateKeysImpl = countPrivateKeys,
  loopbackHealthImpl = loopbackHealth,
  auditStoreHealthImpl = auditStoreHealth,
  realpathImpl = realpath,
  readFileImpl = readFile,
  githubSignerRequired = process.env.BROKER_REQUIRE_GITHUB_SIGNER === '1',
} = {}) {
  const brokerUser = command('systemctl', [
    'show',
    'secret-broker.service',
    '-p',
    'User',
    '--value',
  ]);
  const brokerGroup = command('systemctl', [
    'show',
    'secret-broker.service',
    '-p',
    'Group',
    '--value',
  ]);
  const brokerActive = command('systemctl', ['is-active', '--quiet', 'secret-broker.service']);
  const policyActive = command('systemctl', [
    'is-active',
    '--quiet',
    'secret-broker-policy.service',
  ]);
  const auditSignerActive = command('systemctl', [
    'is-active',
    '--quiet',
    'secret-broker-audit-signer.service',
  ]);
  const auditExporterActive = command('systemctl', [
    'is-active',
    '--quiet',
    'secret-broker-audit-exporter.service',
  ]);
  const auditStoreActive = command('systemctl', [
    'is-active',
    '--quiet',
    'secret-broker-audit-store.service',
  ]);
  const auditRecoveryAuthorityActive = command('systemctl', [
    'is-active',
    '--quiet',
    'secret-broker-audit-recovery.service',
  ]);
  const auditSignerUser = command('systemctl', [
    'show',
    'secret-broker-audit-signer.service',
    '-p',
    'User',
    '--value',
  ]);
  const auditExporterUser = command('systemctl', [
    'show',
    'secret-broker-audit-exporter.service',
    '-p',
    'User',
    '--value',
  ]);
  const auditStoreUser = command('systemctl', [
    'show',
    'secret-broker-audit-store.service',
    '-p',
    'User',
    '--value',
  ]);
  const auditRecoveryUser = command('systemctl', [
    'show',
    'secret-broker-audit-recovery.service',
    '-p',
    'User',
    '--value',
  ]);
  const auditSignerGroup = command('systemctl', [
    'show',
    'secret-broker-audit-signer.service',
    '-p',
    'Group',
    '--value',
  ]);
  const auditExporterGroup = command('systemctl', [
    'show',
    'secret-broker-audit-exporter.service',
    '-p',
    'Group',
    '--value',
  ]);
  const auditStoreGroup = command('systemctl', [
    'show',
    'secret-broker-audit-store.service',
    '-p',
    'Group',
    '--value',
  ]);
  const auditRecoveryGroup = command('systemctl', [
    'show',
    'secret-broker-audit-recovery.service',
    '-p',
    'Group',
    '--value',
  ]);
  const deployAccount = command('getent', ['passwd', 'broker-deploy']);
  const nginx = command('nginx', ['-T']);
  const release = await pathInfoImpl(paths.currentRelease);
  const state = await pathInfoImpl(paths.controlPlaneState);
  const stateKey = await pathInfoImpl(paths.controlPlaneStateKey);
  const policySocket = await pathInfoImpl(paths.policySocket);
  const githubSignerDirectory = await pathInfoImpl(paths.githubSignerDirectory);
  const githubSignerSocket = await pathInfoImpl(paths.githubSignerSocket);
  const brokerUidResult = command('id', ['-u', 'broker']);
  const brokerUid = brokerUidResult.ok ? Number(brokerUidResult.stdout) : Number.NaN;
  const brokerGroupsResult = command('id', ['-G', 'broker']);
  const brokerGroups = brokerGroupsResult.ok
    ? brokerGroupsResult.stdout.trim().split(/\s+/).map(Number)
    : [];
  const forbiddenPrivateKeyCount = (
    await Promise.all(paths.forbiddenKeyRoots.map((path) => countPrivateKeysImpl(path)))
  ).reduce((sum, value) => sum + value, 0);
  const deployHelperExecutable = await isExecutableImpl(paths.deployHelper);
  const loopbackHealth = await loopbackHealthImpl(fetchImpl);
  // Keep the release/process double-sample last. No asynchronous probe may
  // extend the acceptance window after this point.
  const auditRuntime = await collectStableAuditRuntimeSnapshot({
    command,
    realpathImpl,
    readFileImpl,
    paths,
    healthProbe: (release) =>
      auditStoreHealthImpl(command, {
        ...paths,
        auditStoreHealthHelper: path.join(
          release,
          'bin',
          path.basename(paths.auditStoreHealthHelper),
        ),
      }),
  });

  return {
    brokerUser: brokerUser.ok ? brokerUser.stdout : '',
    brokerGroup: brokerGroup.ok ? brokerGroup.stdout : '',
    brokerActive: brokerActive.ok,
    policyActive: policyActive.ok,
    auditSignerActive: auditSignerActive.ok,
    auditExporterActive: auditExporterActive.ok,
    auditStoreActive: auditStoreActive.ok,
    ...auditRuntime,
    auditRecoveryAuthorityActive: auditRecoveryAuthorityActive.ok,
    auditSignerUser: auditSignerUser.ok ? auditSignerUser.stdout : '',
    auditExporterUser: auditExporterUser.ok ? auditExporterUser.stdout : '',
    auditStoreUser: auditStoreUser.ok ? auditStoreUser.stdout : '',
    auditRecoveryUser: auditRecoveryUser.ok ? auditRecoveryUser.stdout : '',
    auditSignerGroup: auditSignerGroup.ok ? auditSignerGroup.stdout : '',
    auditExporterGroup: auditExporterGroup.ok ? auditExporterGroup.stdout : '',
    auditStoreGroup: auditStoreGroup.ok ? auditStoreGroup.stdout : '',
    auditRecoveryGroup: auditRecoveryGroup.ok ? auditRecoveryGroup.stdout : '',
    managedReleaseSymlink: release?.isSymbolicLink() === true,
    deployHelperExecutable,
    deployAccountPresent: deployAccount.ok && deployAccount.stdout.length > 0,
    nginxConfigValid: nginx.ok,
    nginxVerifyOnCount: nginx.ok
      ? (nginx.stdout.match(/^\s*proxy_ssl_verify\s+on;/gmu) ?? []).length
      : 0,
    nginxVerifyOffCount: nginx.ok
      ? (nginx.stdout.match(/^\s*proxy_ssl_verify\s+off;/gmu) ?? []).length
      : 0,
    forbiddenPrivateKeyCount,
    controlPlaneStatePresent: state?.isFile() === true && state.isSymbolicLink() === false,
    controlPlaneStateKeyProtected:
      stateKey?.isFile() === true &&
      stateKey.isSymbolicLink() === false &&
      stateKey.uid === 0 &&
      (stateKey.mode & 0o077) === 0,
    policySocketProtected:
      policySocket?.isSocket() === true &&
      policySocket.isSymbolicLink() === false &&
      (policySocket.mode & 0o007) === 0,
    githubSignerSocketProtected:
      Number.isSafeInteger(brokerUid) &&
      githubSignerDirectory?.isDirectory() === true &&
      githubSignerDirectory.isSymbolicLink() === false &&
      (githubSignerDirectory.mode & 0o022) === 0 &&
      githubSignerDirectory.uid !== brokerUid &&
      brokerGroups.includes(githubSignerDirectory.gid) &&
      (githubSignerDirectory.mode & 0o010) !== 0 &&
      githubSignerSocket?.isSocket() === true &&
      githubSignerSocket.isSymbolicLink() === false &&
      (githubSignerSocket.mode & 0o007) === 0 &&
      githubSignerSocket.uid === githubSignerDirectory.uid &&
      githubSignerSocket.uid !== brokerUid &&
      githubSignerSocket.gid === githubSignerDirectory.gid &&
      brokerGroups.includes(githubSignerSocket.gid) &&
      (githubSignerSocket.mode & 0o060) === 0o060,
    githubSignerRequired,
    loopbackHealth,
  };
}

async function main() {
  const snapshot = await collectProductionSnapshot();
  const result = evaluateProductionReadiness(snapshot);
  process.stdout.write(renderProductionReadiness(result));
  if (!result.ready) process.exitCode = 65;
}

export function isDirectExecution(argv1, moduleUrl = import.meta.url) {
  return argv1 === '-' || Boolean(argv1 && moduleUrl === pathToFileURL(argv1).href);
}

if (isDirectExecution(process.argv[1])) {
  await main();
}
