#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs';
import { access, lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { posix as path } from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_PATHS = Object.freeze({
  currentRelease: '/opt/secret-broker/broker',
  nodeRuntime: '/opt/secret-broker/runtime/node/bin/node',
  policyExecutable: '/opt/secret-broker/broker/bin/secret-broker-policy',
  deployHelper: '/usr/local/sbin/secret-broker-deploy',
  controlPlaneState: '/var/lib/secret-broker/control-plane-state.enc',
  controlPlaneStateKey: '/etc/secret-broker/control-plane-state.key',
  policySocket: '/run/secret-broker/core.sock',
  healthSocket: '/run/secret-broker-health/health.sock',
  providerSigners: Object.freeze({
    github: Object.freeze({
      directory: '/run/secret-broker-github-signer',
      socket: '/run/secret-broker-github-signer/signer.sock',
      executable: '/opt/secret-broker/broker/bin/secret-broker-github-signer',
    }),
    aliyun: Object.freeze({
      directory: '/run/secret-broker-aliyun-signer',
      socket: '/run/secret-broker-aliyun-signer/signer.sock',
      executable: '/opt/secret-broker/broker/bin/secret-broker-aliyun-signer',
    }),
  }),
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
const AUDIT_SUPPLEMENTARY_GROUPS = Object.freeze({
  signer: Object.freeze([]),
  exporter: Object.freeze(['broker-audit-signer', 'broker-audit-store']),
  store: Object.freeze([]),
  recovery: Object.freeze(['broker-audit-store']),
});
const PROVIDER_SIGNERS = Object.freeze({
  github: Object.freeze({
    service: 'secret-broker-github-signer.service',
    socketService: 'secret-broker-github-signer.socket',
    user: 'broker-github-signer',
    group: 'broker-github-signer',
  }),
  aliyun: Object.freeze({
    service: 'secret-broker-aliyun-signer.service',
    socketService: 'secret-broker-aliyun-signer.socket',
    user: 'broker-aliyun-signer',
    group: 'broker-aliyun-signer',
  }),
});
const PROVIDER_SIGNER_NAMES = Object.freeze(Object.keys(PROVIDER_SIGNERS));

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
  [
    'policy_core_active',
    (snapshot) =>
      snapshot.policyActive === true &&
      snapshot.policyUser === 'broker-core' &&
      snapshot.policyGroup === 'broker',
  ],
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
    'provider_signers_ready',
    (snapshot) =>
      snapshot.isolatedRuntimeIdentities === true && snapshot.providerSignersReady === true,
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

function parseKernelID(result) {
  if (!result?.ok || typeof result.stdout !== 'string' || !/^[0-9]{1,10}$/u.test(result.stdout)) {
    return Number.NaN;
  }
  const value = Number(result.stdout);
  return Number.isSafeInteger(value) && value <= 4_294_967_294 ? value : Number.NaN;
}

function parseKernelIDList(result) {
  if (
    !result?.ok ||
    typeof result.stdout !== 'string' ||
    !/^[0-9]{1,10}( [0-9]{1,10})*$/u.test(result.stdout)
  ) {
    return [];
  }
  const values = result.stdout.split(' ').map(Number);
  return values.every((value) => Number.isSafeInteger(value) && value <= 4_294_967_294)
    ? values
    : [];
}

function parseGroupGID(result, expectedName) {
  if (!result?.ok || typeof result.stdout !== 'string') return Number.NaN;
  const fields = result.stdout.split(':');
  if (fields.length !== 4 || fields[0] !== expectedName) return Number.NaN;
  return parseKernelID({ ok: true, stdout: fields[2] });
}

function parsePasswdIdentity(result, expectedName) {
  if (!result?.ok || typeof result.stdout !== 'string') return null;
  const fields = result.stdout.split(':');
  if (fields.length !== 7 || fields[0] !== expectedName) return null;
  const uid = parseKernelID({ ok: true, stdout: fields[2] });
  const gid = parseKernelID({ ok: true, stdout: fields[3] });
  return Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(gid) && gid > 0
    ? { uid, gid }
    : null;
}

function sameIDSet(actual, expected) {
  return (
    Array.isArray(actual) &&
    Array.isArray(expected) &&
    new Set(actual).size === actual.length &&
    new Set(expected).size === expected.length &&
    actual.length === expected.length &&
    actual.every((value) => expected.includes(value))
  );
}

function sameSocketMetadata(left, right) {
  return (
    left?.isSocket() === true &&
    right?.isSocket() === true &&
    left.isSymbolicLink() === false &&
    right.isSymbolicLink() === false &&
    ['dev', 'ino', 'mode', 'uid', 'gid'].every((field) => left[field] === right[field])
  );
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

async function localHealth(command, paths) {
  const result = command('curl', [
    '--fail',
    '--silent',
    '--show-error',
    '--max-time',
    '3',
    '--unix-socket',
    paths.healthSocket,
    'http://localhost/health',
  ]);
  return result.ok;
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
    providerSignerProcessesReleaseBound: false,
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

function processIdentity(status) {
  if (typeof status !== 'string') return null;
  const uid = /^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$/mu.exec(status);
  const gid = /^Gid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$/mu.exec(status);
  const groups = /^Groups:\s+([0-9]+(?:\s+[0-9]+)*)\s*$/mu.exec(status);
  if (uid === null || gid === null || groups === null) return null;
  const uids = uid.slice(1).map(Number);
  const gids = gid.slice(1).map(Number);
  const supplementaryGids = groups[1].trim().split(/\s+/u).map(Number);
  if (
    !uids.every((value) => Number.isSafeInteger(value) && value > 0) ||
    !gids.every((value) => Number.isSafeInteger(value) && value > 0) ||
    !supplementaryGids.every((value) => Number.isSafeInteger(value) && value > 0) ||
    new Set(supplementaryGids).size !== supplementaryGids.length ||
    new Set(uids).size !== 1 ||
    new Set(gids).size !== 1
  ) {
    return null;
  }
  return { uid: uids[0], gid: gids[0], supplementaryGids };
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
  const expectedIdentity = AUDIT_IDENTITIES[service];
  const expectedUID = parseKernelID(command('id', ['-u', expectedIdentity.user]));
  const expectedGID = parseKernelID(command('id', ['-g', expectedIdentity.user]));
  const supplementaryGIDs = AUDIT_SUPPLEMENTARY_GROUPS[service].map((group) =>
    parseGroupGID(command('getent', ['group', group]), group),
  );
  if (
    expectedUID <= 0 ||
    expectedGID <= 0 ||
    supplementaryGIDs.some((gid) => !Number.isSafeInteger(gid) || gid <= 0)
  ) {
    return null;
  }
  try {
    const [expectedExecutable, runningExecutable, stat, status] = await Promise.all([
      realpathImpl(executables[service]),
      realpathImpl(`/proc/${pid}/exe`),
      readFileImpl(`/proc/${pid}/stat`, 'utf8'),
      readFileImpl(`/proc/${pid}/status`, 'utf8'),
    ]);
    const startTime = processStartTime(stat, pid);
    const credentials = processIdentity(status);
    const releaseExecutable = path.join(release, 'bin', path.basename(executables[service]));
    if (
      startTime === null ||
      credentials === null ||
      credentials.uid !== expectedUID ||
      credentials.gid !== expectedGID ||
      !sameIDSet(credentials.supplementaryGids, [expectedGID, ...supplementaryGIDs]) ||
      expectedExecutable !== releaseExecutable ||
      runningExecutable !== expectedExecutable
    ) {
      return null;
    }
    return { pid, startTime, executable: runningExecutable, credentials };
  } catch {
    return null;
  }
}

async function providerSignerProcessSample(
  command,
  realpathImpl,
  readFileImpl,
  paths,
  release,
  signer,
) {
  const identity = PROVIDER_SIGNERS[signer];
  const signerPath = paths?.providerSigners?.[signer];
  if (
    typeof command !== 'function' ||
    typeof realpathImpl !== 'function' ||
    typeof readFileImpl !== 'function' ||
    identity === undefined ||
    signerPath === null ||
    typeof signerPath !== 'object' ||
    typeof signerPath.executable !== 'string' ||
    signerPath.executable.length === 0
  ) {
    return null;
  }
  let result;
  try {
    result = command('systemctl', ['show', identity.service, '-p', 'MainPID', '--value']);
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
  const expectedUID = parseKernelID(command('id', ['-u', identity.user]));
  const expectedGID = parseKernelID(command('id', ['-g', identity.user]));
  if (expectedUID <= 0 || expectedGID <= 0) return null;
  try {
    const [expectedExecutable, runningExecutable, stat, status] = await Promise.all([
      realpathImpl(signerPath.executable),
      realpathImpl(`/proc/${pid}/exe`),
      readFileImpl(`/proc/${pid}/stat`, 'utf8'),
      readFileImpl(`/proc/${pid}/status`, 'utf8'),
    ]);
    const startTime = processStartTime(stat, pid);
    const credentials = processIdentity(status);
    const releaseExecutable = path.join(release, 'bin', path.basename(signerPath.executable));
    if (
      startTime === null ||
      credentials === null ||
      credentials.uid !== expectedUID ||
      credentials.gid !== expectedGID ||
      !sameIDSet(credentials.supplementaryGids, [expectedGID]) ||
      expectedExecutable !== releaseExecutable ||
      runningExecutable !== expectedExecutable
    ) {
      return null;
    }
    return { pid, startTime, executable: runningExecutable, credentials };
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
    left.executable === right.executable &&
    left.workingDirectory === right.workingDirectory &&
    left.commandLine === right.commandLine &&
    left.credentials?.uid === right.credentials?.uid &&
    left.credentials?.gid === right.credentials?.gid &&
    sameIDSet(left.credentials?.supplementaryGids, right.credentials?.supplementaryGids)
  );
}

async function workloadIdentityProcessSample(command, realpathImpl, readFileImpl, release, spec) {
  const {
    service,
    expectedUID,
    expectedGIDs,
    executablePath,
    expectedExecutable,
    commandLine,
    requireReleaseCwd,
  } = spec;
  if (
    !Number.isSafeInteger(expectedUID) ||
    expectedUID <= 0 ||
    !Array.isArray(expectedGIDs) ||
    expectedGIDs.some((gid) => !Number.isSafeInteger(gid) || gid <= 0)
  ) {
    return null;
  }
  const result = command('systemctl', ['show', service, '-p', 'MainPID', '--value']);
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
    const [stat, status, resolvedExecutable, runningExecutable, runningDirectory, rawCommandLine] =
      await Promise.all([
        readFileImpl(`/proc/${pid}/stat`, 'utf8'),
        readFileImpl(`/proc/${pid}/status`, 'utf8'),
        realpathImpl(executablePath),
        realpathImpl(`/proc/${pid}/exe`),
        requireReleaseCwd ? realpathImpl(`/proc/${pid}/cwd`) : Promise.resolve(release),
        commandLine === undefined
          ? Promise.resolve('')
          : readFileImpl(`/proc/${pid}/cmdline`, 'utf8'),
      ]);
    const startTime = processStartTime(stat, pid);
    const credentials = processIdentity(status);
    const observedCommandLine = Buffer.isBuffer(rawCommandLine)
      ? rawCommandLine.toString('utf8')
      : rawCommandLine;
    if (
      startTime === null ||
      credentials === null ||
      credentials.uid !== expectedUID ||
      credentials.gid !== expectedGIDs[0] ||
      !sameIDSet(credentials.supplementaryGids, expectedGIDs) ||
      resolvedExecutable !== expectedExecutable ||
      runningExecutable !== expectedExecutable ||
      runningDirectory !== release ||
      typeof observedCommandLine !== 'string' ||
      Buffer.byteLength(observedCommandLine, 'utf8') > 1024 ||
      (commandLine !== undefined && observedCommandLine !== commandLine)
    ) {
      return null;
    }
    return {
      pid,
      startTime,
      executable: runningExecutable,
      workingDirectory: runningDirectory,
      commandLine: observedCommandLine,
      credentials,
    };
  } catch {
    return null;
  }
}

export async function collectStableAuditRuntimeSnapshot({
  command,
  realpathImpl,
  readFileImpl,
  paths,
  healthProbe,
  endpointProbe = async () => true,
}) {
  const rejected = emptyAuditRuntimeSnapshot();
  if (
    typeof healthProbe !== 'function' ||
    typeof endpointProbe !== 'function' ||
    typeof paths?.currentRelease !== 'string'
  ) {
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
    const brokerGID = parseGroupGID(command('getent', ['group', 'broker']), 'broker');
    const githubSignerGID = parseGroupGID(
      command('getent', ['group', PROVIDER_SIGNERS.github.group]),
      PROVIDER_SIGNERS.github.group,
    );
    const aliyunSignerGID = parseGroupGID(
      command('getent', ['group', PROVIDER_SIGNERS.aliyun.group]),
      PROVIDER_SIGNERS.aliyun.group,
    );
    const nodeRuntime = await realpathImpl(paths.nodeRuntime);
    const workloadSpecs = [
      {
        service: 'secret-broker.service',
        expectedUID: parseKernelID(command('id', ['-u', 'broker'])),
        expectedGIDs: [brokerGID, githubSignerGID, aliyunSignerGID],
        executablePath: paths.nodeRuntime,
        expectedExecutable: nodeRuntime,
        commandLine: `${paths.nodeRuntime}\0${paths.currentRelease}/server.js\0`,
        requireReleaseCwd: true,
      },
      {
        service: 'secret-broker-policy.service',
        expectedUID: parseKernelID(command('id', ['-u', 'broker-core'])),
        expectedGIDs: [brokerGID],
        executablePath: paths.policyExecutable,
        expectedExecutable: path.join(release, 'bin', path.basename(paths.policyExecutable)),
        requireReleaseCwd: false,
      },
    ];
    const workloadBefore = await Promise.all(
      workloadSpecs.map((spec) =>
        workloadIdentityProcessSample(command, realpathImpl, readFileImpl, release, spec),
      ),
    );
    const before = await Promise.all(
      AUDIT_SERVICES.map((service) =>
        auditProcessSample(command, realpathImpl, readFileImpl, paths, release, service),
      ),
    );
    const providerBefore = await Promise.all(
      PROVIDER_SIGNER_NAMES.map((signer) =>
        providerSignerProcessSample(command, realpathImpl, readFileImpl, paths, release, signer),
      ),
    );
    if (
      before.some((sample) => sample === null) ||
      providerBefore.some((sample) => sample === null) ||
      workloadBefore.some((sample) => sample === null)
    ) {
      return rejected;
    }
    const auditStoreHealthReady = (await healthProbe(release)) === true;
    if ((await endpointProbe(release)) !== true) return rejected;
    const after = await Promise.all(
      AUDIT_SERVICES.map((service) =>
        auditProcessSample(command, realpathImpl, readFileImpl, paths, release, service),
      ),
    );
    const providerAfter = await Promise.all(
      PROVIDER_SIGNER_NAMES.map((signer) =>
        providerSignerProcessSample(command, realpathImpl, readFileImpl, paths, release, signer),
      ),
    );
    const workloadAfter = await Promise.all(
      workloadSpecs.map((spec) =>
        workloadIdentityProcessSample(command, realpathImpl, readFileImpl, release, spec),
      ),
    );
    if (
      after.some((sample) => sample === null) ||
      providerAfter.some((sample) => sample === null) ||
      workloadAfter.some((sample) => sample === null)
    ) {
      return rejected;
    }
    const finalRelease = await realpathImpl(paths.currentRelease);
    if (
      release !== finalRelease ||
      before.some((sample, index) => !sameAuditProcess(sample, after[index])) ||
      providerBefore.some((sample, index) => !sameAuditProcess(sample, providerAfter[index])) ||
      workloadBefore.some((sample, index) => !sameAuditProcess(sample, workloadAfter[index]))
    ) {
      return rejected;
    }
    return {
      auditSignerReleaseBound: true,
      auditExporterReleaseBound: true,
      auditStoreReleaseBound: true,
      auditRecoveryReleaseBound: true,
      auditStoreHealthReady,
      providerSignerProcessesReleaseBound: true,
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
  paths = DEFAULT_PATHS,
  pathInfoImpl = pathInfo,
  isExecutableImpl = isExecutable,
  countPrivateKeysImpl = countPrivateKeys,
  loopbackHealthImpl = localHealth,
  auditStoreHealthImpl = auditStoreHealth,
  realpathImpl = realpath,
  readFileImpl = readFile,
  providerContractEvidenceImpl = async ({ release }) => {
    const result = command(paths.nodeRuntime, [
      path.join(release, 'bin', 'provider-contract-evidence-check.js'),
      '--release',
      release,
    ]);
    return result.ok && result.stdout === 'provider_contract_evidence_ready=yes';
  },
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
  const policyUser = command('systemctl', [
    'show',
    'secret-broker-policy.service',
    '-p',
    'User',
    '--value',
  ]);
  const policyGroup = command('systemctl', [
    'show',
    'secret-broker-policy.service',
    '-p',
    'Group',
    '--value',
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
  const auditIdentityRuntime = Object.fromEntries(
    AUDIT_SERVICES.map((service) => {
      const identity = AUDIT_IDENTITIES[service];
      return [
        service,
        {
          uid: command('id', ['-u', identity.user]),
          gid: command('id', ['-g', identity.user]),
          groupRecord: command('getent', ['group', identity.group]),
        },
      ];
    }),
  );
  const providerSignerRuntime = Object.fromEntries(
    PROVIDER_SIGNER_NAMES.map((signer) => {
      const identity = PROVIDER_SIGNERS[signer];
      return [
        signer,
        {
          active: command('systemctl', ['is-active', '--quiet', identity.service]).ok,
          socketActive: command('systemctl', ['is-active', '--quiet', identity.socketService]).ok,
          socketListen: command('systemctl', [
            'show',
            identity.socketService,
            '-p',
            'Listen',
            '--value',
          ]),
          socketTriggers: command('systemctl', [
            'show',
            identity.socketService,
            '-p',
            'Triggers',
            '--value',
          ]),
          user: command('systemctl', ['show', identity.service, '-p', 'User', '--value']),
          group: command('systemctl', ['show', identity.service, '-p', 'Group', '--value']),
          uid: command('id', ['-u', identity.user]),
          gid: command('id', ['-g', identity.user]),
          groupRecord: command('getent', ['group', identity.group]),
        },
      ];
    }),
  );
  const deployAccount = command('getent', ['passwd', 'broker-deploy']);
  const deployIdentity = parsePasswdIdentity(deployAccount, 'broker-deploy');
  const deployGroupGid = parseGroupGID(
    command('getent', ['group', 'broker-deploy']),
    'broker-deploy',
  );
  const nginx = command('nginx', ['-T']);
  const release = await pathInfoImpl(paths.currentRelease);
  const state = await pathInfoImpl(paths.controlPlaneState);
  const stateKey = await pathInfoImpl(paths.controlPlaneStateKey);
  const policySocket = await pathInfoImpl(paths.policySocket);
  const brokerUidResult = command('id', ['-u', 'broker']);
  const brokerUid = parseKernelID(brokerUidResult);
  const brokerGid = parseKernelID(command('id', ['-g', 'broker']));
  const brokerGroupGid = parseGroupGID(command('getent', ['group', 'broker']), 'broker');
  const policyUid = parseKernelID(command('id', ['-u', 'broker-core']));
  const policyGid = parseKernelID(command('id', ['-g', 'broker-core']));
  const brokerGroupsResult = command('id', ['-G', 'broker']);
  const brokerGroups = parseKernelIDList(brokerGroupsResult);
  const forbiddenPrivateKeyCount = (
    await Promise.all(paths.forbiddenKeyRoots.map((path) => countPrivateKeysImpl(path)))
  ).reduce((sum, value) => sum + value, 0);
  const deployHelperExecutable = await isExecutableImpl(paths.deployHelper);
  // Keep the release/process double-sample last. No asynchronous probe may
  // extend the acceptance window after this point.
  let providerSignerPaths = null;
  let providerContractEvidenceReady = false;
  let localHealthReady = false;
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
    endpointProbe: async (release) => {
      const healthSocketBefore = await pathInfoImpl(paths.healthSocket);
      const healthReady = await loopbackHealthImpl(command, paths);
      providerSignerPaths = Object.fromEntries(
        await Promise.all(
          PROVIDER_SIGNER_NAMES.map(async (signer) => [
            signer,
            {
              directory: await pathInfoImpl(paths.providerSigners?.[signer]?.directory),
              socket: await pathInfoImpl(paths.providerSigners?.[signer]?.socket),
            },
          ]),
        ),
      );
      providerContractEvidenceReady =
        (await providerContractEvidenceImpl({
          release,
          providers: PROVIDER_SIGNER_NAMES,
        })) === true;
      const healthSocketAfter = await pathInfoImpl(paths.healthSocket);
      localHealthReady =
        healthReady &&
        sameSocketMetadata(healthSocketBefore, healthSocketAfter) &&
        healthSocketAfter.uid === brokerUid &&
        healthSocketAfter.gid === brokerGid &&
        (healthSocketAfter.mode & 0o077) === 0;
      return true;
    },
  });
  providerSignerPaths ??= Object.fromEntries(
    PROVIDER_SIGNER_NAMES.map((signer) => [signer, { directory: null, socket: null }]),
  );

  const signerUsers = PROVIDER_SIGNER_NAMES.map((signer) =>
    providerSignerRuntime[signer].user.ok ? providerSignerRuntime[signer].user.stdout : '',
  );
  const signerGroups = PROVIDER_SIGNER_NAMES.map((signer) =>
    providerSignerRuntime[signer].group.ok ? providerSignerRuntime[signer].group.stdout : '',
  );
  const signerUids = PROVIDER_SIGNER_NAMES.map((signer) =>
    parseKernelID(providerSignerRuntime[signer].uid),
  );
  const signerGids = PROVIDER_SIGNER_NAMES.map((signer) =>
    parseKernelID(providerSignerRuntime[signer].gid),
  );
  const auditUids = AUDIT_SERVICES.map((service) =>
    parseKernelID(auditIdentityRuntime[service].uid),
  );
  const auditGids = AUDIT_SERVICES.map((service) =>
    parseKernelID(auditIdentityRuntime[service].gid),
  );
  const allRuntimeUids = [
    brokerUid,
    policyUid,
    ...auditUids,
    ...signerUids,
    deployIdentity?.uid ?? Number.NaN,
  ];
  const isolatedServiceGids = [
    brokerGid,
    ...auditGids,
    ...signerGids,
    deployIdentity?.gid ?? Number.NaN,
  ];
  const auditGroupMappingsValid = AUDIT_SERVICES.every(
    (service, index) =>
      parseGroupGID(auditIdentityRuntime[service].groupRecord, AUDIT_IDENTITIES[service].group) ===
      auditGids[index],
  );
  const isolatedRuntimeIdentities =
    policyUser.ok &&
    policyUser.stdout === 'broker-core' &&
    policyGroup.ok &&
    policyGroup.stdout === 'broker' &&
    brokerGroupGid === brokerGid &&
    policyGid === brokerGid &&
    deployIdentity !== null &&
    deployGroupGid === deployIdentity.gid &&
    allRuntimeUids.every((value) => Number.isSafeInteger(value) && value > 0) &&
    new Set(allRuntimeUids).size === allRuntimeUids.length &&
    isolatedServiceGids.every((value) => Number.isSafeInteger(value) && value > 0) &&
    new Set(isolatedServiceGids).size === isolatedServiceGids.length &&
    auditGroupMappingsValid;
  const providerSignerBoundariesReady = PROVIDER_SIGNER_NAMES.every((signer) => {
    const expected = PROVIDER_SIGNERS[signer];
    const runtime = providerSignerRuntime[signer];
    const signerUid = parseKernelID(runtime.uid);
    const signerGid = parseKernelID(runtime.gid);
    const configuredGroupGid = parseGroupGID(runtime.groupRecord, expected.group);
    const directory = providerSignerPaths[signer].directory;
    const socket = providerSignerPaths[signer].socket;
    return (
      runtime.active === true &&
      runtime.socketActive === true &&
      runtime.socketListen.ok &&
      runtime.socketListen.stdout === `${paths.providerSigners[signer].socket} (Stream)` &&
      runtime.socketTriggers.ok &&
      runtime.socketTriggers.stdout === expected.service &&
      runtime.user.ok &&
      runtime.user.stdout === expected.user &&
      runtime.group.ok &&
      runtime.group.stdout === expected.group &&
      Number.isSafeInteger(signerUid) &&
      signerUid > 0 &&
      signerUid !== brokerUid &&
      Number.isSafeInteger(signerGid) &&
      signerGid > 0 &&
      configuredGroupGid === signerGid &&
      directory?.isDirectory() === true &&
      directory.isSymbolicLink() === false &&
      directory.uid === 0 &&
      directory.gid === signerGid &&
      (directory.mode & 0o777) === 0o750 &&
      brokerGroups.includes(directory.gid) &&
      socket?.isSocket() === true &&
      socket.isSymbolicLink() === false &&
      socket.uid === 0 &&
      socket.gid === directory.gid &&
      (socket.mode & 0o777) === 0o660
    );
  });
  const providerSignerIdentitiesIndependent =
    Number.isSafeInteger(brokerUid) &&
    brokerUid > 0 &&
    new Set(signerUsers).size === PROVIDER_SIGNER_NAMES.length &&
    new Set(signerGroups).size === PROVIDER_SIGNER_NAMES.length &&
    new Set(signerUids).size === PROVIDER_SIGNER_NAMES.length &&
    new Set(signerGids).size === PROVIDER_SIGNER_NAMES.length &&
    signerUids.every(Number.isSafeInteger) &&
    signerGids.every(Number.isSafeInteger) &&
    signerUsers.every((user) => user !== '' && user !== 'broker' && user !== 'root') &&
    signerGroups.every((group) => group !== '' && group !== 'broker' && group !== 'root');

  return {
    brokerUser: brokerUser.ok ? brokerUser.stdout : '',
    brokerGroup: brokerGroup.ok ? brokerGroup.stdout : '',
    brokerActive: brokerActive.ok,
    policyActive: policyActive.ok,
    policyUser: policyUser.ok ? policyUser.stdout : '',
    policyGroup: policyGroup.ok ? policyGroup.stdout : '',
    isolatedRuntimeIdentities,
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
    deployAccountPresent: deployIdentity !== null,
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
    providerSignersReady:
      providerSignerBoundariesReady &&
      providerSignerIdentitiesIndependent &&
      providerContractEvidenceReady &&
      auditRuntime.providerSignerProcessesReleaseBound === true,
    loopbackHealth: localHealthReady,
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
