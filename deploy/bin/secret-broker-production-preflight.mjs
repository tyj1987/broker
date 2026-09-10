#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs';
import { access, lstat, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const DEFAULT_PATHS = Object.freeze({
  currentRelease: '/opt/secret-broker/broker',
  deployHelper: '/usr/local/sbin/secret-broker-deploy',
  controlPlaneState: '/var/lib/secret-broker/control-plane-state.enc',
  controlPlaneStateKey: '/etc/secret-broker/control-plane-state.key',
  policySocket: '/run/secret-broker/core.sock',
  githubSignerDirectory: '/run/secret-broker-signer',
  githubSignerSocket: '/run/secret-broker-signer/github.sock',
  forbiddenKeyRoots: [
    '/etc/secret-broker/pki/ca',
    '/etc/secret-broker/pki/clients',
    '/opt/secret-broker/pki',
  ],
});

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
  ['control_plane_state_key_protected', (snapshot) => snapshot.controlPlaneStateKeyProtected === true],
  ['policy_socket_protected', (snapshot) => snapshot.policySocketProtected === true],
  ['github_signer_socket_protected', (snapshot) => snapshot.githubSignerSocketProtected === true],
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

export function evaluateProductionReadiness(snapshot) {
  const checks = CHECKS.map(([name, predicate]) => ({ name, passed: Boolean(predicate(snapshot)) }));
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
} = {}) {
  const brokerUser = command('systemctl', ['show', 'secret-broker.service', '-p', 'User', '--value']);
  const brokerGroup = command('systemctl', ['show', 'secret-broker.service', '-p', 'Group', '--value']);
  const brokerActive = command('systemctl', ['is-active', '--quiet', 'secret-broker.service']);
  const policyActive = command('systemctl', ['is-active', '--quiet', 'secret-broker-policy.service']);
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

  return {
    brokerUser: brokerUser.ok ? brokerUser.stdout : '',
    brokerGroup: brokerGroup.ok ? brokerGroup.stdout : '',
    brokerActive: brokerActive.ok,
    policyActive: policyActive.ok,
    managedReleaseSymlink: release?.isSymbolicLink() === true,
    deployHelperExecutable: await isExecutableImpl(paths.deployHelper),
    deployAccountPresent: deployAccount.ok && deployAccount.stdout.length > 0,
    nginxConfigValid: nginx.ok,
    nginxVerifyOnCount: nginx.ok ? (nginx.stdout.match(/^\s*proxy_ssl_verify\s+on;/gmu) ?? []).length : 0,
    nginxVerifyOffCount: nginx.ok ? (nginx.stdout.match(/^\s*proxy_ssl_verify\s+off;/gmu) ?? []).length : 0,
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
    loopbackHealth: await loopbackHealthImpl(fetchImpl),
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
