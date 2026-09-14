#!/usr/bin/env node

import { lstat, readFile, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { posix as path } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PROVIDER_CONTRACT_EVIDENCE_PATHS,
  verifyProviderContractEvidence,
} from '../lib/provider-contract-evidence.js';

const RELEASE_RE = /^[a-f0-9]{40}$/u;
const SHA256_RE = /^[a-f0-9]{64}$/u;

function sameStat(left, right) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'mode', 'uid', 'gid'].every(
    (field) => left?.[field] === right?.[field],
  );
}

async function readProtectedFile(filePath, maxBytes, { lstatImpl, readFileImpl, realpathImpl }) {
  const parent = path.dirname(filePath);
  const [parentStat, resolvedParent] = await Promise.all([lstatImpl(parent), realpathImpl(parent)]);
  if (
    resolvedParent !== parent ||
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    parentStat.uid !== 0 ||
    (parentStat.mode & 0o022) !== 0
  ) {
    throw new Error('unsafe evidence boundary');
  }
  const before = await lstatImpl(filePath);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== 0 ||
    (before.mode & 0o077) !== 0 ||
    before.size < 2 ||
    before.size > maxBytes ||
    (await realpathImpl(filePath)) !== filePath
  ) {
    throw new Error('unsafe evidence file');
  }
  const bytes = await readFileImpl(filePath);
  const after = await lstatImpl(filePath);
  if (!Buffer.isBuffer(bytes) || bytes.length !== before.size || !sameStat(before, after)) {
    throw new Error('unstable evidence file');
  }
  return bytes;
}

async function readSignerConfig(filePath, maxBytes, { lstatImpl, readFileImpl, realpathImpl }) {
  const parent = path.dirname(filePath);
  const [parentStat, resolvedParent] = await Promise.all([lstatImpl(parent), realpathImpl(parent)]);
  if (
    resolvedParent !== parent ||
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    parentStat.uid !== 0 ||
    (parentStat.mode & 0o022) !== 0
  ) {
    throw new Error('unsafe signer configuration boundary');
  }
  const before = await lstatImpl(filePath);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== 0 ||
    !Number.isSafeInteger(before.gid) ||
    before.gid <= 0 ||
    (before.mode & 0o777) !== 0o640 ||
    before.size < 2 ||
    before.size > maxBytes ||
    (await realpathImpl(filePath)) !== filePath
  ) {
    throw new Error('unsafe signer configuration file');
  }
  const bytes = await readFileImpl(filePath);
  const after = await lstatImpl(filePath);
  if (!Buffer.isBuffer(bytes) || bytes.length !== before.size || !sameStat(before, after)) {
    throw new Error('unstable signer configuration file');
  }
  return { bytes, gid: before.gid };
}

async function assertProtectedDirectory(directoryPath, { lstatImpl, realpathImpl }) {
  const [directoryStat, resolvedDirectory] = await Promise.all([
    lstatImpl(directoryPath),
    realpathImpl(directoryPath),
  ]);
  if (
    resolvedDirectory !== directoryPath ||
    !directoryStat.isDirectory() ||
    directoryStat.isSymbolicLink() ||
    directoryStat.uid !== 0 ||
    (directoryStat.mode & 0o022) !== 0
  ) {
    throw new Error('unsafe evidence directory');
  }
}

export function readBindingGeneration(
  requestImpl = httpRequest,
  socketPath = '/run/secret-broker-health/health.sock',
  { setTimer = setTimeout, clearTimer = clearTimeout } = {},
) {
  return new Promise((resolve) => {
    let settled = false;
    let request;
    let response;
    let wallClockTimer;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimer(wallClockTimer);
      response?.destroy?.();
      request?.destroy?.();
      resolve(value);
    };
    wallClockTimer = setTimer(() => finish(null), 3_000);
    try {
      request = requestImpl(
        { socketPath, path: '/provider-binding-generation', method: 'GET' },
        (incomingResponse) => {
          response = incomingResponse;
          const chunks = [];
          let size = 0;
          incomingResponse.on('data', (chunk) => {
            if (settled) return;
            const bytes = Buffer.from(chunk);
            size += bytes.length;
            if (size > 256) return finish(null);
            chunks.push(bytes);
          });
          incomingResponse.on('end', () => {
            if (settled || incomingResponse.statusCode !== 200) return finish(null);
            try {
              const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              const keys =
                value && typeof value === 'object' && !Array.isArray(value)
                  ? Object.keys(value)
                  : [];
              finish(
                keys.length === 2 &&
                  value.version === 1 &&
                  SHA256_RE.test(value.binding_generation_sha256 || '')
                  ? value.binding_generation_sha256
                  : null,
              );
            } catch {
              finish(null);
            }
          });
          incomingResponse.on('error', () => finish(null));
        },
      );
      request.setTimeout(3_000, () => finish(null));
      request.on('error', () => finish(null));
      request.end();
    } catch {
      finish(null);
    }
  });
}

export async function runProviderContractEvidenceCheck(
  argv = process.argv,
  {
    paths = PROVIDER_CONTRACT_EVIDENCE_PATHS,
    lstatImpl = lstat,
    readFileImpl = readFile,
    realpathImpl = realpath,
    bindingGenerationImpl = readBindingGeneration,
    writeOutput = (value) => process.stdout.write(`${value}\n`),
    now = Date.now,
  } = {},
) {
  let ready = false;
  try {
    const liveGenerationMode = argv.length === 8;
    if (
      (argv.length !== 4 && !liveGenerationMode) ||
      argv[2] !== '--release' ||
      !path.isAbsolute(argv[3]) ||
      (liveGenerationMode &&
        (argv[4] !== '--github-authority-generation' ||
          !SHA256_RE.test(argv[5] || '') ||
          argv[6] !== '--aliyun-authority-generation' ||
          !SHA256_RE.test(argv[7] || '')))
    ) {
      throw new Error('invalid invocation');
    }
    const release = await realpathImpl(argv[3]);
    const releaseSha = path.basename(release);
    if (release !== argv[3] || !RELEASE_RE.test(releaseSha)) throw new Error('invalid release');
    if (typeof now !== 'function') throw new Error('invalid clock');
    const bindingBefore = await bindingGenerationImpl();
    if (bindingBefore === null) throw new Error('binding unavailable');
    const fileDeps = { lstatImpl, readFileImpl, realpathImpl };
    const evidenceDirectory = path.join(paths.evidenceRoot, releaseSha);
    await assertProtectedDirectory(paths.evidenceRoot, fileDeps);
    const [evidenceBytes, signatureBytes, keyringBytes, githubConfigFile, aliyunConfigFile] =
      await Promise.all([
        readProtectedFile(path.join(evidenceDirectory, 'evidence.json'), 32 * 1024, fileDeps),
        readProtectedFile(path.join(evidenceDirectory, 'evidence.sig'), 256, fileDeps),
        readProtectedFile(paths.keyring, 32 * 1024, fileDeps),
        readSignerConfig(paths.signerConfigs.github, 32 * 1024, fileDeps),
        readSignerConfig(paths.signerConfigs.aliyun, 32 * 1024, fileDeps),
      ]);
    if (githubConfigFile.gid === aliyunConfigFile.gid) {
      throw new Error('signer configuration groups are not isolated');
    }
    const githubConfig = githubConfigFile.bytes;
    const aliyunConfig = aliyunConfigFile.bytes;
    const bindingAfter = await bindingGenerationImpl();
    if (bindingAfter !== bindingBefore) throw new Error('binding changed');
    const diskSignerAuthorityGeneration = {
      github: createHash('sha256').update(githubConfig).digest('hex'),
      aliyun: createHash('sha256').update(aliyunConfig).digest('hex'),
    };
    const expectedSignerAuthorityGeneration = liveGenerationMode
      ? { github: argv[5], aliyun: argv[7] }
      : diskSignerAuthorityGeneration;
    if (
      expectedSignerAuthorityGeneration.github !== diskSignerAuthorityGeneration.github ||
      expectedSignerAuthorityGeneration.aliyun !== diskSignerAuthorityGeneration.aliyun
    ) {
      throw new Error('loaded signer authority differs from protected configuration');
    }
    ready = verifyProviderContractEvidence({
      evidenceBytes,
      signatureBytes,
      keyringBytes,
      expectedReleaseSha: releaseSha,
      expectedBindingGeneration: bindingBefore,
      expectedSignerAuthorityGeneration,
      now: now(),
    });
  } catch {
    ready = false;
  }
  writeOutput(`provider_contract_evidence_ready=${ready ? 'yes' : 'no'}`);
  return ready;
}

/* c8 ignore start -- exercised by process invocation */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const ready = await runProviderContractEvidenceCheck();
  if (!ready) process.exitCode = 65;
}
/* c8 ignore stop */
