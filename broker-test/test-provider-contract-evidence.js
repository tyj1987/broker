import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';

import {
  readBindingGeneration,
  runProviderContractEvidenceCheck,
} from '../broker/bin/provider-contract-evidence-check.js';
import {
  PROVIDER_CONTRACT_EVIDENCE_PATHS,
  verifyProviderContractEvidence,
} from '../broker/lib/provider-contract-evidence.js';
import { canonicalJson } from '../broker/lib/operations-v2.js';

const now = Date.parse('2026-09-13T01:00:00Z');
const evidenceSchema = JSON.parse(
  readFileSync(new URL('../contracts/provider-contract-evidence-v1.schema.json', import.meta.url)),
);
assert.equal(evidenceSchema.properties.receipts.items, false);
assert.equal(evidenceSchema.properties.receipts.prefixItems[0].allOf[1].properties.provider.const, 'github');
assert.equal(evidenceSchema.properties.receipts.prefixItems[1].allOf[1].properties.provider.const, 'aliyun');
const releaseSha = 'a'.repeat(40);
const binding = 'b'.repeat(64);
const signerAuthorityGeneration = { github: '1'.repeat(64), aliyun: '2'.repeat(64) };
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicDer = publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const checks = [
  'tool_discovery',
  'authority_identity',
  'authority_match',
  'bounded_read',
  'safe_output',
  'wrong_account_denied',
  'wrong_resource_denied',
];
const evidence = {
  version: 1,
  evidence_id: '019d0000-0000-7000-8000-000000000001',
  key_id: 'provider-contract-2026-01',
  release_sha: releaseSha,
  binding_generation_sha256: binding,
  signer_authority_generation_sha256: signerAuthorityGeneration,
  issued_at: '2026-09-13T00:59:00Z',
  expires_at: '2026-09-13T01:10:00Z',
  receipts: [
    {
      version: 2,
      provider: 'github',
      operation_id: 'repo.read',
      environment: 'production',
      status: 'passed',
      checks,
      plan_sha256: 'c'.repeat(64),
      provider_audit_sha256: 'd'.repeat(64),
    },
    {
      version: 2,
      provider: 'aliyun',
      operation_id: 'ecs.instances.list',
      environment: 'production',
      status: 'passed',
      checks,
      plan_sha256: 'e'.repeat(64),
      provider_audit_sha256: 'f'.repeat(64),
    },
  ],
};
const keyring = {
  version: 1,
  keys: [
    {
      key_id: evidence.key_id,
      algorithm: 'ed25519',
      public_key_spki_der: publicDer,
      not_before: '2026-09-12T00:00:00Z',
      not_after: '2026-09-14T00:00:00Z',
    },
  ],
};

const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
const fixture = (evidenceValue = evidence, keyringValue = keyring) => {
  const evidenceBytes = canonicalBytes(evidenceValue);
  return {
    evidenceBytes,
    signatureBytes: Buffer.from(`${sign(null, evidenceBytes, privateKey).toString('base64url')}\n`),
    keyringBytes: canonicalBytes(keyringValue),
  };
};
const valid = fixture();
const verify = (overrides = {}) =>
  verifyProviderContractEvidence({
    ...valid,
    expectedReleaseSha: releaseSha,
    expectedBindingGeneration: binding,
    expectedSignerAuthorityGeneration: signerAuthorityGeneration,
    now,
    ...overrides,
  });

assert.equal(verify(), true);
assert.equal(verify({ expectedReleaseSha: '1'.repeat(40) }), false);
assert.equal(verify({ expectedBindingGeneration: '2'.repeat(64) }), false);
assert.equal(
  verify({
    expectedSignerAuthorityGeneration: { ...signerAuthorityGeneration, github: '3'.repeat(64) },
  }),
  false,
);
assert.equal(verify({ now: Date.parse(evidence.expires_at) }), false);
assert.equal(verify({ now: Number.NaN }), false);
assert.equal(verify({ ...fixture({ ...evidence, issued_at: '2026-09-13T01:02:00Z' }) }), false);
assert.equal(
  verify({ evidenceBytes: Buffer.concat([valid.evidenceBytes, Buffer.from(' ')]) }),
  false,
);
assert.equal(verify({ evidenceBytes: Buffer.from(`\ufeff${valid.evidenceBytes}`) }), false);
assert.equal(
  verify({ signatureBytes: Buffer.from(`${valid.signatureBytes.toString().trim()}==\n`) }),
  false,
);
assert.equal(verify({ signatureBytes: Buffer.alloc(64, 'a') }), false);
assert.equal(
  verify({ ...fixture({ ...evidence, receipts: [...evidence.receipts].reverse() }) }),
  false,
);
assert.equal(
  verify({
    ...fixture({
      ...evidence,
      receipts: [{ ...evidence.receipts[0], environment: 'staging' }, evidence.receipts[1]],
    }),
  }),
  false,
);
assert.equal(verify({ ...fixture({ ...evidence, expires_at: '2026-09-14T01:00:01Z' }) }), false);
assert.equal(verify({ ...fixture({ ...evidence, unexpected: true }) }), false);
assert.equal(
  verify({
    ...fixture(evidence, {
      ...keyring,
      keys: [...keyring.keys, structuredClone(keyring.keys[0])],
    }),
  }),
  false,
);
assert.equal(
  verify({
    ...fixture(evidence, {
      ...keyring,
      keys: [{ ...keyring.keys[0], algorithm: 'rsa' }],
    }),
  }),
  false,
);

function stat(kind, size = 0) {
  return {
    dev: 1,
    ino: size + 10,
    size,
    mtimeMs: 1,
    mode: (kind === 'dir' ? 0o040000 : 0o100000) | (kind === 'dir' ? 0o700 : 0o600),
    uid: 0,
    gid: 0,
    isDirectory: () => kind === 'dir',
    isFile: () => kind === 'file',
    isSymbolicLink: () => false,
  };
}

const evidenceDirectory = `${PROVIDER_CONTRACT_EVIDENCE_PATHS.evidenceRoot}/${releaseSha}`;
const githubConfig = Buffer.from('github signer authority generation\n');
const aliyunConfig = Buffer.from('aliyun signer authority generation\n');
evidence.signer_authority_generation_sha256 = {
  github: createHash('sha256').update(githubConfig).digest('hex'),
  aliyun: createHash('sha256').update(aliyunConfig).digest('hex'),
};
const runtimeValid = fixture(evidence);
const files = new Map([
  [`${evidenceDirectory}/evidence.json`, runtimeValid.evidenceBytes],
  [`${evidenceDirectory}/evidence.sig`, runtimeValid.signatureBytes],
  [PROVIDER_CONTRACT_EVIDENCE_PATHS.keyring, valid.keyringBytes],
  [PROVIDER_CONTRACT_EVIDENCE_PATHS.signerConfigs.github, githubConfig],
  [PROVIDER_CONTRACT_EVIDENCE_PATHS.signerConfigs.aliyun, aliyunConfig],
]);
const run = async (overrides = {}) => {
  const output = [];
  const ready = await runProviderContractEvidenceCheck(
    ['node', 'provider-contract-evidence-check.js', '--release', `/releases/${releaseSha}`],
    {
      now: () => now,
      realpathImpl: async (path) => path,
      lstatImpl: async (path) => {
        const bytes = files.get(path);
        return bytes ? stat('file', bytes.length) : stat('dir');
      },
      readFileImpl: async (path) => files.get(path),
      bindingGenerationImpl: async () => binding,
      writeOutput: (value) => output.push(value),
      ...overrides,
    },
  );
  return { ready, output };
};

assert.deepEqual(await run(), {
  ready: true,
  output: ['provider_contract_evidence_ready=yes'],
});
assert.deepEqual(await run({ bindingGenerationImpl: async () => null }), {
  ready: false,
  output: ['provider_contract_evidence_ready=no'],
});
let bindingReads = 0;
assert.deepEqual(
  await run({
    bindingGenerationImpl: async () => (bindingReads++ === 0 ? 'a' : 'b').repeat(64),
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({
    readFileImpl: async (path) =>
      path === PROVIDER_CONTRACT_EVIDENCE_PATHS.signerConfigs.github
        ? Buffer.from('changed signer authority\n')
        : files.get(path),
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({
    lstatImpl: async (path) => {
      const bytes = files.get(path);
      const value = bytes ? stat('file', bytes.length) : stat('dir');
      return path === evidenceDirectory ? { ...value, mode: 0o040770 } : value;
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
let evidenceStats = 0;
assert.deepEqual(
  await run({
    lstatImpl: async (path) => {
      const bytes = files.get(path);
      const value = bytes ? stat('file', bytes.length) : stat('dir');
      if (path.endsWith('/evidence.json') && evidenceStats++ > 0) {
        return { ...value, mtimeMs: 2 };
      }
      return value;
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({
    lstatImpl: async (path) => {
      const bytes = files.get(path);
      const value = bytes ? stat('file', bytes.length) : stat('dir');
      return path === PROVIDER_CONTRACT_EVIDENCE_PATHS.evidenceRoot
        ? { ...value, mode: 0o040770 }
        : value;
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({
    lstatImpl: async (path) => {
      const bytes = files.get(path);
      const value = bytes ? stat('file', bytes.length) : stat('dir');
      return path.endsWith('/evidence.json') ? { ...value, size: 32 * 1024 + 1 } : value;
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({
    lstatImpl: async (path) => {
      const bytes = files.get(path);
      const value = bytes ? stat('file', bytes.length) : stat('dir');
      return path.endsWith('/evidence.json') ? { ...value, mode: 0o100644 } : value;
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);
assert.deepEqual(
  await run({ realpathImpl: async (path) => (path.endsWith('/evidence.json') ? '/other' : path) }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);

function bindingRequest(body, statusCode = 200) {
  return (_options, callback) => {
    const request = new EventEmitter();
    request.setTimeout = () => {};
    request.destroy = () => {};
    request.end = () => {
      const response = new EventEmitter();
      response.statusCode = statusCode;
      callback(response);
      queueMicrotask(() => {
        response.emit('data', body);
        response.emit('end');
      });
    };
    return request;
  };
}
assert.equal(
  await readBindingGeneration(
    bindingRequest(JSON.stringify({ version: 1, binding_generation_sha256: binding })),
  ),
  binding,
);
assert.equal(await readBindingGeneration(bindingRequest('x'.repeat(257))), null);
assert.equal(await readBindingGeneration(bindingRequest('{}', 503)), null);
let wallClockExpiry;
let requestDestroyed = false;
let responseDestroyed = false;
const slowDrip = (_options, callback) => {
  const request = new EventEmitter();
  request.setTimeout = () => {};
  request.destroy = () => {
    requestDestroyed = true;
  };
  request.end = () => {
    const response = new EventEmitter();
    response.statusCode = 200;
    response.destroy = () => {
      responseDestroyed = true;
    };
    callback(response);
    response.emit('data', '{');
  };
  return request;
};
const slowResult = readBindingGeneration(slowDrip, '/socket', {
  setTimer: (callback) => {
    wallClockExpiry = callback;
    return 1;
  },
  clearTimer: () => {},
});
wallClockExpiry();
assert.equal(await slowResult, null);
assert.equal(requestDestroyed, true);
assert.equal(responseDestroyed, true);

assert.deepEqual(
  await run({
    readFileImpl: async () => {
      throw new Error('credential canary');
    },
  }),
  { ready: false, output: ['provider_contract_evidence_ready=no'] },
);

console.log('provider contract evidence: canonical signed release and binding proof passed');
