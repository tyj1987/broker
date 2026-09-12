import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';

import {
  runProviderContractCheck,
  safeProviderContractErrorCode,
} from '../broker/bin/provider-contract-check.js';
import { ProviderContractError } from '../broker/lib/provider-contract-runner.js';

const apiKey = `${['mb', 'test'].join('_')}_0123456789abcdefghijklmnopqrstuv`;
const taskId = '00000000-0000-4000-8000-000000000201';
const contractPath = resolve('protected-test-inputs', 'contract.json');
const apiKeyPath = resolve('protected-test-inputs', 'broker.key');
const clientCertPath = resolve('protected-test-inputs', 'client.crt');
const clientKeyPath = resolve('protected-test-inputs', 'client.key');
const caPath = resolve('protected-test-inputs', 'ca.crt');
const missingPlanPath = resolve('protected-test-inputs', 'missing.json');
const plan = {
  version: 1,
  provider: 'github',
  tool_name: 'github.repository.read',
  tool_version: '1.0.0',
  account_ref: 'github-isolated',
  wrong_account_ref: 'github-other',
  environment: 'staging',
  parameters: {
    resource_ref: 'contract-owner/private-contract-repo',
    owner: 'contract-owner',
    repo: 'private-contract-repo',
  },
  wrong_resource_ref: 'contract-owner/other-private-repo',
  idempotency_prefix: 'dq004-github-cli-20260912',
};

function requestImpl(options, callback) {
  const request = new EventEmitter();
  const chunks = [];
  request.write = (chunk) => chunks.push(Buffer.from(chunk));
  request.end = (finalChunk) => {
    if (finalChunk) chunks.push(Buffer.from(finalChunk));
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
    let statusCode = 200;
    let responseBody;
    if (options.path === '/api/v2/tools') {
      responseBody = {
        registry_version: 1,
        tools: [
          {
            name: plan.tool_name,
            version: plan.tool_version,
            provider: plan.provider,
            operation_id: 'repo.read',
            agent_execution: true,
            environments: ['staging'],
          },
        ],
      };
    } else if (options.path.endsWith('/run')) {
      responseBody = {
        id: taskId,
        tool: plan.tool_name,
        tool_version: plan.tool_version,
        account_ref: plan.account_ref,
        environment: plan.environment,
        state: 'SUCCEEDED',
        result: {
          id: 123,
          full_name: plan.parameters.resource_ref,
          visibility: 'private',
          archived: false,
        },
      };
    } else if (
      body.account_ref === plan.wrong_account_ref ||
      body.parameters.resource_ref === plan.wrong_resource_ref
    ) {
      statusCode = 403;
      responseBody = { error: { code: 'forbidden', detail: 'must not escape' } };
    } else {
      responseBody = {
        id: taskId,
        tool: plan.tool_name,
        tool_version: plan.tool_version,
        account_ref: plan.account_ref,
        environment: plan.environment,
        state: 'READY',
      };
    }
    const response = new EventEmitter();
    response.statusCode = statusCode;
    response.setEncoding = () => {};
    callback(response);
    queueMicrotask(() => {
      response.emit('data', JSON.stringify(responseBody));
      response.emit('end');
    });
  };
  request.destroy = () => {};
  request.setTimeout = () => {};
  return request;
}

const files = new Map([
  [contractPath, Buffer.from(JSON.stringify(plan))],
  [apiKeyPath, Buffer.from(`${apiKey}\n`)],
  [clientCertPath, Buffer.from('certificate')],
  [clientKeyPath, Buffer.from('private key')],
  [caPath, Buffer.from('ca certificate')],
]);
const readFileImpl = (path) => {
  if (!files.has(path)) throw new Error('missing');
  return files.get(path);
};
const argv = [
  'node',
  'provider-contract-check',
  '--broker',
  'https://broker.52trz.com',
  '--plan-file',
  contractPath,
  '--api-key-file',
  apiKeyPath,
  '--client-cert-file',
  clientCertPath,
  '--client-key-file',
  clientKeyPath,
  '--ca-file',
  caPath,
];
const output = [];
const receipt = await runProviderContractCheck(argv, {
  readFileImpl,
  requestImpl,
  writeOutput: (value) => output.push(value),
});
assert.equal(receipt.status, 'passed');
assert.deepEqual(JSON.parse(output[0]), receipt);
assert.equal(output[0].includes(plan.account_ref), false);
assert.equal(output[0].includes(plan.parameters.resource_ref), false);

const withoutTls = [
  'node',
  'provider-contract-check',
  '--plan-file',
  contractPath,
  '--api-key-file',
  apiKeyPath,
];
const originalStdoutWrite = process.stdout.write;
let defaultOutput = '';
process.stdout.write = (value) => {
  defaultOutput += String(value);
  return true;
};
try {
  assert.equal(
    (await runProviderContractCheck(withoutTls, { readFileImpl, requestImpl })).status,
    'passed',
  );
} finally {
  process.stdout.write = originalStdoutWrite;
}
assert.equal(JSON.parse(defaultOutput).status, 'passed');

const clientKeyArgument = argv.indexOf('--client-key-file');
const withoutClientKey = [
  ...argv.slice(0, clientKeyArgument),
  ...argv.slice(clientKeyArgument + 2),
];
for (const invalidArgv of [
  [...argv, '--api-key', apiKey],
  withoutClientKey,
  ['node', 'check', '--plan-file', 'relative.json', '--api-key-file', apiKeyPath],
  ['node', 'check', '--plan-file', missingPlanPath, '--api-key-file', apiKeyPath],
  ['node', 'check', '--plan-file', contractPath, '--api-key-file', 'relative.key'],
]) {
  await assert.rejects(
    runProviderContractCheck(invalidArgv, { readFileImpl, requestImpl, writeOutput: () => {} }),
  );
}

for (const [path, contents, pattern] of [
  [contractPath, Buffer.from('{'), /invalid JSON/],
  [contractPath, Buffer.alloc(0), /file size is invalid/],
  [apiKeyPath, Buffer.from('invalid'), /valid scoped Broker API key/],
]) {
  const invalidFiles = new Map(files);
  invalidFiles.set(path, contents);
  await assert.rejects(
    runProviderContractCheck(argv, {
      readFileImpl: (filePath) => invalidFiles.get(filePath),
      requestImpl,
      writeOutput: () => {},
    }),
    pattern,
  );
}

const oversizedFiles = new Map(files);
oversizedFiles.set(contractPath, Buffer.alloc(32 * 1024 + 1));
await assert.rejects(
  runProviderContractCheck(argv, {
    readFileImpl: (path) => oversizedFiles.get(path),
    requestImpl,
    writeOutput: () => {},
  }),
  /file size is invalid/,
);

assert.equal(
  safeProviderContractErrorCode(new ProviderContractError('contract_plan_invalid')),
  'contract_plan_invalid',
);
assert.equal(
  safeProviderContractErrorCode(new ProviderContractError('contract_secret_exposed')),
  'provider_contract_check_failed',
);
assert.equal(
  safeProviderContractErrorCode(Object.assign(new Error('private detail'), { code: 'forbidden' })),
  'provider_contract_check_failed',
);

console.log('provider contract CLI: file-only inputs and safe receipt passed');
