import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  runProviderContractCheck,
  safeProviderContractErrorCode,
} from '../broker/bin/provider-contract-check.js';
import { ProviderContractError } from '../broker/lib/provider-contract-runner.js';

const apiKey = `${['mb', 'test'].join('_')}_0123456789abcdefghijklmnopqrstuv`;
const taskId = '00000000-0000-4000-8000-000000000201';
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
  ['C:\\protected\\contract.json', Buffer.from(JSON.stringify(plan))],
  ['C:\\protected\\broker.key', Buffer.from(`${apiKey}\n`)],
  ['C:\\protected\\client.crt', Buffer.from('certificate')],
  ['C:\\protected\\client.key', Buffer.from('private key')],
  ['C:\\protected\\ca.crt', Buffer.from('ca certificate')],
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
  'C:\\protected\\contract.json',
  '--api-key-file',
  'C:\\protected\\broker.key',
  '--client-cert-file',
  'C:\\protected\\client.crt',
  '--client-key-file',
  'C:\\protected\\client.key',
  '--ca-file',
  'C:\\protected\\ca.crt',
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
  'C:\\protected\\contract.json',
  '--api-key-file',
  'C:\\protected\\broker.key',
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
  ['node', 'check', '--plan-file', 'relative.json', '--api-key-file', 'C:\\protected\\broker.key'],
  [
    'node',
    'check',
    '--plan-file',
    'C:\\protected\\missing.json',
    '--api-key-file',
    'C:\\protected\\broker.key',
  ],
  [
    'node',
    'check',
    '--plan-file',
    'C:\\protected\\contract.json',
    '--api-key-file',
    'relative.key',
  ],
]) {
  await assert.rejects(
    runProviderContractCheck(invalidArgv, { readFileImpl, requestImpl, writeOutput: () => {} }),
  );
}

for (const [path, contents, pattern] of [
  ['C:\\protected\\contract.json', Buffer.from('{'), /invalid JSON/],
  ['C:\\protected\\contract.json', Buffer.alloc(0), /file size is invalid/],
  ['C:\\protected\\broker.key', Buffer.from('invalid'), /valid scoped Broker API key/],
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
oversizedFiles.set('C:\\protected\\contract.json', Buffer.alloc(32 * 1024 + 1));
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
