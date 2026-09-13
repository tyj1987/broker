#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createBrokerClient, parseArgs } from '../mcp-server.js';
import {
  ProviderContractError,
  createProviderContractRunner,
} from '../lib/provider-contract-runner.js';

const ALLOWED_ARGUMENTS = new Set([
  'broker',
  'plan-file',
  'api-key-file',
  'client-cert-file',
  'client-key-file',
  'ca-file',
]);
const MAX_PLAN_BYTES = 32 * 1024;
const MAX_API_KEY_BYTES = 256;
const MAX_TLS_FILE_BYTES = 1024 * 1024;

function readBoundedFile(path, label, maxBytes, readFileImpl) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new Error(`${label} path must be absolute`);
  }
  let value;
  try {
    value = readFileImpl(path);
  } catch {
    throw new Error(`${label} file could not be read`);
  }
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (bytes.byteLength < 1 || bytes.byteLength > maxBytes) {
    throw new Error(`${label} file size is invalid`);
  }
  return bytes;
}

function parsePlan(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('Provider contract plan is invalid JSON');
  }
}

export function safeProviderContractErrorCode(error) {
  if (
    error instanceof ProviderContractError &&
    /^contract_[a-z0-9_]{1,54}$/.test(error.code || '') &&
    !/(secret|password|private|material|canary)/i.test(error.code)
  ) {
    return error.code;
  }
  return 'provider_contract_check_failed';
}

export async function runProviderContractCheck(
  argv = process.argv,
  {
    readFileImpl = readFileSync,
    requestImpl,
    writeOutput = (value) => process.stdout.write(`${value}\n`),
  } = {},
) {
  const args = parseArgs(argv);
  if (Object.keys(args).some((name) => !ALLOWED_ARGUMENTS.has(name))) {
    throw new Error('Provider contract argument is not allowed');
  }
  if (
    (args['client-cert-file'] && !args['client-key-file']) ||
    (args['client-key-file'] && !args['client-cert-file'])
  ) {
    throw new Error('Broker client certificate and key must be configured together');
  }

  const plan = parsePlan(
    readBoundedFile(args['plan-file'], 'Provider contract plan', MAX_PLAN_BYTES, readFileImpl),
  );
  const apiKey = readBoundedFile(
    args['api-key-file'],
    'Broker API key',
    MAX_API_KEY_BYTES,
    readFileImpl,
  )
    .toString('utf8')
    .trim();
  const optionalFile = (name, label) =>
    args[name] ? readBoundedFile(args[name], label, MAX_TLS_FILE_BYTES, readFileImpl) : undefined;
  const callBroker = createBrokerClient({
    origin: args.broker || 'https://127.0.0.1:18443',
    apiKey,
    cert: optionalFile('client-cert-file', 'Broker client certificate'),
    key: optionalFile('client-key-file', 'Broker client key'),
    ca: optionalFile('ca-file', 'Broker CA'),
    ...(requestImpl ? { requestImpl } : {}),
  });
  const receipt = await createProviderContractRunner({ callBroker })(plan);
  writeOutput(JSON.stringify(receipt));
  return receipt;
}

/* c8 ignore start -- exercised by process invocation, not imported unit tests */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runProviderContractCheck().catch((error) => {
    console.error(`[provider-contract] failed (${safeProviderContractErrorCode(error)})`);
    process.exitCode = 1;
  });
}
/* c8 ignore stop */
