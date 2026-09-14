#!/usr/bin/env node

import { fileURLToPath } from 'node:url';

import { parseArgs } from '../mcp-server.js';
import {
  TrustDomainCutoverError,
  renderTrustDomainCutoverReport,
} from '../lib/trust-domain-cutover.js';
import { readProtectedInputFile } from '../lib/protected-input-file.js';

const ALLOWED_ARGUMENTS = new Set(['plan-file']);
const MAX_PLAN_BYTES = 64 * 1024;

function parsePlan(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('Trust-domain cutover plan is invalid JSON');
  }
}

export function safeTrustDomainCutoverErrorCode(error) {
  if (
    error instanceof TrustDomainCutoverError &&
    ['cutover_plan_invalid', 'cutover_evaluation_invalid'].includes(error.code)
  ) {
    return error.code;
  }
  return 'trust_domain_cutover_check_failed';
}

export function runTrustDomainCutoverCheck(
  argv = process.argv,
  {
    readProtectedFileImpl = readProtectedInputFile,
    now = () => Date.now(),
    writeOutput = (value) => process.stdout.write(value),
  } = {},
) {
  const args = parseArgs(argv);
  if (
    Object.keys(args).some((name) => !ALLOWED_ARGUMENTS.has(name)) ||
    typeof args['plan-file'] !== 'string'
  ) {
    throw new Error('Trust-domain cutover arguments are invalid');
  }
  const bytes = readProtectedFileImpl(
    args['plan-file'],
    'Trust-domain cutover plan',
    MAX_PLAN_BYTES,
    { sensitive: true },
  );
  if (!Buffer.isBuffer(bytes) || bytes.byteLength < 1 || bytes.byteLength > MAX_PLAN_BYTES) {
    throw new Error('Trust-domain cutover plan file size is invalid');
  }
  const report = renderTrustDomainCutoverReport(parsePlan(bytes), { now });
  writeOutput(report);
  return report;
}

/* c8 ignore start -- exercised by process invocation, not imported unit tests */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    runTrustDomainCutoverCheck();
  } catch (error) {
    console.error(`[trust-domain-cutover] failed (${safeTrustDomainCutoverErrorCode(error)})`);
    process.exitCode = 1;
  }
}
/* c8 ignore stop */
