// broker-test/test-client-bundle.js — one-time certificate bundle invariants

import { readFileSync } from 'node:fs';
import { createClientBundle } from '../broker/lib/client-bundle.js';

let passed = 0;
let failed = 0;

function ok(name, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL  ${name}`);
  }
}

function throwsWith(fn, pattern) {
  try {
    fn();
    return false;
  } catch (error) {
    return pattern.test(error.message);
  }
}

function localEntries(zip) {
  const entries = new Map();
  let offset = 0;
  while (offset + 30 <= zip.length && zip.readUInt32LE(offset) === 0x04034b50) {
    const size = zip.readUInt32LE(offset + 18);
    const nameLength = zip.readUInt16LE(offset + 26);
    const extraLength = zip.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const name = zip.subarray(nameStart, nameStart + nameLength).toString('utf8');
    const data = zip.subarray(dataStart, dataStart + size);
    entries.set(name, data);
    offset = dataStart + size;
  }
  return entries;
}

const certPem = '-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----\n';
const keyPem = '-----BEGIN PRIVATE KEY-----\nKEYDATA\n-----END PRIVATE KEY-----\n';
const caPem = '-----BEGIN CERTIFICATE-----\nCADATA\n-----END CERTIFICATE-----\n';

console.log('[bundle contents]');
{
  const zip = createClientBundle({ name: 'client.alice', certPem, keyPem, caPem });
  ok('bundle is a ZIP buffer', Buffer.isBuffer(zip) && zip.readUInt32LE(0) === 0x04034b50);
  const entries = localEntries(zip);
  ok('bundle contains client certificate', entries.get('client.alice.crt')?.toString() === certPem);
  ok('bundle contains client private key', entries.get('client.alice.key')?.toString() === keyPem);
  ok('bundle contains CA certificate', entries.get('ca.crt')?.toString() === caPem);
  const installer = entries.get('install.sh')?.toString() || '';
  ok('bundle contains install script', installer.startsWith('#!/bin/sh'));
  ok('installer fails closed', installer.includes('set -eu'));
  ok('installer uses restrictive umask', installer.includes('umask 077'));
  ok('installer sets private-key mode 0600', installer.includes('chmod 600'));
  ok('installer sets public certificate mode 0644', installer.includes('chmod 644'));
}

console.log('\n[input validation]');
{
  ok(
    'path traversal client name is rejected',
    throwsWith(
      () => createClientBundle({ name: '../escape', certPem, keyPem, caPem }),
      /Invalid client name/,
    ),
  );
  ok(
    'empty certificate is rejected',
    throwsWith(
      () => createClientBundle({ name: 'client.alice', certPem: '', keyPem, caPem }),
      /certPem is required/,
    ),
  );
  ok(
    'empty private key is rejected',
    throwsWith(
      () => createClientBundle({ name: 'client.alice', certPem, keyPem: '', caPem }),
      /keyPem is required/,
    ),
  );
}

console.log('\n[secure-default server wiring]');
{
  const server = readFileSync(new URL('../broker/server.js', import.meta.url), 'utf8');
  const dashboard = readFileSync(
    new URL('../broker/dashboard/admin/clients.js', import.meta.url),
    'utf8',
  );
  ok(
    'private-key retention is explicit opt-in',
    server.includes("process.env.BROKER_RETAIN_CLIENT_PRIVATE_KEYS === '1'"),
  );
  ok(
    'issuance removes key before config persistence',
    server.indexOf('deleteClientKeyFile(name, { strict: true })') <
      server.indexOf('await persistConfig()', server.indexOf('async function issueAndPersist')),
  );
  ok(
    'issuance returns an in-memory bundle',
    server.includes('bundle_base64: issuance.bundle.toString'),
  );
  ok(
    'one-time bundle is included in all three issuance responses',
    server.split("bundle_base64: issuance.bundle.toString('base64')").length - 1 === 3,
  );
  ok('legacy bundle is disabled by default', server.includes('if (!RETAIN_CLIENT_PRIVATE_KEYS)'));
  ok('legacy bundle requires POST', server.includes('Use POST with {verify}'));
  ok(
    'legacy binary response uses hardened helper',
    server.includes('return sendBufferSafe(res, 200, bundle'),
  );
  ok('dashboard no longer uses a repeatable bundle URL', !dashboard.includes('/bundle`'));
  ok(
    'dashboard downloads returned base64 in memory',
    dashboard.includes('downloadOneTimeBundle(r.bundle_base64'),
  );
  ok('dashboard clears secret DOM on close', dashboard.includes('out.replaceChildren()'));
}

console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
