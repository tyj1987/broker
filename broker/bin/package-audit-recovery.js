#!/usr/bin/env node
// Build-time only: a closed dependency set for the independent recovery UID.
import { lstatSync, readdirSync, readFileSync, writeFileSync, mkdirSync, mkdtempSync,
  renameSync, rmSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

export const RECOVERY_FILES = Object.freeze([
  'bin/audit-recovery-service-check.js', 'bin/audit-recovery-check.js',
  ...['audit-recovery-check', 'audit-recovery-chain', 'audit-anchor-recovery',
    'audit-anchor', 'audit-hash-chain', 'redact', 'protected-input-file',
    'local-audit-anchor-store-client'].map(name => `lib/${name}.js`),
]);
const digest = data => createHash('sha256').update(data).digest('hex');
const error = () => { throw new Error('Recovery package is invalid'); };
function filesUnder(root, prefix = '') {
  const rootInfo = lstatSync(join(root, prefix));
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) error();
  const names = [];
  for (const name of readdirSync(join(root, prefix)).sort()) {
    const path = join(prefix, name);
    const stat = lstatSync(join(root, path));
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) error();
    if (stat.isDirectory()) names.push(...filesUnder(root, path));
    else names.push(path.split('\\').join('/'));
    if (names.length > 2048) error();
  }
  return names;
}

export function packageRecovery(root, { verify = false } = {}) {
  const target = join(root, 'recovery-runtime');
  const expectedNames = ['package.json', ...RECOVERY_FILES, 'node_modules/yaml/package.json',
    'node_modules/yaml/LICENSE', ...filesUnder(join(root, 'node_modules/yaml/dist')).map(name => `node_modules/yaml/dist/${name}`)].sort();
  if (verify) {
    const list = filesUnder(target).filter(name => name !== 'manifest.json');
    if (JSON.stringify(list.sort()) !== JSON.stringify(expectedNames)) error();
    const manifest = JSON.parse(readFileSync(join(target, 'manifest.json'), 'utf8'));
    if (manifest.version !== 1 || JSON.stringify(list.sort()) !== JSON.stringify(Object.keys(manifest.files).sort())) error();
    for (const name of list) {
      const expected = name === 'package.json' ? Buffer.from('{\"type\":\"module\",\"private\":true}\n') : readFileSync(join(root, name));
      const actual = readFileSync(join(target, name));
      if (!actual.equals(expected) || digest(actual) !== manifest.files[name]) error();
    }
    return Object.freeze({ files: list.length });
  }
  if (existsSync(target)) error();
  const yamlRoot = join(root, 'node_modules/yaml');
  if (!lstatSync(yamlRoot).isDirectory() || lstatSync(yamlRoot).isSymbolicLink()) error();
  const yamlPackage = JSON.parse(readFileSync(join(yamlRoot, 'package.json'), 'utf8'));
  const expected = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).dependencies.yaml;
  if (yamlPackage.name !== 'yaml' || yamlPackage.version !== expected) error();
  const yamlFiles = ['package.json', 'LICENSE', ...filesUnder(join(yamlRoot, 'dist')).map(name => `dist/${name}`)];
  const stage = mkdtempSync(join(root, '.recovery-package-'));
  const files = {};
  const put = (name, bytes) => {
    if (bytes.length > 1024 * 1024) error();
    const path = join(stage, name); mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes, { mode: 0o600 }); files[name] = digest(bytes);
  };
  const copy = (source, name) => {
    const info = lstatSync(source);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) error();
    put(name, readFileSync(source));
  };
  try {
    put('package.json', Buffer.from('{"type":"module","private":true}\n'));
    for (const name of RECOVERY_FILES) copy(join(root, name), name);
    for (const name of yamlFiles) copy(join(yamlRoot, name), `node_modules/yaml/${name}`);
    writeFileSync(join(stage, 'manifest.json'), JSON.stringify({ version: 1, files }, null, 2) + '\n');
    renameSync(stage, target);
  } finally { rmSync(stage, { force: true, recursive: true }); }
  return packageRecovery(root, { verify: true });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || (args.length === 1 && args[0] !== '--verify')) error();
    const root = fileURLToPath(new URL('../', import.meta.url));
    const result = packageRecovery(root, { verify: args[0] === '--verify' });
    console.log(JSON.stringify({ status: 'recovery_package_verified', files: result.files }));
  } catch { console.error('recovery_package_invalid'); process.exitCode = 1; }
}
