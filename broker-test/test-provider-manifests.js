import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../broker/package.json', import.meta.url));
const { parse } = require('yaml');

const providerDir = resolve(import.meta.dirname, '../providers');
const expected = new Set(['aliyun', 'cloudflare', 'docker', 'github', 'openai', 'tencent']);
const manifests = readdirSync(providerDir).filter((name) => name.endsWith('.yaml'));
const ids = new Set();

for (const filename of manifests) {
  const document = parse(readFileSync(resolve(providerDir, filename), 'utf8'));
  if (document.manifest_version !== 1) throw new Error(`${filename}: unsupported manifest version`);
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(document.id || '')) throw new Error(`${filename}: invalid id`);
  if (ids.has(document.id)) throw new Error(`${filename}: duplicate id`);
  ids.add(document.id);
  if (document.status === 'production') throw new Error(`${filename}: cannot be production before a real contract test`);
  if (document.contract_test?.required !== true || document.contract_test?.last_result !== 'not_run') {
    throw new Error(`${filename}: must retain an explicit unverified contract gate`);
  }
  for (const source of document.official_docs || []) {
    const url = new URL(source);
    if (url.protocol !== 'https:') throw new Error(`${filename}: documentation URL must use HTTPS`);
  }
  for (const origin of document.origins || []) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error(`${filename}: invalid pinned origin`);
    }
  }
  const operationIds = new Set();
  for (const operation of document.operations || []) {
    if (operationIds.has(operation.id)) throw new Error(`${filename}: duplicate operation id`);
    operationIds.add(operation.id);
    if (!operation.path_template?.startsWith('/') || operation.path_template.startsWith('//')) {
      throw new Error(`${filename}: operation path is not origin-relative`);
    }
    if (operation.mutating && operation.approval === 'none') {
      throw new Error(`${filename}: mutating operation requires approval`);
    }
  }
}

for (const id of expected) {
  if (!ids.has(id)) throw new Error(`missing initial provider manifest: ${id}`);
}
console.log(`provider manifests: ${manifests.length} validated; all remain contract-gated`);
