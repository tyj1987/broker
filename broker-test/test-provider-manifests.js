import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../broker/package.json', import.meta.url));
const { parse } = require('yaml');

const providerDir = resolve(import.meta.dirname, '../providers');
const manifestSchema = JSON.parse(readFileSync(resolve(providerDir, 'schema.json'), 'utf8'));
const schemaKeys = new Set(Object.keys(manifestSchema.properties || {}));
const authenticationSchemaKeys = new Set(
  Object.keys(manifestSchema.properties?.authentication?.properties || {}),
);
const expected = new Set([
  'aliyun',
  'cloudflare',
  'deepseek',
  'docker',
  'github',
  'google_drive',
  'openai',
  'postgresql',
  'ssh',
  'tencent',
]);
const manifests = readdirSync(providerDir).filter((name) => name.endsWith('.yaml'));
const ids = new Set();
const manifestOperations = new Map();

for (const filename of manifests) {
  const document = parse(readFileSync(resolve(providerDir, filename), 'utf8'));
  for (const key of Object.keys(document)) {
    if (!schemaKeys.has(key)) throw new Error(`${filename}: field ${key} is missing from schema.json`);
  }
  for (const key of Object.keys(document.authentication || {})) {
    if (!authenticationSchemaKeys.has(key)) {
      throw new Error(`${filename}: authentication field ${key} is missing from schema.json`);
    }
  }
  if (document.manifest_version !== 1) throw new Error(`${filename}: unsupported manifest version`);
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(document.id || '')) throw new Error(`${filename}: invalid id`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(document.checked_at || '')
    || !Number.isFinite(Date.parse(`${document.checked_at}T00:00:00Z`))) {
    throw new Error(`${filename}: checked_at must be an ISO date`);
  }
  if (ids.has(document.id)) throw new Error(`${filename}: duplicate id`);
  ids.add(document.id);
  if (document.status === 'production') throw new Error(`${filename}: cannot be production before a real contract test`);
  if (!Array.isArray(document.official_docs) || document.official_docs.length < 1) {
    throw new Error(`${filename}: at least one official documentation URL is required`);
  }
  if (!Array.isArray(document.origins)) throw new Error(`${filename}: origins must be an array`);
  if (!Array.isArray(document.authentication?.priority) || document.authentication.priority.length < 1
    || !document.authentication.inject || typeof document.authentication.inject !== 'object'
    || typeof document.authentication.rotation !== 'string' || !document.authentication.rotation
    || typeof document.authentication.revocation !== 'string' || !document.authentication.revocation) {
    throw new Error(`${filename}: authentication priority, injection, rotation and revocation are required`);
  }
  if (document.contract_test?.required !== true || document.contract_test?.last_result !== 'not_run'
    || typeof document.contract_test?.account !== 'string' || !document.contract_test.account) {
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
  manifestOperations.set(document.id, operationIds);
}

for (const id of expected) {
  if (!ids.has(id)) throw new Error(`missing initial provider manifest: ${id}`);
}
const registry = JSON.parse(readFileSync(resolve(import.meta.dirname, '../tools/registry.json'), 'utf8'));
const registryOperations = new Map();
for (const tool of registry.tools || []) {
  if (tool.provider === 'broker') continue;
  if (!manifestOperations.has(tool.provider)) {
    throw new Error(`tool registry provider ${tool.provider} has no provider manifest`);
  }
  const operations = registryOperations.get(tool.provider) || new Set();
  operations.add(tool.operation_id);
  registryOperations.set(tool.provider, operations);
  if (!manifestOperations.get(tool.provider).has(tool.operation_id)) {
    throw new Error(`tool registry operation ${tool.provider}:${tool.operation_id} is absent from its manifest`);
  }
}
for (const [provider, operations] of manifestOperations) {
  for (const operation of operations) {
    if (!registryOperations.get(provider)?.has(operation)) {
      throw new Error(`manifest operation ${provider}:${operation} is absent from the tool registry`);
    }
  }
}
console.log(`provider manifests: ${manifests.length} validated; all remain contract-gated`);
