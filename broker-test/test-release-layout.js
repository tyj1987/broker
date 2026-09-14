import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const dockerfile = readFileSync(resolve(root, 'Dockerfile'), 'utf8');
const deployWorkflow = readFileSync(resolve(root, '.github/workflows/deploy-ecs.yml'), 'utf8');
const deployScript = readFileSync(resolve(root, 'deploy/bin/secret-broker-deploy'), 'utf8');

assert.equal((dockerfile.match(/COPY providers\/ \.\/providers\//g) || []).length, 2);
assert.match(deployWorkflow, /-C \.\. providers/);
assert.match(deployWorkflow, /cp deploy\/bin\/secret-broker-production-preflight\.mjs broker\/bin\//);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-github-signer \.\/cmd\/github-signer/);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-aliyun-signer \.\/cmd\/aliyun-signer/);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-audit-store \.\/cmd\/audit-store/);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-audit-signer \.\/cmd\/audit-signer/);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-audit-store-health \.\/cmd\/audit-store-health/);
assert.match(deployWorkflow, /broker\/bin\/secret-broker-audit-mirror-worker \.\/cmd\/audit-mirror-worker/);
for (const binary of [
  'secret-broker-audit-signer',
  'secret-broker-audit-store',
  'secret-broker-audit-store-health',
  'secret-broker-audit-mirror-worker',
]) {
  assert.match(deployScript, new RegExp(`PAYLOAD/bin/${binary}`));
}
assert.match(deployScript, /-d "\$PAYLOAD\/providers"/);
assert.match(deployScript, /-name '\*\.yaml'/);
assert.match(deployScript, /PAYLOAD\/bin\/secret-broker-audit-exporter/);
assert.match(deployScript, /broker-audit-exporter:r-x/);
assert.match(dockerfile, /rm -f package-lock\.json bin\/secret-broker-audit-exporter/);
assert.match(deployScript, /provider-contract-evidence-check\.js/);
const manifests = readdirSync(resolve(root, 'providers')).filter((name) => name.endsWith('.yaml'));
assert.ok(manifests.length > 0, 'provider manifests must be present in source');

console.log(`release layout: ${manifests.length} provider manifests included in image and ECS payload`);
