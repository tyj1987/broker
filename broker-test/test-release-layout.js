import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const dockerfile = readFileSync(resolve(root, 'Dockerfile'), 'utf8');
const deployWorkflow = readFileSync(resolve(root, '.github/workflows/deploy-ecs.yml'), 'utf8');
const deployScript = readFileSync(resolve(root, 'deploy/bin/secret-broker-deploy'), 'utf8');

assert.equal((dockerfile.match(/COPY providers\/ \.\/providers\//g) || []).length, 2);
assert.match(deployWorkflow, /-C \.\. providers/);
assert.match(deployScript, /-d "\$PAYLOAD\/providers"/);
assert.match(deployScript, /-name '\*\.yaml'/);
const manifests = readdirSync(resolve(root, 'providers')).filter((name) => name.endsWith('.yaml'));
assert.ok(manifests.length > 0, 'provider manifests must be present in source');

console.log(`release layout: ${manifests.length} provider manifests included in image and ECS payload`);
