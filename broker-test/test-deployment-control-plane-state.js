import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const service = read('../deploy/systemd/secret-broker.service');
const deployment = read('../deploy/helm/broker/templates/deployment.yaml');
const values = read('../deploy/helm/broker/values.yaml');
const migration = read('../deploy/PRODUCTION-MIGRATION.md');
const deployHelper = read('../deploy/bin/secret-broker-deploy');
const nginx = read('../deploy/nginx/broker.52trz.com.conf');
const workflow = read('../.github/workflows/ci.yml');
const deployWorkflow = read('../.github/workflows/deploy-ecs.yml');
const dockerfile = read('../Dockerfile');

assert.match(service, /LoadCredential=control-plane-state\.key:/);
assert.match(service, /CONTROL_PLANE_STATE_KEY_FILE=%d\/control-plane-state\.key/);
assert.match(
  service,
  /CONTROL_PLANE_STATE_PATH=\/var\/lib\/secret-broker\/control-plane-state\.enc/,
);
assert.match(deployment, /persistence\.enabled must be true for durable control-plane state/);
assert.match(deployment, /supports exactly one replica/);
assert.match(
  deployment,
  /name: CONTROL_PLANE_STATE_PATH[\s\S]*\/var\/lib\/broker\/control-plane-state\.enc/,
);
assert.match(
  deployment,
  /name: CONTROL_PLANE_STATE_KEY_FILE[\s\S]*\/etc\/broker\/state\/control-plane-state\.key/,
);
assert.match(deployment, /required "secrets\.stateKeySecretName is required"/);
assert.match(values, /replicaCount: 1/);
assert.match(values, /stateKeySecretName: ""/);
assert.match(migration, /initializer refuses to overwrite an existing state file/i);
assert.match(migration, /production startup must fail closed/i);
assert.match(migration, /not approved for production scheduling/i);
assert.doesNotMatch(service, /CONTROL_PLANE_STATE_KEY=/);
assert.match(service, /ExecStart=\/opt\/secret-broker\/runtime\/node\/bin\/node/);
assert.match(service, /Environment=TLS_CA=\/etc\/secret-broker\/pki\/ca\/ca\.crt/);
assert.match(service, /Environment=TLS_KEY=\/etc\/secret-broker\/pki\/server\/server\.key/);
assert.match(migration, /`root:broker`, `0750`/);
assert.match(migration, /Separately extract the verified candidate artifact/);
assert.match(deployHelper, /readonly NODE_RUNTIME=\/opt\/secret-broker\/runtime\/node\/bin\/node/);
assert.match(deployHelper, /chown -R root:broker/);
assert.match(deployHelper, /find "\$RELEASE" -type d -exec chmod 0550/);
assert.match(deployHelper, /for _ in \{1\.\.20\}/);
assert.match(deployHelper, /-f "\$RELEASE\/tools\/registry\.json"/);
assert.doesNotMatch(deployHelper, /chown -R broker:broker/);
assert.match(deployWorkflow, /cp -R tools broker\/tools/);
assert.match(
  deployWorkflow,
  /name: Build Go policy core[\s\S]*working-directory: core[\s\S]*-o \.\.\/broker\/bin\/secret-broker-policy \.\/cmd\/policy-server/,
);
assert.match(nginx, /ssl_certificate \/etc\/nginx\/cert\/broker\.52trz\.com\/fullchain\.pem/);
assert.match(nginx, /proxy_ssl_verify on;/);
assert.match(nginx, /proxy_ssl_protocols TLSv1\.3;/);
assert.doesNotMatch(nginx, /proxy_ssl_verify off;/);
assert.match(workflow, /Dir::Etc::sourcelist=\/etc\/apt\/sources\.list\.d\/ubuntu\.sources/);
assert.match(workflow, /secrets\.stateKeySecretName=broker-state-key/);
assert.doesNotMatch(workflow, /branches:\s*\[master,\s*'codex\/\*\*'\]/);
assert.match(workflow, /^  workflow_dispatch:$/m);
assert.match(workflow, /name: Production container validation/);
assert.match(workflow, /push: false/);
assert.match(workflow, /image-ref: secret-broker:\$\{\{ github\.sha \}\}/);
assert.match(workflow, /subject-name: secret-broker/);
assert.doesNotMatch(workflow, /push-to-registry:\s*true/);
assert.doesNotMatch(workflow, /packages:\s*write/);
assert.match(dockerfile, /-require=google\.golang\.org\/grpc@v1\.83\.2/);
assert.doesNotMatch(dockerfile, /-require=google\.golang\.org\/grpc@v1\.83\.1/);

console.log(
  'deployment state boundary: protected key, persistent state, single replica and fail-closed bootstrap passed',
);
