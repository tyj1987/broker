import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const service = read('../deploy/systemd/secret-broker.service');
const deployment = read('../deploy/helm/broker/templates/deployment.yaml');
const values = read('../deploy/helm/broker/values.yaml');
const migration = read('../deploy/PRODUCTION-MIGRATION.md');
const workflow = read('../.github/workflows/ci.yml');

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
assert.match(workflow, /Dir::Etc::sourcelist=\/etc\/apt\/sources\.list\.d\/ubuntu\.sources/);
assert.match(workflow, /secrets\.stateKeySecretName=broker-state-key/);

console.log(
  'deployment state boundary: protected key, persistent state, single replica and fail-closed bootstrap passed',
);
