import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const service = read('../deploy/systemd/secret-broker.service');
const policyService = read('../deploy/systemd/secret-broker-policy.service');
const deployment = read('../deploy/helm/broker/templates/deployment.yaml');
const values = read('../deploy/helm/broker/values.yaml');
const migration = read('../deploy/PRODUCTION-MIGRATION.md');
const deployHelper = read('../deploy/bin/secret-broker-deploy');
const nginx = read('../deploy/nginx/broker.52trz.com.conf');
const workflow = read('../.github/workflows/ci.yml');
const deployWorkflow = read('../.github/workflows/deploy-ecs.yml');
const dockerfile = read('../Dockerfile');
const server = read('../broker/server.js');

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
assert.match(service, /Environment=BROKER_HEALTH_SOCKET=\/run\/secret-broker-health\/health\.sock/);
assert.match(service, /RuntimeDirectory=secret-broker-health/);
assert.match(service, /RuntimeDirectoryMode=0700/);
assert.doesNotMatch(service, /BROKER_HEALTH_BIND=/);
assert.doesNotMatch(service, /RuntimeDirectory=secret-broker(?:\r?\n|$)/);
assert.match(policyService, /RuntimeDirectory=secret-broker/);
assert.doesNotMatch(policyService, /RuntimeDirectory=secret-broker-health/);
assert.match(migration, /`root:broker`, `0750`/);
assert.match(migration, /Separately extract the verified candidate artifact/);
assert.match(deployHelper, /readonly NODE_RUNTIME=\/opt\/secret-broker\/runtime\/node\/bin\/node/);
assert.match(deployHelper, /readonly GH_CLI=\/usr\/bin\/gh/);
assert.match(deployHelper, /readonly SETFACL=\/usr\/bin\/setfacl/);
assert.match(deployHelper, /github-attestation-trusted-root\.jsonl/);
assert.match(deployHelper, /readonly HEALTH_SOCKET=\/run\/secret-broker-health\/health\.sock/);
assert.match(deployHelper, /chown -R root:broker/);
assert.match(deployHelper, /find "\$PAYLOAD" -type d -exec chmod 0550/);
assert.match(deployHelper, /u:broker-github-signer:--x,u:broker-aliyun-signer:--x/);
assert.match(deployHelper, /u:broker-github-signer:r-x/);
assert.match(deployHelper, /u:broker-aliyun-signer:r-x/);
assert.doesNotMatch(deployHelper, /chown[^\n]*broker-(?:github|aliyun)-signer/);
assert.match(deployHelper, /for _ in \{1\.\.20\}/);
assert.match(deployHelper, /-f "\$PAYLOAD\/tools\/registry\.json"/);
assert.match(deployHelper, /\.failed-\$RELEASE_SHA-/);
assert.match(deployHelper, /runuser -u broker -- env AUDIT_DIR=/);
assert.match(deployHelper, /candidate cannot read the current audit chain/);
assert.match(deployHelper, /provider-contract-evidence-check\.js/);
assert.match(deployHelper, /candidate provider contract evidence is unavailable/);
assert.match(deployHelper, /attestation verify "broker-\$RELEASE_SHA\.tgz"/);
assert.match(deployHelper, /--bundle "broker-\$RELEASE_SHA\.attestation\.jsonl"/);
assert.match(deployHelper, /--custom-trusted-root "\$ATTESTATION_TRUST_ROOT"/);
assert.match(deployHelper, /--repo tyj1987\/broker/);
assert.match(deployHelper, /--signer-workflow tyj1987\/broker\/\.github\/workflows\/deploy-ecs\.yml/);
assert.match(deployHelper, /--source-ref refs\/heads\/master/);
assert.match(deployHelper, /--source-digest "\$RELEASE_SHA"/);
assert.match(deployHelper, /--deny-self-hosted-runners/);
assert.match(deployWorkflow, /gh attestation download/);
assert.match(deployWorkflow, /broker-\$\{\{ env\.RELEASE_SHA \}\}\.attestation\.jsonl/);
assert.ok(
  deployHelper.indexOf('release provenance verification failed') <
    deployHelper.indexOf('tar --extract'),
  'untrusted payload must be rejected before extraction or candidate execution',
);
assert.match(
  deployHelper,
  /provider-contract-evidence-check\.js[\s\S]*FAILED_CANDIDATE=.*\.failed-\$RELEASE_SHA-[\s\S]*mv -- "\$RELEASE" "\$FAILED_CANDIDATE"/,
);
assert.match(deployHelper, /secret-broker-production-preflight\.mjs/);
assert.match(deployHelper, /production acceptance remains closed pending fresh release evidence/);
assert.ok(
  deployHelper.indexOf('candidate provider contract evidence is unavailable')
    < deployHelper.indexOf('ln -s "releases/$RELEASE_SHA"'),
  'candidate evidence must be verified before the release symlink changes',
);
assert.ok(
  deployHelper.indexOf('if ! full_preflight; then') > deployHelper.indexOf('if ! wait_ready; then'),
  'the complete production preflight must run after post-switch readiness',
);
assert.doesNotMatch(deployHelper, /rollback\(\)[\s\S]*wait_ready && \\\n+    full_preflight/);
assert.match(deployHelper, /rollback failed readiness verification/);
assert.match(deployHelper, /exit 71/);
assert.match(deployHelper, /secret-broker-audit-exporter\.service/);
assert.match(deployHelper, /secret-broker-audit-signer\.service/);
assert.match(deployHelper, /secret-broker-audit-store\.service/);
assert.match(deployHelper, /secret-broker-audit-recovery\.service/);
assert.match(deployHelper, /audit service identity does not match the pinned contract/);
assert.doesNotMatch(deployHelper, /chown -R broker:broker/);
assert.match(server, /required local health listener failed; terminating/);
assert.match(server, /server\.close\(\(\) => process\.exit\(1\)\)/);
assert.doesNotMatch(server, /local health listener failed:', e\.message/);
assert.match(deployWorkflow, /cp -R tools broker\/tools/);
assert.match(
  deployWorkflow,
  /name: Build Go production binaries[\s\S]*working-directory: core[\s\S]*-o \.\.\/broker\/bin\/secret-broker-policy \.\/cmd\/policy-server/,
);
assert.match(
  deployWorkflow,
  /-o \.\.\/broker\/bin\/secret-broker-github-signer \.\/cmd\/github-signer/,
);
assert.match(
  deployWorkflow,
  /-o \.\.\/broker\/bin\/secret-broker-aliyun-signer \.\/cmd\/aliyun-signer/,
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
