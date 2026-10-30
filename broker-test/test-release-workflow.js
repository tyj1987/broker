// broker-test/test-release-workflow.js — release, CI and production image invariants

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../broker/package.json', import.meta.url));
const { parse: parseYaml } = require('yaml');

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

function count(text, needle) {
  return text.split(needle).length - 1;
}

function read(relativePath) {
  return readFileSync(new URL(`../${relativePath}`, import.meta.url), 'utf8');
}

const workflowNames = readdirSync(new URL('../.github/workflows/', import.meta.url))
  .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
  .sort();
const workflows = Object.fromEntries(
  workflowNames.map((name) => [name, read(`.github/workflows/${name}`)]),
);
const allWorkflows = Object.values(workflows).join('\n');
const release = workflows['release.yml'];
const ci = workflows['ci.yml'];
const ciV4 = workflows['ci-v4.yml'];
const deploy = workflows['deploy.yml'];
const dockerfile = read('Dockerfile');
const composeSource = read('docker-compose.yml');
const dockerignore = read('.dockerignore');
const taskfile = read('Taskfile.yml');
const installSops = read('scripts/ci/install-sops.sh');
const installAge = read('scripts/ci/install-age.sh');
const injectAliyun = read('scripts/broker/inject-aliyun-ak.sh');
const nginxBroker = read('scripts/broker/nginx-broker.52trz.com.conf');
const gitignore = read('.gitignore');
const pkg = JSON.parse(read('broker/package.json'));
const lock = JSON.parse(read('broker/package-lock.json'));

console.log('[workflow YAML syntax]');
for (const [name, source] of Object.entries(workflows)) {
  let document = null;
  try {
    document = parseYaml(source);
  } catch (error) {
    console.error(`        ${name}: ${error.message}`);
  }
  ok(`${name} parses and declares jobs`, !!document?.jobs);
}

console.log('\n[quality gate wiring]');
ok(
  'package exposes quality:gate',
  pkg.scripts?.['quality:gate'] ===
    'npm run lint && npm run format:check && npm run test:verify-all',
);
ok('package excludes unsupported Node 20', pkg.engines?.node === '>=22.0.0');
ok('package-lock version matches package', lock.version === pkg.version);
ok('package-lock engine matches package', lock.packages?.['']?.engines?.node === pkg.engines.node);
ok('cross-platform CI runs quality gate', ciV4.includes('npm run quality:gate'));
ok('release has quality-gate job', release.includes('\n  quality-gate:\n'));
ok('release build depends on quality gate', release.includes('needs: quality-gate'));
ok('dual-cloud deploy has quality gate', deploy.includes('\n  quality-gate:\n'));
ok('dual-cloud build depends on quality gate', deploy.includes('needs: quality-gate'));
ok(
  'release quality gate audits production dependencies',
  release.includes('npm audit --omit=dev --audit-level=high'),
);

console.log('\n[GitHub Actions runtime versions]');
for (const required of [
  'actions/checkout@v7',
  'actions/setup-node@v7',
  'actions/setup-python@v7',
  'actions/upload-artifact@v7',
  'docker/setup-qemu-action@v4',
  'docker/setup-buildx-action@v4',
  'docker/login-action@v4',
  'docker/metadata-action@v6',
  'docker/build-push-action@v7',
  'sigstore/cosign-installer@v4',
]) {
  ok(`workflows use ${required}`, allWorkflows.includes(required));
}
ok('legacy checkout v4 is absent', !allWorkflows.includes('actions/checkout@v4'));
ok('legacy setup-node v4 is absent', !allWorkflows.includes('actions/setup-node@v4'));
ok('legacy setup-python v5 is absent', !allWorkflows.includes('actions/setup-python@v5'));
ok('legacy upload-artifact v4 is absent', !allWorkflows.includes('actions/upload-artifact@v4'));
ok('legacy gitleaks v2 is absent', !allWorkflows.includes('gitleaks/gitleaks-action@v2'));
ok('CI no longer selects Node 20', !allWorkflows.match(/node-version:\s*['"]?20(?:\.x)?['"]?/));

console.log('\n[release image signing and SBOM]');
ok(
  'build-push step has stable id',
  release.includes('id: build\n        uses: docker/build-push-action@v7'),
);
ok(
  'both SBOMs scan the published image digest',
  count(
    release,
    'image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}',
  ) === 2,
);
ok('SPDX output file is explicit', release.includes('output-file: broker.spdx.json'));
ok('CycloneDX output file is explicit', release.includes('output-file: broker.cyclonedx.json'));
ok(
  'implicit SBOM artifact upload is disabled twice',
  count(release, 'upload-artifact: false') === 2,
);
ok('SBOM files are validated before signing', release.includes('Validate generated SBOM files'));
ok('metadata digest is not used as image digest', !release.includes('steps.meta.outputs.digest'));
ok('signature uses the build digest', release.includes('steps.build.outputs.digest'));
ok('SPDX attestation is verified', release.includes('cosign verify-attestation'));
ok(
  'cosign identity is exact for this workflow ref',
  release.includes(
    'CERT_IDENTITY: https://github.com/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}',
  ),
);
ok('broad cosign identity regexp is absent', !release.includes('certificate-identity-regexp'));
ok(
  'release tag expression uses GitHub Actions syntax',
  release.includes('type=raw,value=${{ steps.tag.outputs.name }}'),
);
ok('broken double-brace metadata template absent', !release.includes('value={{steps.'));
ok('release tag is validated', release.includes('Release tag must look like v4.9.0'));
ok('release artifacts fail closed when missing', release.includes('if-no-files-found: error'));
ok('release action is current major', release.includes('softprops/action-gh-release@v3'));
ok(
  'manual release requires an existing tag',
  release.includes("description: 'Existing tag to release") && release.includes('required: true'),
);
ok(
  'both release jobs checkout the selected tag',
  count(release, 'ref: ${{ inputs.tag || github.ref }}') === 2,
);
ok(
  'release permissions are read-only by default',
  release.includes('permissions:\n  contents: read'),
);
ok(
  'publishing privileges are scoped to build-and-sign',
  release.includes(
    'permissions:\n      contents: write\n      packages: write\n      id-token: write',
  ),
);
ok(
  'prereleases cannot overwrite latest',
  release.includes("type=raw,value=latest,enable=${{ !contains(steps.tag.outputs.name, '-') }}"),
);
ok(
  'GitHub prerelease flag follows the tag',
  release.includes("prerelease: ${{ contains(steps.tag.outputs.name, '-') }}"),
);

console.log('\n[verified tool installers]');
ok('SOPS defaults to 3.13.3', installSops.includes('SOPS_VERSION:-3.13.3'));
ok(
  'SOPS checksum manifest is independently pinned',
  installSops.includes('91710ede6a3218e5b62286412543768a92d0c3449434951bd148d21043aad538'),
);
ok('SOPS manifest is checked with sha256sum', installSops.includes('selected-checksum.txt'));
ok(
  'SOPS installer rejects unsupported architectures',
  installSops.includes('unsupported SOPS architecture'),
);
ok('age defaults to 1.3.2', installAge.includes('AGE_VERSION:-1.3.2'));
ok(
  'age archive checksum is pinned',
  installAge.includes('cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10'),
);
ok('old SOPS 3.9.0 downloads are absent', !allWorkflows.includes('sops-v3.9.0'));
ok('old age 1.2.0 downloads are absent', !allWorkflows.includes('age-v1.2.0'));
ok('CI invokes verified SOPS installer', ci.includes('scripts/ci/install-sops.sh'));
ok('CI invokes verified age installer', ci.includes('scripts/ci/install-age.sh'));

console.log('\n[production Dockerfile]');
ok('port directive is valid', dockerfile.includes('\nEXPOSE 8443\n'));
ok('EXOSE typo is absent', !dockerfile.includes('EXOSE'));
ok('dependency stage uses Node 24 LTS', dockerfile.includes('FROM node:24-bookworm-slim AS deps'));
ok('development stage uses Node 24', dockerfile.includes('FROM node:24-alpine AS dev'));
ok(
  'production stage uses Node 24 LTS',
  dockerfile.includes('FROM node:24-bookworm-slim AS production'),
);
ok(
  'Docker build uses verified SOPS installer',
  dockerfile.includes('COPY scripts/ci/install-sops.sh'),
);
ok('Docker build pins SOPS 3.13.3', dockerfile.includes('ARG SOPS_VERSION=3.13.3'));
ok('Docker dependency install requires package-lock', !dockerfile.includes('package-lock.json*'));
ok('Docker build never falls back to npm install', !dockerfile.includes('else npm install'));
ok(
  'obsolete broker-only Dockerfile is removed',
  !existsSync(new URL('../broker/Dockerfile', import.meta.url)),
);
for (const runtimePackage of ['ca-certificates', 'git', 'openssh-client', 'openssl']) {
  ok(`production installs ${runtimePackage}`, dockerfile.includes(runtimePackage));
}
ok('production runs as non-root node user', dockerfile.includes('\nUSER node\n'));
ok(
  'production Node entrypoint is explicit',
  dockerfile.includes('ENTRYPOINT ["node", "server.js"]'),
);
ok('production image does not bake PKI files', !dockerfile.includes('COPY pki/'));

console.log('\n[deployment workflow parity]');
ok('CI builds the root production target', ci.includes('--target production'));
ok('CI no longer builds the stale broker-only Dockerfile', !ci.includes('broker/Dockerfile'));
ok(
  'Taskfile builds the root production target',
  taskfile.includes('--target production -f Dockerfile'),
);
ok('Taskfile test runs the complete quality gate', taskfile.includes('npm run quality:gate'));
ok('dual-cloud deploy builds the root Dockerfile', deploy.includes('file: ./Dockerfile'));
ok('dual-cloud deploy selects production target', deploy.includes('target: production'));
ok('dual-cloud deploy no longer uses broker-only context', !deploy.includes('context: ./broker'));
ok(
  'manual broken Terraform zip install is absent',
  !deploy.includes('terraform_1.7.5_linux_amd64.zip'),
);
ok('Terraform setup action is used', deploy.includes('hashicorp/setup-terraform@v4'));
ok(
  'official Aliyun OIDC credential action is used',
  deploy.includes('aliyun/configure-aliyun-credentials-action@v1'),
);
ok('OIDC token is not misused as a file path', !deploy.includes('ALIYUN_OIDC_TOKEN_FILE_PATH'));
for (const runtimeBinary of ['node', 'sops', 'openssl', 'ssh', 'ssh-keygen', 'git']) {
  ok(`CI smoke-checks ${runtimeBinary}`, ci.includes(runtimeBinary));
}
ok('CI verifies the image is non-root', ci.includes('test "$(id -u)" != "0"'));
ok(
  'CI scans the image for secret-like files',
  ci.includes('secret-like file found in production image'),
);

console.log('\n[Compose deployment contract]');
let compose = null;
try {
  compose = parseYaml(composeSource, { uniqueKeys: true });
} catch (error) {
  console.error(`        docker-compose.yml: ${error.message}`);
}
ok('Compose parses with unique mapping keys', !!compose?.services?.broker);
const composeBroker = compose?.services?.broker || {};
const composeEnv = Array.isArray(composeBroker.environment)
  ? Object.fromEntries(
      composeBroker.environment.map((entry) => {
        const separator = entry.indexOf('=');
        return [entry.slice(0, separator), entry.slice(separator + 1)];
      }),
    )
  : composeBroker.environment || {};
const composeMount = (target) =>
  composeBroker.volumes?.find((mount) => typeof mount === 'object' && mount.target === target);
ok('Compose builds the production target', composeBroker.build?.target === 'production');
ok('Compose local image tag matches package version', composeBroker.image?.includes(pkg.version));
for (const [name, value] of Object.entries({
  PORT: '8443',
  CONFIG_PATH: '/var/lib/broker/secrets/broker.yaml',
  SECRETS_PATH: '/var/lib/broker/secrets/common.env',
  TLS_CA: '/run/secrets/broker/pki/ca/ca.crt',
  CA_KEY_PATH: '/run/secrets/broker/pki/ca/ca.key',
  SOPS_AGE_KEY_FILE: '/run/secrets/broker/age/key.txt',
})) {
  ok(`Compose uses server-recognized ${name}`, String(composeEnv[name]) === value);
}
ok('ignored BROKER_CONFIG_PATH alias is absent', !('BROKER_CONFIG_PATH' in composeEnv));
ok('Compose keeps the root filesystem read-only', composeBroker.read_only === true);
ok('Compose drops all Linux capabilities', composeBroker.cap_drop?.includes('ALL'));
ok(
  'unneeded NET_BIND_SERVICE capability is absent',
  !composeBroker.cap_add?.includes('NET_BIND_SERVICE'),
);
for (const target of [
  '/run/secrets/broker/pki/ca',
  '/run/secrets/broker/pki/server',
  '/run/secrets/broker/age',
]) {
  const mount = composeMount(target);
  ok(
    `${target} is a guarded read-only bind`,
    mount?.type === 'bind' && mount.read_only === true && mount.bind?.create_host_path === false,
  );
}
for (const target of ['/run/secrets/broker/pki/clients', '/var/lib/broker/secrets']) {
  const mount = composeMount(target);
  ok(
    `${target} is a guarded writable state bind`,
    mount?.type === 'bind' && mount.read_only === false && mount.bind?.create_host_path === false,
  );
}
ok(
  'temporary state uses bounded tmpfs, not a volume access mode',
  composeBroker.tmpfs?.some(
    (entry) =>
      entry.startsWith('/tmp:') && entry.includes('size=64m') && entry.includes('mode=1777'),
  ),
);
ok('obsolete persistent temporary volume is absent', !compose?.volumes?.['broker-tmp']);
const healthCommand = composeBroker.healthcheck?.test;
ok(
  'healthcheck uses the Compose CMD marker',
  Array.isArray(healthCommand) && healthCommand[0] === 'CMD' && healthCommand[1] === 'node',
);
const healthSource = Array.isArray(healthCommand) ? healthCommand.join(' ') : '';
ok('healthcheck explicitly requests public health', healthSource.includes("path:'/health'"));
ok(
  'healthcheck verifies the configured CA and TLS name',
  healthSource.includes('process.env.TLS_CA') &&
    healthSource.includes('servername:') &&
    !healthSource.includes('rejectUnauthorized:false'),
);
ok(
  'origin published port is loopback-only by default',
  composeBroker.ports?.includes('127.0.0.1:8443:8443'),
);
const productionSource = dockerfile.split('FROM node:24-bookworm-slim AS production')[1] || '';
for (const name of ['TLS_CA', 'CA_KEY_PATH', 'CONFIG_PATH', 'SECRETS_PATH', 'SOPS_AGE_KEY_FILE']) {
  ok(`production image defines required ${name}`, productionSource.includes(`${name}=`));
}
for (const excluded of ['**/node_modules/', '.tmp/', '.worktrees/', 'age/', 'pki/']) {
  ok(`Docker context excludes ${excluded}`, dockerignore.split(/\r?\n/).includes(excluded));
}

console.log('\n[Aliyun credential rotation safety]');
ok('rotation script enables strict shell mode', injectAliyun.includes('set -euo pipefail'));
ok('rotation script disables command tracing', injectAliyun.includes('set +x'));
ok('rotation script uses restrictive umask', injectAliyun.includes('umask 077'));
ok(
  'tracked script contains no AccessKey assignment placeholder',
  !injectAliyun.match(/^ALIYUN_ACCESS_KEY=/m) && !injectAliyun.match(/^ALIYUN_ACCESS_SECRET=/m),
);
ok(
  'interactive secret prompt disables echo',
  injectAliyun.includes('read -r -s -p "Aliyun AccessKey Secret:'),
);
ok(
  'credential values are staged in protected files rather than argv',
  injectAliyun.includes('SECRET_FILE="$TMP_DIR/access-key-secret"') &&
    injectAliyun.includes('-v secret_file="$SECRET_FILE"'),
);
ok(
  'rotation script securely cleans temporary plaintext',
  injectAliyun.includes('trap secure_remove EXIT HUP INT TERM') &&
    injectAliyun.includes('shred -u'),
);
ok(
  'rotation verifies field presence without printing decrypted values',
  injectAliyun.includes('END { exit !(have_ak && have_secret) }') &&
    !injectAliyun.includes('grep -E "ALIYUN"'),
);
ok(
  'rotation requires active broker after restart',
  injectAliyun.includes('systemctl is-active --quiet secret-broker'),
);
ok(
  'credential rotation scratch paths are ignored',
  gitignore.includes('secrets/.inject-aliyun.*/') &&
    gitignore.includes('secrets/.common.env.next.*'),
);

console.log('\n[Nginx edge security]');
ok(
  'broker vhost does not import generic security headers',
  !nginxBroker.includes('_security-headers.conf'),
);
ok(
  'route-specific CSP remains owned by Broker',
  !nginxBroker.includes('add_header Content-Security-Policy') &&
    !nginxBroker.includes('proxy_hide_header Content-Security-Policy'),
);
for (const expectedHeader of [
  'add_header X-Content-Type-Options "nosniff" always;',
  'add_header X-Frame-Options "DENY" always;',
  'add_header Referrer-Policy "no-referrer" always;',
  'add_header Cross-Origin-Opener-Policy "same-origin" always;',
  'add_header Cross-Origin-Resource-Policy "same-origin" always;',
]) {
  ok(`edge emits ${expectedHeader}`, nginxBroker.includes(expectedHeader));
}
ok('edge hides upstream server fingerprint', nginxBroker.includes('proxy_hide_header Server;'));
ok('origin TLS verification is enabled', nginxBroker.includes('proxy_ssl_verify on;'));
ok('origin TLS verification is never disabled', !nginxBroker.includes('proxy_ssl_verify off;'));
ok('origin sends verified SNI', nginxBroker.includes('proxy_ssl_server_name on;'));
ok(
  'origin certificate name is pinned to broker domain',
  nginxBroker.includes('proxy_ssl_name broker.52trz.com;'),
);
ok(
  'origin trust chain is explicit',
  nginxBroker.includes('proxy_ssl_trusted_certificate /opt/secret-broker/pki/ca/ca.crt;'),
);
ok(
  'common proxy TLS configuration is defined once',
  count(nginxBroker, 'proxy_ssl_verify on;') === 1 &&
    count(nginxBroker, 'proxy_ssl_certificate /opt/secret-broker/pki/proxies/nginx.crt;') === 1,
);
ok(
  'operator endpoints remain loopback-only',
  nginxBroker.includes('location ~ ^/(ready|readyz|live|healthz|metrics|metrics\\.json)$') &&
    nginxBroker.includes('allow 127.0.0.1;') &&
    nginxBroker.includes('deny all;'),
);

const releaseDocument = parseYaml(release);
const releaseSteps = Object.values(releaseDocument.jobs).flatMap((job) => job.steps || []);
ok(
  'workflow inputs are never interpolated directly into shell source',
  releaseSteps.every((step) => !String(step.run || '').includes('${{ inputs.')),
);
ok(
  'manual release tag is supplied using an intermediate environment variable',
  releaseSteps.some(
    (step) =>
      step.id === 'tag' &&
      step.env?.INPUT_TAG === '${{ inputs.tag }}' &&
      step.run.includes('TAG="$INPUT_TAG"'),
  ),
);
ok(
  'Nginx uses a dedicated proxy credential, not a business client',
  nginxBroker.includes('/pki/proxies/nginx.key;') && !nginxBroker.includes('client.mavis'),
);
ok(
  'Nginx forwards explicit WebSocket upgrade metadata',
  nginxBroker.includes('proxy_set_header Upgrade $http_upgrade;') &&
    nginxBroker.includes('proxy_set_header Connection $broker_connection_upgrade;'),
);
ok(
  'startup regression is part of the quality gate',
  pkg.scripts['test:verify-all'].includes('npm run test:startup'),
);
console.log('\n[preproduction promotion and hermetic CI]');
const ciDocument = parseYaml(ci);
const ciBrokerSteps = ciDocument.jobs['broker-test'].steps;
ok(
  'regular CI runs the full quality gate rather than a permissive smoke echo',
  ciBrokerSteps.some((step) => String(step.run || '').includes('npm run quality:gate')),
);
ok(
  'CI never copies private repository PKI or age keys into a smoke fixture',
  !ci.includes('cp -r $GITHUB_WORKSPACE/age') &&
    !ci.includes('cp -r $GITHUB_WORKSPACE/pki') &&
    !ci.includes('broker smoke test passed'),
);
const ecsDocument = parseYaml(workflows['deploy-ecs.yml']);
const ecsDeploy = ecsDocument.jobs.deploy;
const ecsRun = ecsDeploy.steps.map((step) => step.run || '').join('\n');
ok(
  'ECS deployment requires explicit manual preproduction approval input',
  ecsDocument.on.workflow_dispatch.inputs.preprod_review_approved.default === false &&
    ecsDeploy.if.includes("github.event_name == 'workflow_dispatch'") &&
    ecsDeploy.if.includes('inputs.preprod_review_approved'),
);
ok('ECS deployment names a protected environment', ecsDeploy.environment === 'production-ecs');
ok(
  'ECS SSH requires an independently supplied host-key pin',
  ecsRun.includes('${ECS_SSH_KNOWN_HOSTS:?') && !ecsRun.includes('ssh-keyscan'),
);
ok(
  'ECS health check verifies TLS and rejects HTTP failures',
  ecsRun.includes('curl --fail --silent --show-error') &&
    ecsRun.includes('--cacert /opt/secret-broker/pki/ca/ca.crt') &&
    ecsRun.includes('--resolve broker.52trz.com:8443:127.0.0.1') &&
    !ecsRun.includes('curl -sk'),
);
ok(
  'ECS runner removes its temporary deployment key on exit',
  ecsRun.includes('trap') && ecsRun.includes('rm -f "$HOME/.ssh/deploy"'),
);
console.log(`\n=== Total: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
