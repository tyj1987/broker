import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const files = [
  'infra/aliyun/broker/main.tf',
  'infra/aliyun/broker/variables.tf',
  'infra/tencent/broker.tf',
  'infra/tencent/broker-variables.tf',
  'deploy/helm/broker/templates/_helpers.tpl',
  'deploy/helm/broker/templates/deployment.yaml',
  'docker-compose.yml',
  'broker/docs/deployment-2026-09-05-mtls-passthrough/nginx-broker.52trz.com.conf',
  '.github/workflows/deploy.yml',
];
const contents = Object.fromEntries(files.map((file) => [file, readFileSync(resolve(root, file), 'utf8')]));
const failures = [];

for (const [file, text] of Object.entries(contents)) {
  if (/ssh_password|\bpassword\s*=\s*var\./i.test(text)) failures.push(`${file}: password-based SSH is forbidden`);
}
for (const file of ['infra/aliyun/broker/main.tf', 'infra/tencent/broker.tf']) {
  const text = contents[file];
  const resourceBlocks = [...text.matchAll(/resource\s+"[^"]+"\s+"[^"]+"\s*\{([^{}]*)\}/g)].map((match) => match[1]);
  if (resourceBlocks.some((block) => /(?:port|port_range)\s*=\s*"(?:8443|8443\/8443)"/.test(block) && /cidr_ip\s*=\s*"0\.0\.0\.0\/0"/.test(block))) {
    failures.push(`${file}: broker backend 8443 must not be public`);
  }
  if (!/443/.test(text)) failures.push(`${file}: public TLS edge 443 rule is missing`);
  if (!/key_name\s*=\s*var\.ssh_key_name/.test(text)) failures.push(`${file}: cloud SSH key pair is required`);
}
const helm = contents['deploy/helm/broker/templates/_helpers.tpl'];
if (!/required[^\n]*image\.digest/.test(helm) || !/sha256:/.test(helm) || /printf\s+"%s:%s"/.test(helm)) {
  failures.push('Helm: production image must be required by immutable sha256 digest');
}
const helmDeployment = contents['deploy/helm/broker/templates/deployment.yaml'];
const compose = contents['docker-compose.yml'];
const nginx = contents['broker/docs/deployment-2026-09-05-mtls-passthrough/nginx-broker.52trz.com.conf'];
if (/\bssl_verify_client\s+(?:on|optional)/i.test(nginx) || /\bssl_client_certificate\s+/i.test(nginx)) {
  failures.push('nginx public 443 must not request client certificates; mTLS belongs on the private 8443 boundary');
}
for (const header of ['X-SSL-Client-Cert', 'X-SSL-Client-Verify', 'X-SSL-Client-DN']) {
  const lines = nginx.split(/\r?\n/).filter((line) => line.includes(header));
  if (lines.length === 0 || lines.some((line) => !/proxy_set_header\s+[^\s]+\s+""\s*;/.test(line))) {
    failures.push(`nginx public edge must clear caller-controlled ${header}`);
  }
}
for (const [file, text] of [['Compose', compose], ['Helm deployment', helmDeployment]]) {
  for (const legacy of ['PKI_DIR=', 'AUDIT_DIR=', 'SECRETS_DETAIL_PATH=', 'HEALTH_SOCKET_PATH']) {
    if (text.includes(legacy) && !text.includes(`BROKER_${legacy}`)) failures.push(`${file}: legacy runtime variable ${legacy} is forbidden`);
  }
}
for (const [file, text] of [['Helm deployment', helmDeployment], ['Compose', compose]]) {
  if (!text.includes('/tmp/broker-health.sock') || !text.includes("socketPath:")) {
    failures.push(`${file}: health probes must use the local Unix socket`);
  }
  if (/rejectUnauthorized\s*:\s*false/.test(text)) {
    failures.push(`${file}: health probes must not disable TLS authorization`);
  }
}
for (const [index, line] of compose.split(/\r?\n/).entries()) {
  if (/^\s+image:\s+/.test(line) && !/@(?:\$\{BROKER_IMAGE_DIGEST|sha256:[0-9a-f]{64})/.test(line)) {
    failures.push(`docker-compose.yml:${index + 1}: runtime image is not digest-pinned`);
  }
}
const aliyunRole = readFileSync(resolve(root, 'infra/aliyun/broker/role.tf'), 'utf8');
for (const match of aliyunRole.matchAll(/"((?:ecs|vpc|slb|rds):[A-Za-z0-9]+)"/g)) {
  const operation = match[1].split(':')[1];
  if (!operation.startsWith('Describe')) failures.push(`Aliyun runtime RAM role has non-read-only action: ${match[1]}`);
}

const releaseWorkflow = contents['.github/workflows/deploy.yml'];
for (const forbidden of [
  'ALIYUN_ACR_PASSWORD',
  'TENCENT_TCR_PASSWORD',
  'TENCENTCLOUD_SECRET_ID',
  'TENCENTCLOUD_SECRET_KEY',
]) {
  if (releaseWorkflow.includes(forbidden)) failures.push(`Release workflow uses forbidden long-lived credential: ${forbidden}`);
}

for (const dockerfile of ['Dockerfile', 'broker/Dockerfile']) {
  const text = readFileSync(resolve(root, dockerfile), 'utf8');
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (/^FROM\s+/i.test(line) && !/@sha256:[0-9a-f]{64}(?:\s|$)/i.test(line)) {
      failures.push(`${dockerfile}:${index + 1}: base image is not pinned by sha256 digest`);
    }
  }
}
if (/terraform\s+apply/.test(releaseWorkflow)) {
  failures.push('Release workflow must not apply cloud infrastructure before digest-bound deployment is implemented');
}
if (!/ghcr\.io\/\$\{\{ github\.repository \}\}/.test(releaseWorkflow) || !/cosign sign/.test(releaseWorkflow)) {
  failures.push('Release workflow must publish and keylessly sign a digest-addressed GHCR candidate');
}
if (!/cosign verify-attestation[\s\S]*--type spdxjson/.test(releaseWorkflow) || !/cosign verify-attestation[\s\S]*--type slsaprovenance/.test(releaseWorkflow)) {
  failures.push('Release workflow must verify SBOM and SLSA provenance attestations for the exact image digest');
}
if (!/gitleaks\/gitleaks-action@/ .test(releaseWorkflow) || !/fetch-depth:\s*0/.test(releaseWorkflow)) {
  failures.push('Release workflow must run a complete-history gitleaks scan before publishing');
}
if (!/npm run test:verify/.test(releaseWorkflow) || !/npm run coverage:security/.test(releaseWorkflow) || !/npm run supply-chain:verify/.test(releaseWorkflow)) {
  failures.push('Release workflow must run regression, security coverage, and supply-chain gates before publishing');
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log('Infrastructure policy checks passed: private backend, SSH keys, digest-only Helm image, fail-closed cloud release.');
