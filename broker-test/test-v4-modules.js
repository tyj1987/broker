// broker-test/test-v4-modules.js — V4 P1 阶段新模块单元测试
// 覆盖:auto-rotate / alerting / openapi / type-schemas / service-templates / webauthn / template-parser

import { runRotationCheck, checkRotationState, tryRotate, rollbackRotation, ROTATION_RULES } from '../broker/lib/auto-rotate.js';
import { routeEvent, dispatchAlert, alert } from '../broker/lib/alerting.js';
import OPENAPI_SPEC from '../broker/lib/openapi-spec.js';
import { TYPE_SCHEMAS, getTypeSchema, validateFields } from '../broker/type-schemas.js';
import { SERVICE_TEMPLATES, publicTemplateList } from '../broker/service-templates.js';
import { configureWebAuthn, beginRegistration, beginAuthentication, finishRegistration, finishAuthentication, ensureWebAuthnFactors, listCredentials, parseAuthenticatorData, noopVerifier } from '../broker/webauthn.js';
import { parseOpenAPI, extractAuthFromDocs, extractUpstreamFromDocs } from '../broker/lib/template-parser.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// auto-rotate
// ============================================================
section('auto-rotate');
{
  const fresh = checkRotationState({ name: 's1', type: 'github_pat', created_at: new Date().toISOString() }, {});
  ok('fresh secret has state=fresh', fresh.state === 'fresh' && fresh.days_until_rotation > 0);
}
{
  const old = new Date(Date.now() - 100 * 86400_000).toISOString();
  const expired = checkRotationState({ name: 's2', type: 'github_pat', created_at: old }, {});
  ok('100 days old = expired', expired.state === 'expired' && expired.days_until_rotation < 0);
}
{
  const warn = new Date(Date.now() - 80 * 86400_000).toISOString();
  const r = checkRotationState({ name: 's3', type: 'github_pat', created_at: warn }, {});
  ok('80 days old = warn', r.state === 'warn');
}
{
  ok('ROTATION_RULES has github_pat', !!ROTATION_RULES.github_pat);
  ok('ROTATION_RULES.github_pat canAutoRotate=false', ROTATION_RULES.github_pat.canAutoRotate === false);
  ok('ROTATION_RULES.github_pat has hint', typeof ROTATION_RULES.github_pat.hint === 'string' && ROTATION_RULES.github_pat.hint.length > 0);
}
{
  // Custom rotate_recommendation_days
  const r = checkRotationState(
    { name: 's4', type: 'openai_key', created_at: new Date(Date.now() - 200 * 86400_000).toISOString() },
    {},
  );
  // openai_key uses default 90 days threshold, so 200 days is expired
  ok('openai_key 200d = expired', r.state === 'expired');
  ok('threshold_days = 90', r.threshold_days === 90);
}
{
  // Custom 30-day threshold via secret.rotate_recommendation_days
  const r = checkRotationState(
    { name: 's5', type: 'github_pat', created_at: new Date(Date.now() - 40 * 86400_000).toISOString(), rotate_recommendation_days: 30 },
    {},
  );
  ok('custom threshold 30d applied', r.state === 'expired' && r.threshold_days === 30);
}
{
  // tryRotate with auto_rotate disabled
  const ok1 = await tryRotate({ name: 's', type: 'github_pat' }, {}, {});
  ok('tryRotate returns false when auto_rotate disabled', ok1 === false);
  // tryRotate with auto_rotate=true but no rule
  const ok2 = await tryRotate({ name: 's', type: 'github_pat', auto_rotate: true }, {}, {});
  ok('tryRotate returns false when no rule for type', ok2 === false);
  // tryRotate with auto_rotate=true and explicit rotate_command
  let ran = false;
  const ok3 = await tryRotate(
    { name: 's', type: 'github_pat', auto_rotate: true },
    {},
    { runRotate: async () => { ran = true; return { ok: true, value: 'new-token' }; } },
  );
  ok('tryRotate calls runRotate', ok3 === true && ran === true);
  // tryRotate fails
  const ok4 = await tryRotate(
    { name: 's', type: 'github_pat', auto_rotate: true },
    {},
    { runRotate: async () => ({ ok: false, error: 'upstream 500' }) },
  );
  ok('tryRotate returns false on error', ok4 === false);
}
{
  // runRotationCheck with mix of states
  const r = await runRotationCheck(
    [
      { name: 'fresh', type: 'github_pat', created_at: new Date().toISOString() },
      { name: 'warn', type: 'github_pat', created_at: new Date(Date.now() - 80 * 86400_000).toISOString() },
      { name: 'expired', type: 'github_pat', created_at: new Date(Date.now() - 100 * 86400_000).toISOString(), auto_rotate: true },
    ],
    {},
    { runRotate: async () => ({ ok: true, value: 'new-value' }) },
  );
  ok('checked = 3', r.checked === 3);
  ok('warned >= 2', r.warned >= 2);
  ok('rotated >= 1', r.rotated >= 1);
}

// ============================================================
// alerting
// ============================================================
section('alerting');
{
  // routeEvent with no config
  const r1 = routeEvent(null, { severity: 'critical', title: 'test' });
  ok('routeEvent with null config returns []', r1.length === 0);
}
{
  // routeEvent with config
  const r2 = routeEvent(
    { alerting: { channels: [
      { type: 'slack_webhook', url: 'https://hooks.slack.com/xxx', events: ['secret.expired'] },
      { type: 'console', events: ['*'] },
    ] } },
    { severity: 'critical', title: 'secret.expired', detail: 'github.pat is expired' },
  );
  ok('routeEvent matched 2 channels', r2.length === 2);
  ok('slack channel targeted', r2.some(r => r.type === 'slack_webhook' && r.target === 'https://hooks.slack.com/xxx'));
  ok('console channel targeted', r2.some(r => r.type === 'console'));
}
{
  // filter by event match
  const r3 = routeEvent(
    { alerting: { channels: [
      { type: 'slack_webhook', url: 'x', events: ['cert.expiring'] },
      { type: 'console', events: ['*'] },
    ] } },
    { severity: 'info', title: 'unrelated' },
  );
  ok('unrelated event hits only wildcard channel', r3.length === 1 && r3[0].type === 'console');
}
{
  // dispatchAlert to console
  const logs = [];
  const sink = { consoleImpl: { info: (m) => logs.push(m), warn: () => {}, error: () => {} } };
  const r4 = await dispatchAlert({ type: 'console', target: null, payload: { severity: 'info', title: 't', detail: 'd' } }, sink);
  ok('console dispatch ok', r4.ok);
  ok('console log captured', logs.length === 1 && logs[0].includes('t'));
}
{
  // dispatchAlert to mock webhook
  const sink = { fetchImpl: async (url, opts) => ({ ok: true, status: 200 }) };
  const r5 = await dispatchAlert({ type: 'slack_webhook', target: 'https://x', payload: { severity: 'info', title: 't', text: 'hi' } }, sink);
  ok('webhook dispatch ok', r5.ok === true);
}
{
  const sink = { fetchImpl: async (url, opts) => ({ ok: false, status: 500 }) };
  const r6 = await dispatchAlert({ type: 'slack_webhook', target: 'https://x', payload: {} }, sink);
  ok('webhook 500 -> not ok', r6.ok === false && /500/.test(r6.error));
}
{
  // secret value must be redacted in payload
  const sink = { fetchImpl: async (url, opts) => {
    const body = JSON.parse(opts.body);
    if (body.detail && body.detail.includes('ghp_xxx')) throw new Error('leak!');
    return { ok: true, status: 200 };
  } };
  const r7 = await dispatchAlert({
    type: 'slack_webhook', target: 'https://x',
    payload: { severity: 'critical', title: 'leak test', detail: 'token=ghp_xxxxABCDEFGHIJabcdefghij', text: 't' },
  }, sink);
  ok('detail got redacted', r7.ok === true);
}

// ============================================================
// OpenAPI
// ============================================================
section('OpenAPI');
{
  ok('openapi version is 3.1.0', OPENAPI_SPEC.openapi === '3.1.0');
  ok('has >= 30 paths', Object.keys(OPENAPI_SPEC.paths).length >= 30);
  ok('has /health', !!OPENAPI_SPEC.paths['/health']);
  ok('has /api/v1/proxy/{service}', !!OPENAPI_SPEC.paths['/api/v1/proxy/{service}']);
  ok('has signed device suspension', !!OPENAPI_SPEC.paths['/api/v2/devices/{device_id}/suspend']);
  ok('has ProxyRequest schema', !!OPENAPI_SPEC.components.schemas.ProxyRequest);
  ok('has LoginResponse schema', !!OPENAPI_SPEC.components.schemas.LoginResponse);
  ok('has mTLS security scheme', !!OPENAPI_SPEC.components.securitySchemes.mtls);
  ok('has bearerAuth', !!OPENAPI_SPEC.components.securitySchemes.bearerAuth);
  ok('proxy endpoint has 502/503 responses', OPENAPI_SPEC.paths['/api/v1/proxy/{service}'].post.responses['502'] && OPENAPI_SPEC.paths['/api/v1/proxy/{service}'].post.responses['503']);
}

// ============================================================
// type-schemas (V4 新增 17)
// ============================================================
section('type-schemas (V4 additions)');
{
  const v4Types = ['docker_hub_pat', 'ghcr_pat', 'aws_access_key_v2', 'azure_tenant', 'gcp_service_account_v2',
    'digitalocean', 'oracle_cloud', 'github_app', 'gitlab_pat', 'gitee_pat',
    'feishu_app', 'dingtalk_app', 'wechat_miniprogram', 'alipay_key', 'datadog_v2',
    'npm_token', 'pypi_token', 'ssh_jump_host', 'azure_storage'];
  for (const t of v4Types) {
    const schema = getTypeSchema(t);
    ok(`${t} schema exists`, !!schema && Array.isArray(schema.fields) && schema.fields.length > 0);
  }
}
{
  // rotate_recommendation_days
  ok('github_pat has rotate_recommendation_days', getTypeSchema('github_pat').rotate_recommendation_days === 90);
  ok('ssh_jump_host has 180d', getTypeSchema('ssh_jump_host').rotate_recommendation_days === 180);
  ok('wechat_miniprogram has 365d', getTypeSchema('wechat_miniprogram').rotate_recommendation_days === 365);
}
{
  // validation_regex on AWS access key
  const awsSchema = getTypeSchema('aws_access_key_v2');
  const reField = awsSchema.fields.find(f => f.name === 'access_key_id');
  ok('aws_access_key_id has validation_regex', !!reField.validation_regex);
  ok('regex matches AKIA...', reField.validation_regex.test('AKIAIOSFODNN7EXAMPLE'));
  ok('regex matches ASIA...', reField.validation_regex.test('ASIAJBBLPLV4ABCDEFG'));
  ok('regex rejects ghpx_', !reField.validation_regex.test('ghpx_xxxxxxxxxxxxxxxx'));
}
{
  // validateFields
  const e1 = validateFields('aws_access_key_v2', {});
  ok('empty fields -> error', e1.length > 0);
  const e2 = validateFields('aws_access_key_v2', { access_key_id: 'AKIAIOSFODNN7EXAMPLE', secret_access_key: 'x' });
  ok('complete fields -> no error', e2.length === 0);
  const e3 = validateFields('aws_access_key_v2', { access_key_id: 'AKIAIOSFODNN7EXAMPLE', secret_access_key: 'x', unknown_field: 'y' });
  ok('unknown field -> error', e3.some(m => m.includes('未知字段')));
}

// ============================================================
// service-templates (V4 新增 41)
// ============================================================
section('service-templates (V4 additions)');
{
  const v4Templates = ['gitlab', 'gitee', 'github_app', 'gemini', 'deepseek', 'zhipu', 'mistral', 'cohere', 'moonshot', 'qwen',
    'aws', 'gcp', 'azure', 'digitalocean', 'oracle_cloud',
    'aliyun_oss', 'aliyun_dns', 'tencent_cos', 'tencent_tcr',
    'docker_hub', 'ghcr', 'quay', 'stripe', 'wechat_pay', 'alipay',
    'slack', 'discord', 'feishu', 'dingtalk', 'telegram', 'sendgrid',
    'postgresql_proxy', 'mysql_proxy', 'redis_proxy', 'mongodb_proxy',
    'sentry', 'datadog', 'new_relic', 'ssh_proxy', 'npm_registry', 'pypi'];
  for (const t of v4Templates) {
    const s = SERVICE_TEMPLATES[t];
    ok(`${t} template exists`, !!s);
  }
}
{
  // Each template has required fields
  for (const [id, t] of Object.entries(SERVICE_TEMPLATES)) {
    if (!t.upstream && t.id !== 'ssh_proxy' && t.id !== 'alipay' && !t.proxy_listen_port) continue;
    ok(`${id} has upstream or proxy_listen_port`, !!t.upstream || !!t.proxy_listen_port);
  }
}
{
  // publicTemplateList returns safe view
  const list = publicTemplateList();
  ok('publicTemplateList has at least 40', Object.keys(list).length >= 40);
  const git = list.github;
  ok('public view has label/description', git.label && git.description);
  ok('admin skeleton includes github upstream', git.upstream === 'https://api.github.com');
  ok('admin skeleton includes dashboard actions', Array.isArray(git.dashboard_actions) && git.dashboard_actions.length > 0);
  ok('github api version is current', git.inject_headers && git.inject_headers['X-GitHub-Api-Version'] === '2026-03-10');
  ok('cloudflare verify path', (list.cloudflare.dashboard_actions || []).some(a => a.path === '/user/tokens/verify'));
  ok('cloudflare first useful action is zones', (list.cloudflare.dashboard_actions || [])[0]?.path === '/zones');
  ok('gemini uses 2.5 flash', (list.gemini.dashboard_actions || []).some(a => String(a.path).includes('gemini-2.5-flash')));
  ok('ssh_proxy is enabled', list.ssh_proxy && !list.ssh_proxy.disabled);
}

// ============================================================
// webauthn
// ============================================================
section('webauthn');
{
  configureWebAuthn({ rp_id: 'test.local', rp_origin: 'http://localhost:8443' });
  const begin = beginRegistration('tyj', '脱永军', []);
  ok('begin registration returns publicKey options', !!begin.publicKey);
  ok('rp.id = test.local', begin.publicKey.rp.id === 'test.local');
  ok('rp.name = Secret Broker', begin.publicKey.rp.name === 'Secret Broker');
  ok('user.id is buffer of name', Buffer.isBuffer(begin.publicKey.user.id) && begin.publicKey.user.id.toString() === 'tyj');
  ok('user.displayName = 脱永军', begin.publicKey.user.displayName === '脱永军');
  ok('has 2 algorithms (ES256+RS256)', begin.publicKey.pubKeyCredParams.length === 2);
  ok('attestation = none', begin.publicKey.attestation === 'none');
  ok('userVerification = preferred', begin.publicKey.authenticatorSelection.userVerification === 'preferred');
}
{
  // begin authentication
  const begin = beginAuthentication('tyj', [{ id: 'cred1' }]);
  ok('begin auth returns publicKey options', !!begin.publicKey);
  ok('rpId = test.local', begin.publicKey.rpId === 'test.local');
  ok('has 1 allowCredential', begin.publicKey.allowCredentials.length === 1);
}
{
  // finish registration without verifier fails gracefully
  const begin = beginRegistration('tyj');
  // craft a valid clientDataJSON
  const cdata = {
    type: 'webauthn.create',
    challenge: begin.publicKey.challenge.toString('base64url'),
    origin: 'http://localhost:8443',
  };
  const credential = {
    id: 'abc',
    rawId: 'abc',
    response: {
      clientDataJSON: Buffer.from(JSON.stringify(cdata)).toString('base64url'),
      attestationObject: 'aGVsbG8=',  // base64 "hello"
      transports: ['usb'],
    },
  };
  const r = finishRegistration('tyj', credential, null);
  ok('finishRegistration fails without verifier', r.ok === false && /verifier/i.test(r.error));
}
{
  // finish registration with verifier
  const begin = beginRegistration('tyj');
  const cdata = {
    type: 'webauthn.create',
    challenge: begin.publicKey.challenge.toString('base64url'),
    origin: 'http://localhost:8443',
  };
  const credential = {
    id: 'cred-new',
    rawId: 'cred-new',
    response: {
      clientDataJSON: Buffer.from(JSON.stringify(cdata)).toString('base64url'),
      attestationObject: 'aGVsbG8=',
      transports: ['usb', 'nfc'],
    },
  };
  const r = finishRegistration('tyj', credential, (ao, cdh) => ({
    verified: true,
    publicKey: 'fakepubkey',
    signCount: 0,
    aaguid: '00000000-0000-0000-0000-000000000000',
    fmt: 'none',
  }));
  ok('finishRegistration success with verifier', r.ok === true);
  ok('returned credential_id', r.credential_id === 'cred-new');
  ok('credential has transports', r.credential.transports.length === 2);
}
{
  // finish registration wrong type
  const begin = beginRegistration('tyj');
  const cdata = {
    type: 'webauthn.get',  // wrong type
    challenge: begin.publicKey.challenge.toString('base64url'),
    origin: 'http://localhost:8443',
  };
  const credential = {
    id: 'cred-x',
    response: { clientDataJSON: Buffer.from(JSON.stringify(cdata)).toString('base64url'), attestationObject: 'x' },
  };
  const r = finishRegistration('tyj', credential, () => ({ verified: true }));
  ok('wrong ceremony type rejected', r.ok === false && /ceremony/i.test(r.error));
}
{
  // ensureWebAuthnFactors
  const c1 = {};
  ensureWebAuthnFactors(c1);
  ok('initializes webauthn factors', c1.factors && Array.isArray(c1.factors.webauthn.credentials));
  // idempotent
  ensureWebAuthnFactors(c1);
  ok('idempotent (no overwrite)', c1.factors.webauthn.credentials.length === 0);
}
{
  // parseAuthenticatorData
  const fake = Buffer.alloc(37);
  fake.writeUInt32BE(42, 33);  // signCount = 42
  const parsed = parseAuthenticatorData(fake);
  ok('signCount read correctly', parsed.signCount === 42);
  ok('flags byte 0', parsed.flags === 0);
  ok('rpIdHash is 32 bytes', parsed.rpIdHash.length === 32);
}
{
  // too short
  let threw = false;
  try { parseAuthenticatorData(Buffer.alloc(10)); } catch (_e) { threw = true; }
  ok('too short throws', threw);
}

// ============================================================
// template-parser
// ============================================================
section('template-parser');
{
  // OpenAPI JSON
  const openapi = JSON.stringify({
    openapi: '3.1.0',
    info: { version: '2025-09' },
    servers: [{ url: 'https://api.example.com' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer' },
      },
    },
    paths: {
      '/user': { get: { summary: 'Get user' } },
      '/repos/{id}': { get: { summary: 'Get repo' } },  // has param, skip
      '/items': { get: {} },  // no summary
    },
  });
  const r = parseOpenAPI(openapi);
  ok('upstream extracted', r.upstream === 'https://api.example.com');
  ok('auth_type=bearer', r.auth_type === 'bearer');
  ok('default_secret_field=token', r.default_secret_field === 'token');
  ok('template_version=2025-09', r.template_version === '2025-09');
  ok('source=openapi', r.source === 'openapi');
  ok('default_actions has 2', r.default_actions.length === 2);
  ok('action labels', r.default_actions.some(a => a.label === 'Get user') && r.default_actions.some(a => a.label === 'GET /items'));
  ok('skipped path with {param}', !r.default_actions.some(a => a.path === '/repos/{id}'));
}
{
  // OpenAPI YAML
  const yaml = `
openapi: 3.0.0
info:
  version: "1.0.0"
servers:
  - url: https://api.y.com
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /health: {}
`;
  const r = parseOpenAPI(yaml);
  ok('YAML parsed', r.upstream === 'https://api.y.com' && r.auth_type === 'header');
  ok('header inject for apikey', r.inject_headers['X-API-Key'] === '<ApiKeyAuth>');
}
{
  // Invalid input
  let threw = false;
  try { parseOpenAPI('not json or yaml at all: {{'); } catch (_e) { threw = true; }
  ok('invalid spec throws', threw);
}
{
  let threw = false;
  try { parseOpenAPI(''); } catch (_e) { threw = true; }
  ok('empty string throws', threw);
}
{
  // extract auth from docs
  const docs = `
# Example
\`\`\`bash
curl -H "Authorization: Bearer ghp_xxxx" \\
curl -H "x-api-key: sk-abc" \\
\`\`\`
`;
  const r1 = extractAuthFromDocs(docs);
  ok('extracts Bearer from docs', r1.auth_type === 'bearer');
  ok('Bearer sample present', r1.sample && r1.sample.includes('Bearer'));
  const r2 = extractAuthFromDocs('# nothing here');
  ok('default bearer when no match', r2.auth_type === 'bearer');
  const r3 = extractAuthFromDocs('Authorization: Basic dXNlcjpwYXNz');
  ok('extracts Basic', r3.auth_type === 'basic');
  const r4 = extractAuthFromDocs('x-api-key: sk-abc123');
  ok('extracts header auth', r4.auth_type === 'header');
}
{
  // extract upstream
  const r1 = extractUpstreamFromDocs('see https://api.github.com/users');
  ok('github upstream', r1 === 'https://api.github.com');
  const r2 = extractUpstreamFromDocs('https://s3.amazonaws.com/bucket');
  ok('aws upstream', r2 === 'https://s3.amazonaws.com');
  const r3 = extractUpstreamFromDocs('https://storage.googleapis.com/');
  ok('gcp upstream', r3 === 'https://storage.googleapis.com');
  const r4 = extractUpstreamFromDocs('https://ecs.aliyuncs.com/');
  ok('aliyun upstream', r4 === 'https://ecs.aliyuncs.com');
  const r5 = extractUpstreamFromDocs('https://cvm.tencentcloudapi.com');
  ok('tencent upstream', r5 === 'https://cvm.tencentcloudapi.com');
  const r6 = extractUpstreamFromDocs('no urls here');
  ok('null when no url', r6 === null);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
