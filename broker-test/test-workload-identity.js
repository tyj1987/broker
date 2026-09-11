// broker-test/test-workload-identity.js — V4.1 任务 11
// 覆盖: 3 provider 签名 / cache hit / in-flight 合并 / 过期 / 错误 / validateConfig / cache list

import {
  getCredentials,
  invalidateCache,
  listCache,
  validateConfig,
  PROVIDER_NAMES,
  REFRESH_SKEW_MS,
  _resetForTests,
} from '../broker/lib/workload-identity.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// 提供方常量
// ============================================================
section('provider constants');
{
  ok('has 3 providers', PROVIDER_NAMES.length === 3);
  ok('contains aliyun', PROVIDER_NAMES.includes('aliyun'));
  ok('contains aws', PROVIDER_NAMES.includes('aws'));
  ok('contains gcp', PROVIDER_NAMES.includes('gcp'));
  ok('refresh skew = 10min', REFRESH_SKEW_MS === 600_000);
}

// ============================================================
// 基础参数校验
// ============================================================
section('input validation');
{
  let threw = false;
  try { await getCredentials('azure', 'tok', {}, {}); } catch (e) { threw = /unknown.*provider/.test(e.message); }
  ok('unknown provider throws', threw);
}
{
  let threw = false;
  try { await getCredentials('aws', '', { roleArn: 'r' }, {}); } catch (e) { threw = /oidcToken.*non-empty/.test(e.message); }
  ok('empty oidc token throws', threw);
}
{
  let threw = false;
  try { await getCredentials('aws', null, { roleArn: 'r' }, {}); } catch (e) { threw = /oidcToken.*non-empty/.test(e.message); }
  ok('null oidc token throws', threw);
}
{
  let threw = false;
  try { await getCredentials('aws', 'tok', {}, {}); } catch (e) { threw = /aws: roleArn required/.test(e.message); }
  ok('aws without roleArn throws', threw);
}
{
  let threw = false;
  try { await getCredentials('aliyun', 'tok', {}, {}); } catch (e) { threw = /aliyun: oidcProviderArn required/.test(e.message); }
  ok('aliyun without oidcProviderArn throws', threw);
}
{
  let threw = false;
  try { await getCredentials('gcp', 'tok', {}, {}); } catch (e) { threw = /gcp: audience/.test(e.message); }
  ok('gcp without audience throws', threw);
}

// ============================================================
// Aliyun provider
// ============================================================
section('aliyun provider');
{
  _resetForTests();
  let httpCalls = 0;
  const http = async (url, opts) => {
    httpCalls++;
    // 验证 URL / 签名
    ok('aliyun: hits sts.aliyuncs.com', url === 'https://sts.aliyuncs.com/');
    const params = new URLSearchParams(opts.body);
    ok('aliyun: Action=AssumeRoleWithOIDC', params.get('Action') === 'AssumeRoleWithOIDC');
    ok('aliyun: OIDCProviderArn', params.get('OIDCProviderArn') === 'acs:ram::123:oidc-provider/k');
    ok('aliyun: RoleArn', params.get('RoleArn') === 'acs:ram::123:role/app');
    ok('aliyun: OIDCToken', params.get('OIDCToken') === 'fake-sa-token');
    return {
      status: 200,
      body: JSON.stringify({
        Credentials: {
          AccessKeyId: 'STS.AKIDxxx',
          AccessKeySecret: 'STSSECRETxxx',
          SecurityToken: 'TOKENxxx',
          Expiration: new Date(Date.now() + 3600_000).toISOString(),
        },
      }),
    };
  };
  const c = await getCredentials('aliyun', 'fake-sa-token', {
    oidcProviderArn: 'acs:ram::123:oidc-provider/k',
    roleArn: 'acs:ram::123:role/app',
  }, { httpClient: http });
  ok('aliyun: returned access_key_id', c.access_key_id === 'STS.AKIDxxx');
  ok('aliyun: returned security_token', c.security_token === 'TOKENxxx');
  ok('aliyun: provider=aliyun', c.provider === 'aliyun');
  ok('aliyun: expires_at_ms > now', c.expires_at_ms > Date.now());
  ok('aliyun: 1 upstream call', httpCalls === 1);
}

// ============================================================
// AWS provider
// ============================================================
section('aws provider');
{
  _resetForTests();
  const http = async (url, opts) => {
    ok('aws: hits sts.amazonaws.com', url === 'https://sts.amazonaws.com/');
    const params = new URLSearchParams(opts.body);
    ok('aws: Action=AssumeRoleWithWebIdentity', params.get('Action') === 'AssumeRoleWithWebIdentity');
    ok('aws: WebIdentityToken', params.get('WebIdentityToken') === 'k8s-sa.jwt.token');
    return {
      status: 200,
      body: JSON.stringify({
        AssumeRoleWithWebIdentityResult: {
          Credentials: {
            AccessKeyId: 'ASIAxxxx',
            SecretAccessKey: 'SECRETxxxx',
            SessionToken: 'FwoGZX...',
            Expiration: new Date(Date.now() + 3600_000).toISOString(),
          },
        },
      }),
    };
  };
  const c = await getCredentials('aws', 'k8s-sa.jwt.token', {
    roleArn: 'arn:aws:iam::123:role/app',
  }, { httpClient: http });
  ok('aws: access_key_id', c.access_key_id === 'ASIAxxxx');
  ok('aws: provider=aws', c.provider === 'aws');
}
{
  _resetForTests();
  // AWS error path
  const http = async () => ({ status: 403, body: '<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>' });
  let threw = false;
  try {
    await getCredentials('aws', 'tok', { roleArn: 'arn:aws:iam::1:role/x' }, { httpClient: http });
  } catch (e) { threw = /aws sts 403/.test(e.message); }
  ok('aws: 403 surfaces as error', threw);
}
{
  _resetForTests();
  const malformedResponses = [
    { AssumeRoleWithWebIdentityResult: { Credentials: { AccessKeyId: 'AKID', SecretAccessKey: 'SECRET', SessionToken: 'TOKEN' } } },
    { AssumeRoleWithWebIdentityResult: { Credentials: { AccessKeyId: 'AKID', SecretAccessKey: 'SECRET', SessionToken: 'TOKEN', Expiration: 'not-a-date' } } },
  ];
  for (const response of malformedResponses) {
    let threw = false;
    try {
      await getCredentials('aws', 'tok', { roleArn: 'arn:aws:iam::1:role/x' }, {
        httpClient: async () => ({ status: 200, body: JSON.stringify(response) }),
      });
    } catch (e) { threw = /invalid expiration|missing expiration/.test(e.message); }
    ok('aws: malformed expiration fails closed', threw);
    _resetForTests();
  }
  let missingMaterial = false;
  try {
    await getCredentials('aws', 'tok', { roleArn: 'arn:aws:iam::1:role/x' }, {
      httpClient: async () => ({
        status: 200,
        body: JSON.stringify({
          AssumeRoleWithWebIdentityResult: {
            Credentials: {
              SecretAccessKey: 'SECRET', SessionToken: 'TOKEN',
              Expiration: new Date(Date.now() + 3600_000).toISOString(),
            },
          },
        }),
      }),
    });
  } catch (e) { missingMaterial = /missing access key id/.test(e.message); }
  ok('aws: incomplete credential material fails closed', missingMaterial);
}

// ============================================================
// GCP provider
// ============================================================
section('gcp provider');
{
  _resetForTests();
  const http = async (url, opts) => {
    ok('gcp: hits sts.googleapis.com', url === 'https://sts.googleapis.com/v1/token');
    const body = JSON.parse(opts.body);
    ok('gcp: grant_type=token-exchange', body.grant_type === 'urn:ietf:params:oauth:grant-type:token-exchange');
    ok('gcp: subject_token_type=k8s', body.subject_token_type === 'urn:k8s:params:oauth:token-type:serviceaccount');
    ok('gcp: audience', body.audience === '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/a');
    return {
      status: 200,
      body: JSON.stringify({
        access_token: 'ya29.xxx',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
    };
  };
  const c = await getCredentials('gcp', 'sa.jwt', {
    audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/a',
  }, { httpClient: http });
  ok('gcp: access_token in access_key_id', c.access_key_id === 'ya29.xxx');
  ok('gcp: token_type in security_token', c.security_token === 'Bearer');
  ok('gcp: provider=gcp', c.provider === 'gcp');
  ok('gcp: expires_at_ms ~ now+3600s', c.expires_at_ms > Date.now() + 3500_000 && c.expires_at_ms < Date.now() + 3700_000);
}
{
  _resetForTests();
  // GCP error path
  const http = async () => ({ status: 400, body: JSON.stringify({ error: 'invalid_grant' }) });
  let threw = false;
  try { await getCredentials('gcp', 'tok', { audience: 'x' }, { httpClient: http }); } catch (e) { threw = /gcp sts 400/.test(e.message); }
  ok('gcp: 400 surfaces as error', threw);
}

// ============================================================
// Cache hit
// ============================================================
section('cache hit');
{
  _resetForTests();
  let httpCalls = 0;
  const http = async () => {
    httpCalls++;
    return {
      status: 200,
      body: JSON.stringify({
        Credentials: {
          AccessKeyId: 'AKID-cache',
          AccessKeySecret: 'SEC',
          SecurityToken: 'TOK',
          Expiration: new Date(Date.now() + 3600_000).toISOString(),
        },
      }),
    };
  };
  const opts = { oidcProviderArn: 'a', roleArn: 'r' };
  const c1 = await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  const c2 = await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  const c3 = await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  ok('cache: only 1 upstream call for 3 requests', httpCalls === 1);
  ok('cache: same creds returned', c1.access_key_id === c2.access_key_id && c2.access_key_id === c3.access_key_id);
}

// ============================================================
// Cache miss when near expiration
// ============================================================
section('refresh near expiration');
{
  _resetForTests();
  let httpCalls = 0;
  // 第一次返回 1min 后过期(远小于 REFRESH_SKEW_MS=10min)
  const http = async () => {
    httpCalls++;
    return {
      status: 200,
      body: JSON.stringify({
        Credentials: {
          AccessKeyId: `AKID-${httpCalls}`,
          AccessKeySecret: 'SEC',
          SecurityToken: 'TOK',
          Expiration: new Date(Date.now() + 60_000).toISOString(), // 1 min
        },
      }),
    };
  };
  const opts = { oidcProviderArn: 'a', roleArn: 'r' };
  await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  // 第二次: 已经离 expiration < REFRESH_SKEW_MS,应重新调
  const c2 = await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  ok('near-expiry triggers refresh', httpCalls === 2 && c2.access_key_id === 'AKID-2');
}

// ============================================================
// In-flight 合并
// ============================================================
section('in-flight coalesce');
{
  _resetForTests();
  let httpCalls = 0;
  const http = async () => {
    httpCalls++;
    // 模拟 50ms 延迟
    await new Promise(r => setTimeout(r, 50));
    return {
      status: 200,
      body: JSON.stringify({
        Credentials: {
          AccessKeyId: 'shared',
          AccessKeySecret: 's',
          SecurityToken: 't',
          Expiration: new Date(Date.now() + 3600_000).toISOString(),
        },
      }),
    };
  };
  const opts = { oidcProviderArn: 'a', roleArn: 'r' };
  // 同时发 5 个请求
  const results = await Promise.all([
    getCredentials('aliyun', 'tok', opts, { httpClient: http }),
    getCredentials('aliyun', 'tok', opts, { httpClient: http }),
    getCredentials('aliyun', 'tok', opts, { httpClient: http }),
    getCredentials('aliyun', 'tok', opts, { httpClient: http }),
    getCredentials('aliyun', 'tok', opts, { httpClient: http }),
  ]);
  ok('in-flight: 1 upstream call for 5 concurrent', httpCalls === 1);
  ok('in-flight: all return same creds', results.every(r => r.access_key_id === 'shared'));
}

// ============================================================
// invalidateCache
// ============================================================
section('invalidateCache');
{
  _resetForTests();
  let httpCalls = 0;
  const http = async () => {
    httpCalls++;
    return {
      status: 200,
      body: JSON.stringify({
        Credentials: {
          AccessKeyId: `AKID-${httpCalls}`,
          AccessKeySecret: 's',
          SecurityToken: 't',
          Expiration: new Date(Date.now() + 3600_000).toISOString(),
        },
      }),
    };
  };
  const opts = { oidcProviderArn: 'a', roleArn: 'r' };
  await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  const r = invalidateCache('aliyun', opts);
  ok('invalidate returns ok', r.ok === true);
  await getCredentials('aliyun', 'tok', opts, { httpClient: http });
  ok('invalidate forces refresh', httpCalls === 2);
}

// ============================================================
// listCache (metadata only, no secrets)
// ============================================================
section('listCache');
{
  _resetForTests();
  const http = async (url) => ({
    status: 200,
    body: JSON.stringify(url.includes('amazonaws')
      ? {
          AssumeRoleWithWebIdentityResult: {
            Credentials: {
              AccessKeyId: 'SHOULD-NOT-LEAK',
              SecretAccessKey: 'SHOULD-NOT-LEAK',
              SessionToken: 'SHOULD-NOT-LEAK',
              Expiration: new Date(Date.now() + 3600_000).toISOString(),
            },
          },
        }
      : {
          Credentials: {
            AccessKeyId: 'SHOULD-NOT-LEAK',
            AccessKeySecret: 'SHOULD-NOT-LEAK',
            SecurityToken: 'SHOULD-NOT-LEAK',
            Expiration: new Date(Date.now() + 3600_000).toISOString(),
          },
        }),
  });
  await getCredentials('aliyun', 'tok', { oidcProviderArn: 'a', roleArn: 'r1' }, { httpClient: http });
  await getCredentials('aws', 'tok', { roleArn: 'r2' }, { httpClient: http });
  const items = listCache();
  ok('listCache has 2 entries', items.length === 2);
  const txt = JSON.stringify(items);
  ok('listCache does NOT leak access_key_id', !txt.includes('SHOULD-NOT-LEAK'));
  ok('listCache has remaining_ms', items.every(i => typeof i.remaining_ms === 'number'));
  ok('listCache has provider', items.every(i => ['aliyun', 'aws', 'gcp'].includes(i.provider)));
}

// ============================================================
// validateConfig
// ============================================================
section('validateConfig');
{
  const r1 = validateConfig({ providers: { aliyun: { oidcProviderArn: 'a', roleArns: ['r'] } } });
  ok('valid aliyun config', r1.ok === true && r1.errors.length === 0);
}
{
  const r2 = validateConfig({ providers: { aws: { clusterOidcIssuer: 'i', roleArns: ['r'] } } });
  ok('valid aws config', r2.ok === true && r2.errors.length === 0);
}
{
  const r3 = validateConfig({ providers: { gcp: { audience: 'a' } } });
  ok('valid gcp config', r3.ok === true && r3.errors.length === 0);
}
{
  const r4 = validateConfig({});
  ok('empty config invalid', r4.ok === false);
}
{
  const r5 = validateConfig({ providers: { azure: { roleArns: ['r'] } } });
  ok('unknown provider flagged', r5.errors.some(e => /unknown provider: azure/.test(e)));
}
{
  const r6 = validateConfig({ providers: { aliyun: { roleArns: [] } } });
  ok('aliyun missing oidcProviderArn flagged', r6.errors.some(e => /oidcProviderArn required/.test(e)));
}
{
  const r7 = validateConfig({ providers: { aliyun: { oidcProviderArn: 'a' } } });
  ok('aliyun missing roleArns flagged', r7.errors.some(e => /roleArns.*required/.test(e)));
}
{
  const r8 = validateConfig(null);
  ok('null config rejected', r8.ok === false);
}

// ============================================================
// 凭据零接触: 错误路径不泄漏
// ============================================================
section('zero credential leakage');
{
  _resetForTests();
  const http = async () => { throw new Error('upstream 500 with secret=ghp_xxx in stack'); };
  let err = '';
  try { await getCredentials('aws', 'tok', { roleArn: 'r' }, { httpClient: http }); } catch (e) { err = e.message; }
  // 错误来自我们的 wrap,不暴露内部
  ok('error does not leak stack', !err.includes('at '));
}

// ============================================================
console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
