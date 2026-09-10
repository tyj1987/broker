// broker-test/test-signing.js — signing algorithm unit tests
import { signAliyunV3 } from '../broker/signing/aliyun-v3.js';
import { signTencentV3 } from '../broker/signing/tencent-v3.js';
import { signAwsSigV4 } from '../broker/signing/aws-sigv4.js';
import { buildServiceAccountJwt, clearGcpCache } from '../broker/signing/gcp-jwt.js';
import { getAzureToken, signAzureAd, clearAzureCache } from '../broker/signing/azure-ad.js';
import { signCloudflare } from '../broker/signing/cloudflare.js';
import { getDockerRegistryToken, signDockerRegistry } from '../broker/signing/docker-registry.js';
import { signWechatPayV3 } from '../broker/signing/wechat-pay.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }
function throwsLike(run, pattern) {
  try {
    run();
    return false;
  } catch (error) {
    return pattern.test(error.message);
  }
}

// === Aliyun v3 ===
section('Aliyun v3');
{
  const h = signAliyunV3({
    method: 'POST',
    host: 'ecs.cn-shanghai.aliyuncs.com',
    path: '/',
    query: {
      ImageId: 'win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd',
      RegionId: 'cn-shanghai',
    },
    headers: {
      'x-acs-action': 'RunInstances',
      'x-acs-version': '2014-05-26',
    },
    body: '',
    secret: {
      access_key_id: 'YourAccessKeyId',
      access_key_secret: 'YourAccessKeySecret',
    },
    now: new Date('2023-10-26T10:22:32Z'),
    nonce: '3156853299f313e23d1673dc12e1703d',
  });
  ok(
    'official signature vector matches byte-for-byte',
    h.Authorization ===
      'ACS3-HMAC-SHA256 Credential=YourAccessKeyId,' +
        'SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,' +
        'Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0',
  );
  ok('uses ISO 8601 UTC date', h['x-acs-date'] === '2023-10-26T10:22:32Z');
  ok('includes required nonce', h['x-acs-signature-nonce'] === '3156853299f313e23d1673dc12e1703d');
  ok('host header included', h.host === 'ecs.cn-shanghai.aliyuncs.com');
}
{
  const h = signAliyunV3({
    method: 'GET',
    host: 'ecs.cn-hangzhou.aliyuncs.com',
    path: '/',
    headers: { 'x-acs-action': 'DescribeInstances', 'x-acs-version': '2014-05-26' },
    query: { RegionId: 'cn-hangzhou' },
    secret: {
      access_key_id: 'STS.TEST',
      access_key_secret: 'temporary-secret',
      security_token: 'temporary-security-token',
    },
    now: new Date('2026-09-11T00:00:00Z'),
    nonce: 'nonce-1',
  });
  ok('STS security token is signed', h.Authorization.includes('x-acs-security-token'));
  ok('STS security token is returned', h['x-acs-security-token'] === 'temporary-security-token');
}
{
  let rejectedAuthorization = false;
  try {
    signAliyunV3({
      method: 'GET', host: 'ecs.cn-hangzhou.aliyuncs.com', path: '/',
      headers: { Authorization: 'Bearer attacker' },
      secret: { access_key_id: 'test', access_key_secret: 'test' }, nonce: 'nonce-2',
    });
  } catch (error) {
    rejectedAuthorization = /authorization header is forbidden/.test(error.message);
  }
  ok('rejects caller-supplied Authorization', rejectedAuthorization);
}
{
  let rejectedMissingMetadata = false;
  try {
    signAliyunV3({
      method: 'GET', host: 'ecs.cn-hangzhou.aliyuncs.com', path: '/', headers: {},
      secret: { access_key_id: 'test', access_key_secret: 'test' }, nonce: 'nonce-3',
    });
  } catch (error) {
    rejectedMissingMetadata = /x-acs-action must be a non-empty string/.test(error.message);
  }
  ok('rejects missing API action metadata', rejectedMissingMetadata);
}
{
  let rejectedInjection = false;
  try {
    signAliyunV3({
      method: 'GET', host: 'ecs.cn-hangzhou.aliyuncs.com\r\nX-Evil: yes', path: '/',
      secret: { access_key_id: 'test', access_key_secret: 'test' }, nonce: 'nonce-4',
    });
  } catch (error) {
    rejectedInjection = /control characters/.test(error.message);
  }
  ok('rejects header injection through host', rejectedInjection);
}
{
  const base = {
    method: 'POST',
    host: 'ecs.cn-hangzhou.aliyuncs.com',
    path: '/',
    headers: { 'x-acs-action': 'DescribeInstances', 'x-acs-version': '2014-05-26' },
    query: { RegionId: 'cn-hangzhou', Omitted: undefined, Enabled: true },
    body: { PageNumber: 1 },
    secret: { access_key_id: 'test', access_key_secret: 'test' },
    now: '2026-09-11T00:00:00Z',
  };
  const generated = signAliyunV3(base);
  ok('generates a nonce when omitted', /^[0-9a-f-]{36}$/.test(generated['x-acs-signature-nonce']));
  ok('serializes object request bodies', /^[0-9a-f]{64}$/.test(generated['x-acs-content-sha256']));
  for (const [name, change, pattern] of [
    ['rejects an invalid method', { method: '' }, /method must be a non-empty string/],
    ['rejects a relative path', { path: 'relative' }, /path must start/],
    ['rejects a missing secret', { secret: null }, /secret is required/],
    ['rejects a missing access key id', { secret: { access_key_secret: 'test' } }, /access_key_id/],
    ['rejects a missing access key secret', { secret: { access_key_id: 'test' } }, /access_key_secret/],
    ['rejects an invalid nonce', { nonce: 'bad\nnonce' }, /nonce contains control/],
    ['rejects an invalid date', { now: 'not-a-date' }, /now must be a valid date/],
    ['rejects non-object query input', { query: [] }, /query must be an object/],
    ['rejects structured query values', { query: { RegionId: {} } }, /must be a scalar/],
    ['rejects non-object headers', { headers: [] }, /headers must be an object/],
    ['rejects invalid header names', { headers: { 'bad header': 'x' } }, /invalid header name/],
    ['rejects duplicate normalized headers', { headers: { Accept: 'a', accept: 'b' } }, /duplicate header/],
    ['rejects empty header values', { headers: { Accept: ' ' } }, /invalid header value/],
    ['rejects control characters in header values', { headers: { Accept: 'a\r\nb' } }, /invalid header value/],
    [
      'rejects invalid STS security tokens',
      { secret: { access_key_id: 'test', access_key_secret: 'test', security_token: '' } },
      /security_token must be a non-empty string/,
    ],
  ]) {
    ok(name, throwsLike(() => signAliyunV3({ ...base, ...change }), pattern));
  }
}

// === Tencent v3 ===
section('Tencent v3');
{
  const h = signTencentV3({
    method: 'POST',
    host: 'cvm.tencentcloudapi.com',
    path: '/',
    body: '{"Limit":1}',
    service: 'cvm',
    action: 'DescribeInstances',
    version: '2017-03-12',
    region: 'ap-guangzhou',
    timestamp: 1723456789,
    secret: { secret_id: 'AKIDzTestIdxxxxxxxxxxx', secret_key: 'fake-secret' },
  });
  ok('auth starts with TC3', h.Authorization.startsWith('TC3-HMAC-SHA256 Credential=AKIDzTestIdxxxxxxxxxxx/'));
  ok('credentialScope has cvm/tc3_request', h.Authorization.includes('/cvm/tc3_request,'));
  ok('has X-TC-Action', h['X-TC-Action'] === 'DescribeInstances');
  ok('has X-TC-Region', h['X-TC-Region'] === 'ap-guangzhou');
  ok('has X-TC-Timestamp', h['X-TC-Timestamp'] === '1723456789');
  ok('has X-TC-Version', h['X-TC-Version'] === '2017-03-12');
  ok('Signature 64hex', /Signature=[0-9a-f]{64}$/.test(h.Authorization));
}

// === AWS SigV4 ===
section('AWS SigV4');
{
  const h = signAwsSigV4({
    method: 'GET',
    host: 's3.amazonaws.com',
    path: '/my-bucket/key',
    query: { partNumber: '1', uploadId: 'abc' },
    service: 's3',
    region: 'us-east-1',
    now: new Date('2026-08-26T09:12:34Z'),
    secret: { access_key_id: 'AKIAIOSFODNN7EXAMPLE', secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
  });
  ok('auth starts with AWS4', h.Authorization.startsWith('AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/'));
  ok('credentialScope has s3', h.Authorization.includes('/s3/aws4_request,'));
  ok('has X-Amz-Date', h['X-Amz-Date'] === '20260826T091234Z');
  ok('has X-Amz-Content-Sha256', /^[0-9a-f]{64}$/.test(h['X-Amz-Content-Sha256']));
  ok('Signature 64hex', /Signature=[0-9a-f]{64}$/.test(h.Authorization));
}
{
  // STS session token
  const h2 = signAwsSigV4({
    method: 'GET',
    host: 'sts.amazonaws.com',
    path: '/',
    service: 'sts',
    region: 'us-east-1',
    now: new Date('2026-08-26T09:12:34Z'),
    secret: {
      access_key_id: 'ASIA_TEMP_KEY_XXXXXXXXXX',
      secret_access_key: 'temp-secret',
      session_token: 'FQoGZXIvYXdzEHcaSESSIONTOKENxxxxx',
    },
  });
  ok('session token in signed headers', /x-amz-security-token/.test(h2.Authorization));
}

// === GCP JWT ===
section('GCP JWT');
{
  // generate a test RSA key
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pkPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const jwt = buildServiceAccountJwt('test@proj.iam.gserviceaccount.com', pkPem, ['https://www.googleapis.com/auth/cloud-platform']);
  const parts = jwt.split('.');
  ok('JWT has 3 parts', parts.length === 3);
  // decode header and payload
  const dec = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  const header = JSON.parse(dec(parts[0]));
  const payload = JSON.parse(dec(parts[1]));
  ok('header alg=RS256', header.alg === 'RS256');
  ok('header typ=JWT', header.typ === 'JWT');
  ok('payload iss is sa email', payload.iss === 'test@proj.iam.gserviceaccount.com');
  ok('payload aud is google', payload.aud === 'https://oauth2.googleapis.com/token');
  ok('payload has scope', payload.scope.includes('cloud-platform'));
  // verify signature using public key
  const { createVerify } = await import('node:crypto');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${parts[0]}.${parts[1]}`);
  ok('signature verifies', verifier.verify(pubPem, parts[2], 'base64'));
  // expiration set
  ok('exp is in future', payload.exp > Math.floor(Date.now() / 1000));
}
clearGcpCache();

// === Azure AD ===
section('Azure AD');
{
  // mock fetch
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, _opts) => {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' && parsed.hostname === 'login.microsoftonline.com'
      && parsed.pathname.endsWith('/oauth2/v2.0/token')) {
      return new Response(JSON.stringify({ access_token: 'mock-azure-token', expires_in: 3600 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response('not found', { status: 404 });
  };
  const token = await getAzureToken({
    tenant_id: 'tenant-uuid-12345',
    client_id: 'client-uuid',
    client_secret: 'shh',
    scope: 'https://graph.microsoft.com/.default',
  });
  ok('returns mocked token', token === 'mock-azure-token');
  // cache hit
  const t2 = await getAzureToken({
    tenant_id: 'tenant-uuid-12345',
    client_id: 'client-uuid',
    client_secret: 'shh',
    scope: 'https://graph.microsoft.com/.default',
  });
  ok('cache hit returns same token', t2 === 'mock-azure-token');
  // signAzureAd
  const h = await signAzureAd({
    tenant_id: 'tenant-uuid-12345',
    client_id: 'client-uuid',
    client_secret: 'shh',
  });
  ok('Authorization Bearer', h.Authorization === 'Bearer mock-azure-token');
  clearAzureCache();
  globalThis.fetch = origFetch;
}

// === Cloudflare ===
section('Cloudflare');
{
  const h = signCloudflare({ api_token: 'cf-test-token-1234567890' });
  ok('Authorization Bearer', h.Authorization === 'Bearer cf-test-token-1234567890');
  ok('Content-Type JSON', h['Content-Type'] === 'application/json');
}
{
  let threw = false;
  try { signCloudflare({}); } catch (_e) { threw = true; }
  ok('missing token throws', threw);
}

// === Docker Registry ===
section('Docker Registry');
{
  // mock via fetchImpl injection (the module's own http module would need a real server)
  const mockFetch = async (url) => {
    if (url.endsWith('/v2/')) {
      return new Response('', {
        status: 401,
        headers: {
          'www-authenticate': 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"',
        },
      });
    }
    if (url.includes('auth.docker.io/token')) {
      return new Response(JSON.stringify({ token: 'mock-docker-token' }), { status: 200 });
    }
    return new Response('', { status: 404 });
  };
  const tok = await getDockerRegistryToken({ registry: 'https://registry-1.docker.io', fetchImpl: mockFetch });
  ok('returns mock token', tok.token === 'mock-docker-token');
  const h = await signDockerRegistry({ registry: 'https://registry-1.docker.io', fetchImpl: mockFetch });
  ok('Authorization Bearer', h.Authorization === 'Bearer mock-docker-token');
}
{
  // no auth needed (probe returns 200)
  const noAuthFetch = async () => new Response('{}', { status: 200 });
  const tok = await getDockerRegistryToken({ registry: 'http://localhost:5000', fetchImpl: noAuthFetch });
  ok('no-auth returns empty token', tok.token === '');
}

// === WeChat Pay V3 ===
section('WeChat Pay V3');
{
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pkPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const h = signWechatPayV3({
    method: 'POST',
    path: '/v3/pay/transactions/jsapi',
    body: '{"a":1}',
    timestamp: 1723456789,
    nonce_str: 'abc123nonce',
    secret: { mch_id: '1900000109', cert_serial: 'SERIAL_ABC', private_key: pkPem },
  });
  ok('Authorization WECHATPAY2', h.Authorization.startsWith('WECHATPAY2-SHA256-RSA2048 mchid="1900000109"'));
  ok('nonce_str present', /nonce_str="abc123nonce"/.test(h.Authorization));
  ok('serial_no present', /serial_no="SERIAL_ABC"/.test(h.Authorization));
  ok('signature present', /signature="[A-Za-z0-9+/=]+"/.test(h.Authorization));
  ok('Content-Type JSON', h['Content-Type'] === 'application/json');
  ok('User-Agent', h['User-Agent'].includes('secret-broker'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
