// broker-test/test-signing.js — V4 签名算法单元测试
// 用官方文档示例验证输出格式正确(不要求签名值 byte-equal,只要结构对)
import { signAliyunV3 } from '../broker/signing/aliyun-v3.js';
import { signTencentV3 } from '../broker/signing/tencent-v3.js';
import { signAwsSigV4 } from '../broker/signing/aws-sigv4.js';
import { buildServiceAccountJwt, exchangeJwtForToken, signGcpJwt, clearGcpCache } from '../broker/signing/gcp-jwt.js';
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

// === Aliyun v3 ===
section('Aliyun v3');
{
  const h = signAliyunV3({
    method: 'POST',
    host: 'ecs.aliyuncs.com',
    path: '/',
    query: { Action: 'DescribeInstances', RegionId: 'cn-hangzhou' },
    body: '{}',
    secret: { access_key_id: 'LTAI_TEST', access_key_secret: 'fake-secret-for-shape-test' },
    now: new Date('2026-08-26T09:12:34Z'),
  });
  ok('auth header is ACS3', h.Authorization.startsWith('ACS3-HMAC-SHA256 Credential=LTAI_TEST,'));
  ok('has SignedHeaders', /SignedHeaders=[^,]+,/.test(h.Authorization));
  ok('has Signature=64hex', /Signature=[0-9a-f]{64}$/.test(h.Authorization));
  ok('has x-acs-date', !!h['x-acs-date']);
  ok('has x-acs-content-sha256', /^[0-9a-f]{64}$/.test(h['x-acs-content-sha256']));
  ok('host header included', h.host === 'ecs.aliyuncs.com');
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
  globalThis.fetch = async (url, opts) => {
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
