import {
  aliyunRpcVersion, mergeAliyunQuery, ALIYUN_RPC_VERSION_BY_HOST,
} from '../broker/lib/aliyun-rpc.js';

let passed = 0, failed = 0;
function assert(c, m) {
  if (c) { passed++; console.log('  OK  ', m); }
  else { failed++; console.error('  FAIL', m); }
}

console.log('=== aliyunRpcVersion ===');
assert(aliyunRpcVersion({ upstream: 'https://alidns.aliyuncs.com' }) === '2015-01-09', 'alidns host');
assert(aliyunRpcVersion({ upstream: 'https://ecs.aliyuncs.com' }) === '2014-05-26', 'ecs host');
assert(aliyunRpcVersion({ upstream: 'https://ram.aliyuncs.com' }) === '2015-05-01', 'ram host');
assert(aliyunRpcVersion({
  upstream: 'https://alidns.aliyuncs.com',
  query: { Version: '2018-01-01' },
}) === '2018-01-01', 'query Version wins');
assert(aliyunRpcVersion({
  path: '/?Action=DescribeDomains&Version=2015-01-09',
}) === '2015-01-09', 'path Version');
assert(aliyunRpcVersion({
  serviceCfg: { api_version: '2015-01-09' },
  upstream: 'https://ecs.aliyuncs.com',
}) === '2015-01-09', 'serviceCfg.api_version beats host');
assert(ALIYUN_RPC_VERSION_BY_HOST['alidns.aliyuncs.com'] === '2015-01-09', 'map');

console.log('=== mergeAliyunQuery ===');
{
  const q = mergeAliyunQuery('/?Action=DescribeDomains&DomainName=example.com', { PageSize: '10' });
  assert(q.Action === 'DescribeDomains', 'path Action');
  assert(q.DomainName === 'example.com', 'path DomainName');
  assert(q.PageSize === '10', 'json query merged');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
