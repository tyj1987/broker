// broker-test/test-master-key.js — v3.0 M3.3 单元测试
// 测试 api-keys.js 的 master/child 关系 + scope 限定
// 不依赖 broker 启动

import {
  generateApiKey,
  generateMasterKey,
  createChildKey,
  canCreateChild,
  isChildKey,
  isExpired,
  publicView,
  findApiKey,
  canResolveSecret,
  canProxyService,
  canInvokeApiKeyOperation,
} from '../broker/api-keys.js';

let pass = 0, fail = 0;

function ok(name, cond) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
}

function section(name) { console.log(`\n[${name}]`); }

// ============================================================
// 1. generateMasterKey
// ============================================================
section('generateMasterKey');
{
  const cfgKeys = [];
  const { id, secret, key_obj } = generateMasterKey('mcp-test', 'client.test', {});
  ok('secret starts with mb_test_', secret.startsWith('mb_test_'));
  ok('id is 16 chars hex', /^[a-f0-9]{16}$/.test(id));
  ok('is_master = true', key_obj.is_master === true);
  ok('can_create_child = true', key_obj.can_create_child === true);
  ok('scopes only keys:issue_child', JSON.stringify(key_obj.scopes) === JSON.stringify(['keys:issue_child']));
  ok('default_child_ttl_seconds = 3600', key_obj.default_child_ttl_seconds === 3600);
  ok('child_scopes has 2 items', key_obj.child_scopes.length === 2);
  ok('expires_at ~30d from now', Math.abs(new Date(key_obj.expires_at).getTime() - Date.now() - 30*24*3600*1000) < 5000);
}

// ============================================================
// 2. canCreateChild
// ============================================================
section('canCreateChild');
{
  const { key_obj: m } = generateMasterKey('m', 'admin');
  const r1 = canCreateChild(m);
  ok('master can create', r1.ok === true);

  const r2 = canCreateChild(null);
  ok('null denied (not_found)', r2.ok === false && r2.reason === 'not_found');

  m.revoked_at = new Date().toISOString();
  const r3 = canCreateChild(m);
  ok('revoked denied', r3.ok === false && r3.reason === 'revoked');
  m.revoked_at = null;

  const r4 = canCreateChild({ ...m, scopes: ['secrets:resolve'], is_master: true, can_create_child: true });
  ok('wrong scope denied', r4.ok === false && r4.reason === 'no_keys_scope');

  const r5 = canCreateChild({ ...m, scopes: ['keys:issue_child'], is_master: false, can_create_child: true });
  ok('non-master denied', r5.ok === false && r5.reason === 'not_master');

  const r6 = canCreateChild({ ...m, scopes: ['keys:issue_child'], is_master: true, can_create_child: false });
  ok('no child perm denied', r6.ok === false && r6.reason === 'no_child_perm');

  const m2 = { ...m, expires_at: new Date(Date.now() - 1000).toISOString() };
  const r7 = canCreateChild(m2);
  ok('expired denied', r7.ok === false && r7.reason === 'expired');
}

// ============================================================
// 3. createChildKey - scope 限定
// ============================================================
section('createChildKey (scope 限定)');
{
  const cfgKeys = [];
  const { key_obj: master } = generateMasterKey('m', 'client.test', {
    child_scopes: ['secrets:resolve', 'services:proxy'],
    allowed_secrets: ['GITHUB_PAT', 'ALIYUN_AK'],
    allowed_services: ['github', 'aliyun_ecs'],
    allowed_operations: ['github:list_*', 'aliyun_ecs:describe_instances'],
  });

  // 3a. 默认 child 用 master 的 scopes
  cfgKeys.push(master);  // 模拟 broker 把 master 加到 cfgKeys
  const r1 = createChildKey(cfgKeys, master, 'child-default');
  ok('child create ok', r1.ok === true);
  ok('child scopes = master child_scopes', JSON.stringify(r1.key_obj.scopes) === JSON.stringify(['secrets:resolve', 'services:proxy']));
  ok('child parent_master_id = master.id', r1.key_obj.parent_master_id === master.id);
  ok('child expires ~1h', Math.abs(new Date(r1.key_obj.expires_at).getTime() - Date.now() - 3600*1000) < 5000);
  ok('child is master=false', r1.key_obj.is_master === false);
  ok('child can_create_child=false', r1.key_obj.can_create_child === false);
  ok('cfgKeys now has 2 (master + child)', cfgKeys.length === 2);

  // 3b. 越权 scope 攻击：child 试图加 master 没限的 scope
  const r2 = createChildKey(cfgKeys, master, 'child-bad', {
    scopes: ['admin', 'keys:issue_child', 'secrets:resolve'],  // 越权
  });
  ok('privilege escalation blocked', r2.ok === true && !r2.key_obj.scopes.includes('admin') && !r2.key_obj.scopes.includes('keys:issue_child'));
  ok('only master-allowed scopes kept', JSON.stringify(r2.key_obj.scopes) === JSON.stringify(['secrets:resolve']));

  // 3c. 越权 allowed_secrets
  const r3 = createChildKey(cfgKeys, master, 'child-bad-secret', {
    allowed_secrets: ['GITHUB_PAT', 'ROOT_PASSWORD'],  // ROOT_PASSWORD 不在 master
  });
  ok('bad allowed_secrets filtered', r3.ok === true && !r3.key_obj.allowed_secrets.includes('ROOT_PASSWORD'));
  ok('good allowed_secrets kept', r3.key_obj.allowed_secrets.includes('GITHUB_PAT'));

  // 3d. 越权 allowed_services
  const r4 = createChildKey(cfgKeys, master, 'child-bad-svc', {
    allowed_services: ['github', 'aws_prod'],  // aws_prod 不在 master
  });
  ok('bad allowed_services filtered', r4.ok === true && !r4.key_obj.allowed_services.includes('aws_prod'));
  const r4b = createChildKey(cfgKeys, master, 'child-bad-operation', {
    allowed_operations: ['github:list_*', 'github:delete_repository'],
  });
  ok('bad allowed operation filtered', r4b.ok === true && !r4b.key_obj.allowed_operations.includes('github:delete_repository'));
  ok('parent allowed operation retained', r4b.key_obj.allowed_operations.includes('github:list_*'));

  // 3e. custom ttl
  const r5 = createChildKey(cfgKeys, master, 'child-custom-ttl', { ttl_seconds: 600 });
  ok('custom ttl 600s', Math.abs(new Date(r5.key_obj.expires_at).getTime() - Date.now() - 600*1000) < 5000);

  // 3f. revoke 后拒绝
  master.revoked_at = new Date().toISOString();
  const r6 = createChildKey(cfgKeys, master, 'child-after-revoke');
  ok('revoked master denied', r6.ok === false && r6.reason === 'revoked');
}

// ============================================================
// 4. isChildKey
// ============================================================
section('isChildKey');
{
  const cfgKeys = [];
  const { key_obj: m } = generateMasterKey('m', 'admin');
  const { key_obj: c } = generateApiKey('c', 'admin', { parent_master_id: m.id, scopes: ['secrets:resolve'] });
  ok('master is not child', isChildKey(m) === false);
  ok('child with parent is child', isChildKey(c) === true);
  ok('no parent is not child', isChildKey({ ...c, parent_master_id: null }) === false);
  ok('null is not child', isChildKey(null) === false);
}

// ============================================================
// 5. publicView 含 master/child 字段
// ============================================================
section('publicView 含 master/child 字段');
{
  const cfgKeys = [];
  const { key_obj: m } = generateMasterKey('m', 'admin');
  const v = publicView(m);
  ok('view has is_master', v.is_master === true);
  ok('view has can_create_child', v.can_create_child === true);
  ok('view has default_child_ttl_seconds', v.default_child_ttl_seconds === 3600);
  ok('view has child_scopes', Array.isArray(v.child_scopes));
  ok('view has parent_master_id=null', v.parent_master_id === null);
}

// ============================================================
// 6. findApiKey 仍兼容（应能找到 child）
// ============================================================
section('findApiKey 兼容');
{
  const cfgKeys = [];
  const { key_obj: m, secret: ms } = generateMasterKey('m', 'admin');
  cfgKeys.push(m);
  const r1 = createChildKey(cfgKeys, m, 'c');
  cfgKeys.push(r1.key_obj);

  const found1 = findApiKey(cfgKeys, ms);
  ok('master found by secret', !!found1 && found1.id === m.id);
  ok('master is_master true', found1.is_master === true);

  const found2 = findApiKey(cfgKeys, r1.secret);
  ok('child found by secret', !!found2 && found2.id === r1.key_obj.id);
  ok('child parent_master_id matches', found2.parent_master_id === m.id);
  m.revoked_at = new Date().toISOString();
  ok('revoked parent invalidates existing child', findApiKey(cfgKeys, r1.secret) === null);
}

section('child cannot relax parent constraints');
{
  const cfgKeys = [];
  const { key_obj: master } = generateMasterKey('bounded', 'admin', {
    rate_limit: '100/hour',
    ip_whitelist: ['203.0.113.0/24'],
    allowed_secrets: ['ONE'],
    allowed_services: ['github'],
    default_child_ttl_seconds: 300,
  });
  cfgKeys.push(master);
  const child = createChildKey(cfgKeys, master, 'attempt-escalation', {
    rate_limit: 'unlimited',
    ip_whitelist: null,
    allowed_secrets: ['ONE', 'TWO'],
    allowed_services: ['github', 'admin'],
    ttl_seconds: 3600,
  });
  ok('child retains parent rate limit', child.key_obj.rate_limit === '100/hour');
  ok('child retains parent IP boundary', JSON.stringify(child.key_obj.ip_whitelist) === JSON.stringify(['203.0.113.0/24']));
  ok('child secret grants intersect parent', JSON.stringify(child.key_obj.allowed_secrets) === JSON.stringify(['ONE']));
  ok('child service grants intersect parent', JSON.stringify(child.key_obj.allowed_services) === JSON.stringify(['github']));
  ok('child TTL capped by parent policy', new Date(child.key_obj.expires_at).getTime() <= Date.now() + 301_000);
}

// ============================================================
// 7. canResolveSecret / canProxyService - child 仍受 scopes 限制
// ============================================================
section('child scope 仍受 canResolveSecret / canProxyService 限制');
{
  const cfgKeys = [];
  const { key_obj: m } = generateMasterKey('m', 'admin');
  const r1 = createChildKey(cfgKeys, m, 'c');
  const child = r1.key_obj;
  ok('empty secret grant denies by default', canResolveSecret(child, 'GITHUB_PAT') === false);
  ok('empty service grant denies by default', canProxyService(child, 'github') === false);
  ok('explicit secret wildcard permits', canResolveSecret({ ...child, allowed_secrets: ['*'] }, 'GITHUB_PAT') === true);
  ok('explicit service wildcard permits', canProxyService({ ...child, allowed_services: ['*'] }, 'github') === true);
  ok('operation deny defaults closed', canInvokeApiKeyOperation({ ...child, allowed_services: ['github'] }, 'github', 'list_repositories') === false);
  ok('exact operation grant permits', canInvokeApiKeyOperation({ ...child, allowed_services: ['github'], allowed_operations: ['github:list_repositories'] }, 'github', 'list_repositories') === true);
  ok('operation prefix grant permits', canInvokeApiKeyOperation({ ...child, allowed_services: ['github'], allowed_operations: ['github:list_*'] }, 'github', 'list_repositories') === true);
  ok('operation grant cannot bypass service grant', canInvokeApiKeyOperation({ ...child, allowed_services: [], allowed_operations: ['*'] }, 'github', 'list_repositories') === false);
  ok('child cannot resolve if no secrets:resolve', canResolveSecret({ ...child, scopes: ['services:proxy'] }, 'X') === false);
}

console.log(`\n========================================`);
console.log(`  test-master-key: PASS=${pass} FAIL=${fail}`);
console.log(`========================================`);
process.exit(fail === 0 ? 0 : 1);
