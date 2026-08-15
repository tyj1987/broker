// broker-test/test-can-proxy.js — v3.0 canProxy / isServiceAllowed / clientNamesAllowedFor
// 覆盖: rule 匹配 (string / object / regex / 累加语义)

const cp = await import('file:///C:/home/my-first-app/broker/can-proxy.js');

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(s) { console.log(`\n--- ${s} ---`); }

// helper: 拼 ctx
function ctxOf(client) { return { client }; }

(async () => {
  // ======== 1. checkPathAllowed (paths 数组) ========
  section('checkPathAllowed');
  {
    ok('undefined → true', cp.checkPathAllowed(undefined, '/x') === true);
    ok('string regex match', cp.checkPathAllowed('^/user$', '/user') === true);
    ok('string regex no match', cp.checkPathAllowed('^/user$', '/repo') === false);
    ok('array any match', cp.checkPathAllowed(['^/user$', '^/repos'], '/repos/tyj') === true);
    ok('array no match', cp.checkPathAllowed(['^/user$', '^/repos'], '/gists') === false);
    let threw = false; try { cp.checkPathAllowed('[invalid(', '/x'); } catch { threw = true; }
    ok('invalid regex returns false (不抛)', threw === false && cp.checkPathAllowed('[invalid(', '/x') === false);
  }

  // ======== 2. matchProxyRule (单 rule 匹配) ========
  section('matchProxyRule');
  {
    ok('* 通配', cp.matchProxyRule('*', 'github', '/user') === true);
    ok('.* 通配', cp.matchProxyRule('.*', 'github', '/user') === true);
    ok('string 精确匹配', cp.matchProxyRule('github', 'github', '/user') === true);
    ok('string 不匹配', cp.matchProxyRule('openai', 'github', '/user') === false);
    ok('string 含 regex 元字符 (githu*)', cp.matchProxyRule('githu*', 'github', '/user') === true);
    ok('string 含 regex 元字符 (^github$)', cp.matchProxyRule('^github$', 'github', '/user') === true);
    ok('字面 . 不当 regex (aliyun.com 不匹配 aliyunXcom)', cp.matchProxyRule('aliyun.com', 'aliyunXcom', '/x') === false);
    ok('字面 . 不当 regex (aliyun.com 匹配 aliyun.com)', cp.matchProxyRule('aliyun.com', 'aliyun.com', '/x') === true);
    ok('object 显式 service 匹配', cp.matchProxyRule({ service: 'github' }, 'github', '/user') === true);
    ok('object 显式 service 不匹配', cp.matchProxyRule({ service: 'github' }, 'openai', '/user') === false);
    ok('object {service: regex}', cp.matchProxyRule({ service: '^github$' }, 'github', '/x') === true);
    ok('object paths 任一匹配', cp.matchProxyRule({ service: 'github', paths: ['^/user$', '^/repos'] }, 'github', '/repos/tyj') === true);
    ok('object paths 全不匹配', cp.matchProxyRule({ service: 'github', paths: ['^/user$'] }, 'github', '/gists') === false);
    ok('null rule', cp.matchProxyRule(null, 'x', '/x') === false);
    ok('number rule', cp.matchProxyRule(42, 'x', '/x') === false);
  }

  // ======== 3. canProxy (服务端代理权限) ========
  section('canProxy');
  {
    // admin 永远 true
    ok('admin → true', cp.canProxy(ctxOf({ role: 'admin' }), 'github', '/user') === true);
    // 无 ctx
    ok('无 ctx → false', cp.canProxy(null, 'github', '/user') === false);
    ok('无 client → false', cp.canProxy({}, 'github', '/user') === false);
    // string 通配
    ok('developer + ["*"] → true', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: ['*'] }), 'github', '/user') === true);
    // string 精确
    ok('developer + ["github"] 调 github → true', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: ['github'] }), 'github', '/user') === true);
    ok('developer + ["github"] 调 openai → false', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: ['github'] }), 'openai', '/user') === false);
    // 之前 bug: object {service: ".*"} 期望通配但返 false
    ok('M2.5 修复: developer + [{service:".*"}] → true', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: [{ service: '.*' }] }), 'github', '/user') === true);
    // 之前 bug: ['github', '*'] 累积, 应命中
    ok('累积语义: ["github", "*"] 调 openai → true', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: ['github', '*'] }), 'openai', '/user') === true);
    // object + paths
    ok('paths 限死: object {service, paths:["^/user$"]} 调 /user → true',
      cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: [{ service: 'github', paths: ['^/user$'] }] }), 'github', '/user') === true);
    ok('paths 限死: object 调 /gists → false',
      cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: [{ service: 'github', paths: ['^/user$'] }] }), 'github', '/gists') === false);
    // 空 allow
    ok('空 allowed_proxy → false', cp.canProxy(ctxOf({ role: 'developer', allowed_proxy: [] }), 'github', '/user') === false);
  }

  // ======== 4. isServiceAllowed (UI 角标) ========
  section('isServiceAllowed');
  {
    ok('admin → true', cp.isServiceAllowed(ctxOf({ role: 'admin' }), 'github') === true);
    ok('developer + ["*"] → true', cp.isServiceAllowed(ctxOf({ role: 'developer', allowed_proxy: ['*'] }), 'github') === true);
    ok('developer + ["github"] 查 github → true', cp.isServiceAllowed(ctxOf({ role: 'developer', allowed_proxy: ['github'] }), 'github') === true);
    ok('developer + ["github"] 查 openai → false', cp.isServiceAllowed(ctxOf({ role: 'developer', allowed_proxy: ['github'] }), 'openai') === false);
    ok('developer + [{service:"github"}] 查 github → true', cp.isServiceAllowed(ctxOf({ role: 'developer', allowed_proxy: [{ service: 'github' }] }), 'github') === true);
    ok('developer + [{service:".*"}] 查 openai → true (regex 修)',
      cp.isServiceAllowed(ctxOf({ role: 'developer', allowed_proxy: [{ service: '.*' }] }), 'openai') === true);
  }

  // ======== 5. clientNamesAllowedFor (admin UI 权限矩阵) ========
  section('clientNamesAllowedFor');
  {
    const clients = {
      'admin1': { role: 'admin' },
      'dev1':   { role: 'developer', allowed_proxy: ['github'] },
      'dev2':   { role: 'developer', allowed_proxy: ['openai'] },
      'dev3':   { role: 'developer', allowed_proxy: [{ service: 'github' }] },
      'dev4':   { role: 'developer', allowed_proxy: [{ service: '.*' }] },  // 通配
      'readonly1': { role: 'readonly', allowed_proxy: [] },
    };
    const ghUsers = cp.clientNamesAllowedFor(clients, 'github').sort();
    ok('github 权限列表包含 admin1/dev1/dev3/dev4', JSON.stringify(ghUsers) === JSON.stringify(['admin1', 'dev1', 'dev3', 'dev4']));
    const oaUsers = cp.clientNamesAllowedFor(clients, 'openai').sort();
    ok('openai 权限列表包含 admin1/dev2/dev4', JSON.stringify(oaUsers) === JSON.stringify(['admin1', 'dev2', 'dev4']));
    const noUsers = cp.clientNamesAllowedFor(clients, 'unknown').sort();
    ok('unknown 权限列表 = [admin1, dev4] (dev4.* 通配)', JSON.stringify(noUsers) === JSON.stringify(['admin1', 'dev4']));
  }

  console.log('\n========================================');
  console.log(`  test-can-proxy: PASS=${pass} FAIL=${fail}`);
  console.log('========================================');
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('FATAL:', e); process.exit(1); });
