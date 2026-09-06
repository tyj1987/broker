// broker-test/test-proxy-guard.js — v3.1 M5.5
// Service ↔ Secret 联动 (call_service 前置检查) 单元测试
// 覆盖:
//   1. checkSecretForService 5 维 status 分类 (ok/expired/unreachable/misconfigured/fail/skipped/unknown/no_secret)
//   2. 5 min 缓存复用 (同 secret 第二次不重查)
//   3. 缓存过期 (5 min 后重查)
//   4. clearSecretGuardCache 单个 / 全部
//   5. guardHint 4 种 status 提示文本
//   6. 注入失败兜底 (getSecretStatusFn 缺 / null)

import {
  checkSecretForService,
  clearSecretGuardCache,
  guardHint,
  SECRET_GUARD_TTL_MS,
} from '../broker/service-secret-guard.js';

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(s) { console.log(`\n--- ${s} ---`); }

// 每次测试前清缓存, 避免互相干扰
function reset() { clearSecretGuardCache(); }

// mock: 健康度查表
function makeStatusLookup(table) {
  return (name) => table[name] || null;
}

(async () => {
  // ======== 1. 5 维 status 分类 ========
  section('checkSecretForService: 5 维 status 分类');
  {
    reset();
    const lookup = makeStatusLookup({
      'OK_TOKEN':    { status: 'ok',            detail: 'user=octocat' },
      'EXP_TOKEN':   { status: 'expired',       detail: '401 Bad credentials' },
      'UNR_TOKEN':   { status: 'unreachable',   detail: 'ECONNRESET' },
      'MIS_TOKEN':   { status: 'misconfigured', detail: 'ssh_connection missing host field' },
      'FAIL_TOKEN':  { status: 'fail',          detail: 'unknown error' },
      'SKIP_TOKEN':  { status: 'skipped',       detail: 'no extractable credential' },
      'UNK_TOKEN':   null,  // 模拟没 healthcheck 数据
    });
    // ok → allowed
    const r1 = checkSecretForService('OK_TOKEN', lookup);
    ok('ok → allowed=true, status=ok',
       r1.allowed === true && r1.status === 'ok' && r1.detail === 'user=octocat');
    // expired → blocked
    const r2 = checkSecretForService('EXP_TOKEN', lookup);
    ok('expired → allowed=false, status=expired',
       r2.allowed === false && r2.status === 'expired' && r2.detail.includes('401'));
    // unreachable → blocked
    const r3 = checkSecretForService('UNR_TOKEN', lookup);
    ok('unreachable → allowed=false, status=unreachable',
       r3.allowed === false && r3.status === 'unreachable' && r3.detail.includes('ECONNRESET'));
    // misconfigured → blocked
    const r4 = checkSecretForService('MIS_TOKEN', lookup);
    ok('misconfigured → allowed=false, status=misconfigured',
       r4.allowed === false && r4.status === 'misconfigured' && r4.detail.includes('host'));
    // fail → blocked (兜底未知错)
    const r5 = checkSecretForService('FAIL_TOKEN', lookup);
    ok('fail → allowed=false, status=fail',
       r5.allowed === false && r5.status === 'fail');
    // skipped → allowed (service 可能不真用 secret)
    const r6 = checkSecretForService('SKIP_TOKEN', lookup);
    ok('skipped → allowed=true, status=skipped',
       r6.allowed === true && r6.status === 'skipped');
    // null (无 healthcheck 数据) → allowed, status=unknown
    const r7 = checkSecretForService('UNK_TOKEN', lookup);
    ok('no healthcheck data → allowed=true, status=unknown',
       r7.allowed === true && r7.status === 'unknown' && r7.detail.includes('no healthcheck'));
    // 没 token_secret → allowed, status=no_secret
    const r8 = checkSecretForService(null, lookup);
    ok('null token_secret → allowed=true, status=no_secret',
       r8.allowed === true && r8.status === 'no_secret');
    const r9 = checkSecretForService('', lookup);
    ok('empty token_secret → allowed=true, status=no_secret',
       r9.allowed === true && r9.status === 'no_secret');
  }

  // ======== 2. 5 min 缓存复用 ========
  section('5 min 缓存复用 (同 secret 第二次不重查)');
  {
    reset();
    let callCount = 0;
    const lookup = (name) => { callCount++; return { status: 'ok', detail: `call #${callCount}` }; };
    // 第一次 → 查
    const r1 = checkSecretForService('GITHUB_PAT', lookup);
    ok('第一次 → 查 (callCount=1)', callCount === 1 && r1.detail === 'call #1');
    // 第二次 (立即) → 缓存命中, 不查
    const r2 = checkSecretForService('GITHUB_PAT', lookup);
    ok('第二次 (立即) → 缓存命中 (callCount 仍 1)', callCount === 1);
    ok('第二次返同 result', r2.detail === r1.detail && r2.status === r1.status);
    // 第三次 (1ms 后) → 仍缓存命中
    await new Promise(r => setTimeout(r, 5));
    checkSecretForService('GITHUB_PAT', lookup);
    ok('第三次 (5ms 后) → 仍缓存命中 (callCount 仍 1)', callCount === 1);
  }

  // ======== 3. 缓存过期 (5 min 后重查) ========
  section('缓存过期 (TTL 边界)');
  {
    reset();
    let callCount = 0;
    const lookup = (name) => { callCount++; return { status: 'ok', detail: `call #${callCount}` }; };
    // 第一次查
    checkSecretForService('GITHUB_PAT', lookup);
    ok('初始 callCount=1', callCount === 1);
    // 注: 我们不能真等 5 min, 用 mock Date.now
    const origNow = Date.now;
    let mockedTime = origNow();
    Date.now = () => mockedTime;
    try {
      // 4 min 59s 后 → 仍缓存
      mockedTime += 4 * 60 * 1000 + 59 * 1000;
      checkSecretForService('GITHUB_PAT', lookup);
      ok('4 min 59s 后 → 仍缓存 (callCount 仍 1)', callCount === 1);
      // 5 min 1s 后 → 缓存过期, 重查
      mockedTime += 2 * 1000;
      const r = checkSecretForService('GITHUB_PAT', lookup);
      ok('5 min 1s 后 → 缓存过期重查 (callCount=2)', callCount === 2);
      ok('重查返新 result (call #2)', r.detail === 'call #2');
    } finally {
      Date.now = origNow;
    }
  }

  // ======== 4. clearSecretGuardCache ========
  section('clearSecretGuardCache');
  {
    reset();
    let callCount = 0;
    const lookup = (name) => { callCount++; return { status: 'ok' }; };
    checkSecretForService('S1', lookup);
    checkSecretForService('S2', lookup);
    ok('2 个 secret 都缓存 (callCount=2)', callCount === 2);
    checkSecretForService('S1', lookup);
    checkSecretForService('S2', lookup);
    ok('缓存命中 (callCount 仍 2)', callCount === 2);
    // 清单个 S1
    clearSecretGuardCache('S1');
    checkSecretForService('S1', lookup);
    checkSecretForService('S2', lookup);
    ok('清 S1 后 S1 重查 S2 仍缓存 (callCount=3)', callCount === 3);
    // 清全部
    clearSecretGuardCache();
    checkSecretForService('S1', lookup);
    checkSecretForService('S2', lookup);
    ok('清全部后两个都重查 (callCount=5)', callCount === 5);
  }

  // ======== 5. guardHint 4 种 status 提示 ========
  section('guardHint 4 种 status 提示');
  {
    ok('expired → "rotate the secret first"',
       guardHint('expired').includes('rotate'));
    ok('unreachable → "fix the upstream network/firewall"',
       guardHint('unreachable').includes('network'));
    ok('misconfigured → "fix the secret config"',
       guardHint('misconfigured').includes('config'));
    ok('fail → "check the secret status"',
       guardHint('fail').includes('check'));
    ok('未知 status → 兜底 "check"', guardHint('xyz').includes('check'));
  }

  // ======== 6. 注入失败兜底 (getSecretStatusFn 缺 / null / 非函数) ========
  section('注入失败兜底 (不阻断业务)');
  {
    reset();
    // 缺 getSecretStatusFn
    const r1 = checkSecretForService('GITHUB_PAT');
    ok('缺 getSecretStatusFn → allowed=true, status=no_check_fn',
       r1.allowed === true && r1.status === 'no_check_fn');
    // null
    const r2 = checkSecretForService('GITHUB_PAT', null);
    ok('getSecretStatusFn=null → allowed=true, status=no_check_fn',
       r2.allowed === true && r2.status === 'no_check_fn');
    // 非函数 (e.g. object)
    const r3 = checkSecretForService('GITHUB_PAT', { not: 'a function' });
    ok('getSecretStatusFn 非函数 → allowed=true, status=no_check_fn',
       r3.allowed === true && r3.status === 'no_check_fn');
  }

  // ======== 7. SECRET_GUARD_TTL_MS = 5 min ========
  section('strict fail-closed mode');
  {
    reset();
    ok('strict missing credential reference denied', checkSecretForService(null, () => null, { failClosed: true }).allowed === false);
    ok('strict missing checker denied', checkSecretForService('S', null, { failClosed: true }).allowed === false);
    ok('strict unknown health denied', checkSecretForService('UNKNOWN', () => null, { failClosed: true }).allowed === false);
    const fresh = new Date().toISOString();
    const freshResult = checkSecretForService('FRESH', () => ({ status: 'ok', detail: 'ok', ts: fresh }), { failClosed: true });
    ok('strict fresh healthy evidence allowed', freshResult.allowed === true && freshResult.status === 'ok');
    const old = new Date(Date.now() - 60_000).toISOString();
    const staleResult = checkSecretForService('STALE', () => ({ status: 'ok', detail: 'old', ts: old }), { failClosed: true, maxStatusAgeMs: 1000 });
    ok('strict stale health evidence denied', staleResult.allowed === false && staleResult.status === 'stale');
    ok('stale hint requests fresh check', guardHint('stale').includes('fresh'));
  }

  // ======== 7. SECRET_GUARD_TTL_MS = 5 min ========
  section('常量');
  {
    ok('SECRET_GUARD_TTL_MS = 5 * 60 * 1000 (5 min)', SECRET_GUARD_TTL_MS === 300000);
  }

  // ======== 8. 未来 status 兜底 (保守阻断) ========
  section('未知 status 兜底 (未来扩展)');
  {
    reset();
    const lookup = makeStatusLookup({ 'X': { status: 'mystatus', detail: 'future status' } });
    const r = checkSecretForService('X', lookup);
    ok('未知 status (mystatus) → allowed=false (保守阻断)', r.allowed === false);
    ok('保留原 status 和 detail', r.status === 'mystatus' && r.detail === 'future status');
  }

  console.log('\n========================================');
  console.log(`  test-proxy-guard: PASS=${pass} FAIL=${fail}`);
  console.log('========================================');
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});
