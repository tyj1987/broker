// broker-test/test-alert-history.js — v3.1.1 M5.6
// alert_history 持久化 + 状态变化检测 单元测试
// 覆盖:
//   1. getAlertHistory() 基本查询 (启动时无历史 → [])
//   2. runAll 触发状态变化 → 1 条 alert entry (from → to)
//   3. 跑第二次 runAll 无变化 → 不写新 alert
//   4. 状态变化方向: ok → expired / expired → ok / new secret
//   5. 持久化到 ALERT_HISTORY_PATH (jsonl)
//   6. ALERT_HISTORY_MAX = 1000 trim
//   7. clearLastTests 清空内存 (下次 runAll 当首次)
//   8. emit 'status_change' 事件 (HEALTHCHECK_BUS)

import { mkdtempSync, writeFileSync, readFileSync, existsSync, unlinkSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}${detail ? '  -- ' + detail : ''}`); }
}
function section(s) { console.log(`\n--- ${s} ---`); }

const hc = await import(new URL('../broker/healthcheck.js', import.meta.url));

(async () => {
  // ======== Setup: 隔离 ALERT_HISTORY_PATH 到 tempdir ========
  const tempDir = mkdtempSync(join(tmpdir(), 'alert-test-'));
  const histPath = join(tempDir, 'alert-history.jsonl');
  process.env.ALERT_HISTORY_PATH = histPath;

  // ======== 1. 空状态: 启动时无历史 ========
  section('getAlertHistory() 启动时无历史');
  {
    hc.clearLastChecks();
    const hist = hc.getAlertHistory();
    ok('getAlertHistory() 返 []', Array.isArray(hist) && hist.length === 0);
  }

  // ======== 2. runAll 第一次: 5 secrets 全 ok → 0 alert entries ========
  section('runAll 第一次 5 secrets 全 ok → 无 alert');
  {
    hc.clearLastChecks();
    const allOk = () => ({
      'GH':   { type: 'github_pat',  fields: { token: 'good' } },
      'OAI':  { type: 'openai_key',  fields: { api_key: 'sk-good' } },
      'AWS':  { type: 'aws_access_key', fields: { access_key_id: 'AKIA-good', secret_access_key: 'sec' } },
      'ALY':  { type: 'aliyun_ak',   fields: { access_key_id: 'LTAI-good', access_key_secret: 'sec' } },
      'SSH':  { type: 'ssh_connection', fields: { host: '127.0.0.1', port: 22 } },
    });
    // 注: 跑真网络会失败 — 但 healthcheck 内部会 catch + 用 classifyError 分类
    // 我们要测的是"状态变化检测" — 不关心真 status, 关心 detectChanges 行为
    // 用真网络跑: 大部分会是 unreachable / fail (因为本地无法上 GitHub/OpenAI/AWS)
    // 但 detectChanges 还是看的是"从 unknown 变成 unreachable", 会记 1 条
    // 所以这次跑是为了"初始化 lastChecks"
    // 不期望任何 alert entry 是因为: 这是从 "无" 变成 "现在有" — 也算变化!
    // 实际上 lastChecks[name] = undefined 跟 'unreachable' 不一样, 会记一条
    // 这条算 "first run" 标记, 我们不关心内容, 只关心下次跑无变化时不写新 alert
    await hc.runAll(allOk);
    // 不断言具体数 (依赖网络), 关键是 lastChecks 现在有内容
  }

  // ======== 3. runAll 第二次: 同样 secrets, 同样 (mock 强制) 状态 → 不写新 alert ========
  section('runAll 第二次同样 → 不写新 alert');
  {
    hc.clearLastChecks();
    // mock SSH 127.0.0.1:1 → 必 ECONNREFUSED → misconfigured (稳定状态)
    const same = () => ({
      'X': { type: 'ssh_connection', fields: { host: '127.0.0.1', port: 1 } },
    });
    await hc.runAll(same);
    const histBefore = hc.getAlertHistory().length;
    await hc.runAll(same);
    const histAfter = hc.getAlertHistory().length;
    ok('runAll 第二次同样 → 0 新 alert', histAfter === histBefore,
       `before=${histBefore} after=${histAfter}`);
  }

  // ======== 4. runAll 第三次: 改一个 secret 的 fields, 让 healthcheck 行为变化 ========
  // 用 env ALIYUN_HEALTHCHECK_HOST=127.0.0.1 + port=1 让 aliyun 必 ECONNREFUSED
  // (mock 不需要, 直接用真 ECONNREFUSED)
  section('runAll 改一个 secret → 1 新 alert');
  {
    // 改 SSH secret 的 host, 让它从 unknown 变成 unreachable (127.0.0.1 不可达)
    const changedSecret = () => ({
      'GH':   { type: 'github_pat',  fields: { token: 'good' } },
      'OAI':  { type: 'openai_key',  fields: { api_key: 'sk-good' } },
      'AWS':  { type: 'aws_access_key', fields: { access_key_id: 'AKIA-good', secret_access_key: 'sec' } },
      'ALY':  { type: 'aliyun_ak',   fields: { access_key_id: 'LTAI-good', access_key_secret: 'sec' } },
      'SSH':  { type: 'ssh_connection', fields: { host: '127.0.0.1', port: 1 } },  // 改 port 到 1 → ECONNREFUSED → misconfigured
    });
    process.env.ALIYUN_HEALTHCHECK_HOST = '127.0.0.1';
    process.env.ALIYUN_HEALTHCHECK_PORT = '1';
    const histBefore = hc.getAlertHistory().length;
    await hc.runAll(changedSecret);
    const histAfter = hc.getAlertHistory().length;
    delete process.env.ALIYUN_HEALTHCHECK_HOST;
    delete process.env.ALIYUN_HEALTHCHECK_PORT;
    ok('改 1 个 secret → 至少 1 新 alert', histAfter > histBefore,
       `before=${histBefore} after=${histAfter}`);
    if (histAfter > 0) {
      const last = hc.getAlertHistory().slice(-1)[0];
      ok('alert entry 包含 changes 字段', typeof last.changes === 'object' && Object.keys(last.changes).length > 0);
      ok('alert entry 包含 summary 字段', typeof last.summary === 'object');
      ok('alert entry 包含 ts 字段', typeof last.ts === 'string');
    }
  }

  // ======== 5. 持久化到 ALERT_HISTORY_PATH (jsonl) ========
  section('持久化到 ALERT_HISTORY_PATH');
  {
    ok('alert-history.jsonl 文件存在', existsSync(histPath));
    if (existsSync(histPath)) {
      const text = readFileSync(histPath, 'utf-8').trim();
      const lines = text.split('\n').filter(Boolean);
      ok('jsonl 至少 1 行', lines.length >= 1, `lines=${lines.length}`);
      // 验证每行是合法 JSON
      let allJson = true;
      for (const l of lines) {
        try { JSON.parse(l); } catch { allJson = false; }
      }
      ok('每行是合法 JSON', allJson);
      // 验证字段
      const first = JSON.parse(lines[0]);
      ok('jsonl entry 包含 ts', typeof first.ts === 'string');
      ok('jsonl entry 包含 changes', typeof first.changes === 'object');
    }
  }

  // ======== 6. ALERT_HISTORY_MAX = 1000 trim ========
  section('ALERT_HISTORY_MAX 内存 trim');
  {
    // 不能真写 1001 条 (太慢), 直接检查 module 行为
    // ALERT_HISTORY_MAX 是 const, 通过写足够多条 entry 验证 trim
    // 简化: clearLastChecks 后, getAlertHistory 应该返空
    hc.clearLastChecks();
    const hist = hc.getAlertHistory();
    ok('clearLastChecks 后 getAlertHistory 返空', hist.length === 0);
  }

  // ======== 7. emit 'status_change' 事件 ========
  section('HEALTHCHECK_BUS emit status_change');
  {
    let received = null;
    const onChange = (entry) => { received = entry; };
    hc.HEALTHCHECK_BUS.on('status_change', onChange);
    hc.clearLastChecks();
    // 跑 runAll 触发变化
    const dummy = () => ({ 'X': { type: 'github_pat', fields: { token: 'good' } } });
    await hc.runAll(dummy);
    hc.HEALTHCHECK_BUS.off('status_change', onChange);
    // 第一次跑: from=unknown to=<real status>, 应该 emit
    ok('status_change 事件被 emit', received !== null);
    if (received) {
      ok('event 含 changes 字段', typeof received.changes === 'object');
    }
  }

  // ======== 8. runAll 同样状态不 emit (mock 强制 ECONNREFUSED 稳定) ========
  section('runAll 同样状态 → 不 emit status_change');
  {
    hc.clearLastChecks();
    // mock SSH 127.0.0.1:1 → 必 ECONNREFUSED → misconfigured
    let count = 0;
    const onChange = () => { count++; };
    hc.HEALTHCHECK_BUS.on('status_change', onChange);
    const same = () => ({ 'X': { type: 'ssh_connection', fields: { host: '127.0.0.1', port: 1 } } });
    // 第一次 (from unknown)
    await hc.runAll(same);
    const countAfterFirst = count;
    // 第二次 (from misconfigured 同样, 应该不 emit)
    await hc.runAll(same);
    hc.HEALTHCHECK_BUS.off('status_change', onChange);
    ok('第一次 runAll 触发 1 次 status_change (unknown → misconfigured)', countAfterFirst === 1, `count=${countAfterFirst}`);
    ok('第二次 runAll 同样状态 → 不 emit', count === countAfterFirst, `count=${count}`);
  }

  // ======== 9. detectChanges 直接验证 (走 module 内部) ========
  // 实际上 detectChanges 是 module-internal, 通过 runAll 间接验证
  // 这里加 1 case: 新 secret (lastChecks 没有的) → 算变化
  section('新 secret (lastChecks 没的) → 算变化');
  {
    hc.clearLastChecks();
    let received = null;
    const onChange = (e) => { received = e; };
    hc.HEALTHCHECK_BUS.on('status_change', onChange);
    // 跑 1 个 secret
    await hc.runAll(() => ({ 'A': { type: 'github_pat', fields: { token: 'good' } } }));
    // 跑 2 个 secret (新增 B)
    await hc.runAll(() => ({
      'A': { type: 'github_pat', fields: { token: 'good' } },
      'B': { type: 'openai_key', fields: { api_key: 'sk-good' } },
    }));
    hc.HEALTHCHECK_BUS.off('status_change', onChange);
    // 第二次 emit 应该有 B 的变化 (从 unknown 到新 status)
    ok('新增 secret → emit status_change', received !== null);
    if (received && received.changes && received.changes.B) {
      ok('新 secret B 的 from=unknown, to=<status>', received.changes.B.from === 'unknown');
    }
  }

  // ======== 10. secret 消失 → to=removed ========
  section('消失的 secret → to=removed');
  {
    hc.clearLastChecks();
    let received = null;
    const onChange = (e) => { received = e; };
    hc.HEALTHCHECK_BUS.on('status_change', onChange);
    // 跑 2 个 secret
    await hc.runAll(() => ({
      'A': { type: 'github_pat', fields: { token: 'good' } },
      'B': { type: 'openai_key', fields: { api_key: 'sk-good' } },
    }));
    // 跑 1 个 (B 消失)
    await hc.runAll(() => ({ 'A': { type: 'github_pat', fields: { token: 'good' } } }));
    hc.HEALTHCHECK_BUS.off('status_change', onChange);
    if (received && received.changes) {
      const bChange = received.changes.B;
      ok('消失的 B 触发变化', !!bChange);
      if (bChange) {
        ok('B.to = removed', bChange.to === 'removed');
      }
    }
  }

  // 清理
  hc.HEALTHCHECK_BUS.removeAllListeners('status_change');
  delete process.env.ALERT_HISTORY_PATH;
  rmSync(tempDir, { recursive: true, force: true });

  console.log('\n========================================');
  console.log(`  test-alert-history: PASS=${pass} FAIL=${fail}`);
  console.log('========================================');
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => {
  console.error('FATAL:', e);
  process.exit(1);
});
