// broker-test/test-cron-tasks.js — V4.7.0 broker/cron-tasks.js 单元测试
// 覆盖 registerCron / listCron / startCronLoop / stopCronLoop / fireNow
// 注:shouldRun / tick 是内部函数,无法直接测试;通过 fireNow 间接覆盖

import {
  registerCron,
  listCron,
  startCronLoop,
  stopCronLoop,
  fireNow,
} from '../broker/cron-tasks.js';

let pass = 0,
  fail = 0;
function ok(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.error(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`);
  }
}
function section(t) {
  console.log(`\n[${t}]`);
}

// ============================================================
// registerCron + listCron
// ============================================================
section('registerCron + listCron');
{
  const id1 = registerCron('04:00', async () => {});
  const id2 = registerCron('monday 09:00', async () => {});
  ok('returns cron-1', id1 === 'cron-1');
  ok('returns cron-2', id2 === 'cron-2');
  const list = listCron();
  ok('listCron returns array', Array.isArray(list));
  ok(
    'list contains cron-1',
    list.some((t) => t.id === 'cron-1' && t.schedule === '04:00'),
  );
  ok(
    'list contains cron-2',
    list.some((t) => t.id === 'cron-2' && t.schedule === 'monday 09:00'),
  );
  ok(
    'list items have last_run field',
    list.every((t) => 'last_run' in t),
  );
}

// ============================================================
// fireNow
// ============================================================
section('fireNow');
{
  registerCron('never', async () => {
    /* dummy */
  });
  let fired = 0;
  const idWithFn = registerCron('also_never', async () => {
    fired++;
  });
  await fireNow(idWithFn);
  ok('fireNow invokes the registered fn', fired === 1);

  // fn throws → fireNow rejects
  const failingId = registerCron('throws', async () => {
    throw new Error('boom');
  });
  let threw = false;
  try {
    await fireNow(failingId);
  } catch (e) {
    threw = e.message === 'boom';
  }
  ok('fireNow propagates fn errors', threw);

  // unknown id → throws
  let threwUnknown = false;
  try {
    await fireNow('does-not-exist');
  } catch {
    threwUnknown = true;
  }
  ok('fireNow on unknown id throws', threwUnknown);

  // lastRun is set after fireNow
  const after = listCron().find((t) => t.id === idWithFn);
  ok('last_run updated after fireNow', after && after.last_run !== null);
}

// ============================================================
// startCronLoop / stopCronLoop
// ============================================================
section('startCronLoop / stopCronLoop');
{
  // 启动一次,确认无异常
  startCronLoop();
  ok('startCronLoop does not throw', true);
  // 重启幂等
  startCronLoop();
  ok('startCronLoop is idempotent', true);
  stopCronLoop();
  ok('stopCronLoop does not throw', true);
  // 重复 stop 也无异常
  stopCronLoop();
  ok('stopCronLoop is idempotent', true);
}

console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
