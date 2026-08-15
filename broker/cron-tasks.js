// broker/cron-tasks.js — v3.0 M4 broker 内置 cron
// 不依赖 systemd, broker 进程内注册定时任务
// 设计:
// - registerCron(schedule, fn): schedule 是 'HH:MM' (daily) 或 'day HH:MM' (weekly) 或 'HH:MM' + interval
// - 每分钟 check 一次 (1 minute granularity 足够日常自检)
// - broker 退出时 clear 掉所有 timer
//
// v3.0 注册 (M4.1 凭据自检):
// - '04:00' daily: healthcheck.runAll
// 后续可加:
// - '00:30' daily: secrets.cleanupExpired (M4.5)
// - 'monday 09:00' weekly: reports.weekly

const tasks = [];  // { id, schedule, fn, lastRun }
let tickInterval = null;

export function registerCron(schedule, fn) {
  const id = `cron-${tasks.length + 1}`;
  tasks.push({ id, schedule, fn, lastRun: null });
  return id;
}

export function listCron() {
  return tasks.map(t => ({ id: t.id, schedule: t.schedule, last_run: t.lastRun }));
}

function shouldRun(task, now) {
  // schedule format: 'HH:MM' daily OR 'day HH:MM' weekly (e.g. 'monday 09:00')
  const parts = task.schedule.trim().split(/\s+/);
  if (parts.length === 1) {
    // daily HH:MM
    const [hh, mm] = parts[0].split(':').map(Number);
    if (now.getHours() === hh && now.getMinutes() === mm) {
      // 防止重复: 同一分钟内只跑一次
      if (task.lastRun && new Date(task.lastRun).toDateString() === now.toDateString() &&
          new Date(task.lastRun).getHours() === hh && new Date(task.lastRun).getMinutes() === mm) {
        return false;
      }
      return true;
    }
  } else if (parts.length === 2) {
    // weekly 'day HH:MM'
    const dayName = parts[0].toLowerCase();
    const [hh, mm] = parts[1].split(':').map(Number);
    const dayMap = { sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6 };
    if (dayMap[dayName] === now.getDay() && now.getHours() === hh && now.getMinutes() === mm) {
      return !(task.lastRun && new Date(task.lastRun).toDateString() === now.toDateString() &&
                new Date(task.lastRun).getHours() === hh && new Date(task.lastRun).getMinutes() === mm);
    }
  }
  return false;
}

function tick() {
  const now = new Date();
  for (const task of tasks) {
    if (shouldRun(task, now)) {
      task.lastRun = now.toISOString();
      console.log(`[cron] ${task.id} firing (schedule=${task.schedule})`);
      Promise.resolve().then(() => task.fn()).catch(e => {
        console.error(`[cron] ${task.id} failed:`, e.message);
      });
    }
  }
}

export function startCronLoop() {
  if (tickInterval) return;  // already started
  // 每 60s check 一次
  tickInterval = setInterval(tick, 60_000);
  console.log(`[cron] started loop, ${tasks.length} task(s) registered`);
}

export function stopCronLoop() {
  if (tickInterval) {
    clearInterval(tickInterval);
    tickInterval = null;
    console.log('[cron] stopped');
  }
}

// 测试辅助: 强制 fire 一个 task (忽略 schedule)
export async function fireNow(id) {
  const task = tasks.find(t => t.id === id);
  if (!task) throw new Error(`task ${id} not found`);
  task.lastRun = new Date().toISOString();
  await task.fn();
}
