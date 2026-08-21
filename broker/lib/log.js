// broker/lib/log.js — structured JSON logs to stdout (no deps)
// Phase C. Levels: debug | info | warn | error

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function currentLevel() {
  const n = (process.env.BROKER_LOG_LEVEL || 'info').toLowerCase();
  return LEVELS[n] ?? LEVELS.info;
}

function emit(level, msg, fields = {}) {
  if ((LEVELS[level] ?? 99) < currentLevel()) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  });
  if (level === 'error') console.error(line);
  else console.log(line);
}

export const log = {
  debug: (msg, fields) => emit('debug', msg, fields),
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};

export default log;
