// broker/routes/audit.js — V4.3.0 server.js extraction
// 把 server.js 中的内联 audit 模块抽成工厂函数。磁盘仍是 source of truth;
// ring 是 hot cache;行为完全等价于 v4.2.1 的 server.js 内联实现。
//
// 注入:
//   - auditDir: 磁盘 JSONL 路径(默认 /audit)
//   - getConfig: () => CONFIG(用于 collectAuditFacets 取 clients/services)
//   - redact: redactDeep 函数(注入避免本文件依赖 lib/redact.js 路径)
//
// 返回:
//   - audit(event): 写一条审计,推 ring,emit bus
//   - readAuditFiltered / readAudit: 过滤读取(ring 优先,落盘为兜底)
//   - collectAuditFacets: 客户端 / 服务 / 动作 / 状态 集合
//   - clearAuditLogs: 物理清理磁盘 JSONL
//   - bus: EventEmitter,SSE 端点订阅
//   - health: 内部状态(便于 dashboard 显示)

import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const RING_MAX = 1000;
const ROTATE_BYTES = 50 * 1024 * 1024;  // 50MB

/**
 * @param {object} deps
 * @param {string} deps.auditDir
 * @param {() => object} deps.getConfig
 * @param {(value: any) => any} deps.redact   redactDeep 实现
 */
export function createAuditRoutes({ auditDir, getConfig, redact }) {
  if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });

  const bus = new EventEmitter();
  bus.setMaxListeners(0);

  // V4.2.1: in-memory ring buffer for hot reads.
  const ring = [];
  let bytes = 0;

  function filePath() {
    const d = new Date().toISOString().slice(0, 10);
    return join(auditDir, `audit-${d}.jsonl`);
  }

  function audit(event) {
    const e = redact({
      ts: new Date().toISOString(),
      id: randomUUID(),
      ...event,
    });
    const line = JSON.stringify(e) + '\n';
    try {
      appendFileSync(filePath(), line, { encoding: 'utf8' });
      bytes += Buffer.byteLength(line, 'utf8');
      if (bytes > ROTATE_BYTES) {
        const old = filePath();
        const rotated = old + '.1';
        if (existsSync(rotated)) unlinkSync(rotated);
        renameSync(old, rotated);
        bytes = 0;
      }
    } catch (err) {
      console.error('[audit] write failed:', err.message);
    }
    if (ring.length >= RING_MAX) ring.shift();
    ring.push(e);
    setImmediate(() => bus.emit('event', e));
    return e;
  }

  function readAuditFiltered({ client, service, action, status, since, until, limit = 100 } = {}) {
    const maxLimit = Math.min(Math.max(1, limit), 5000);
    const cnL = client ? String(client).toLowerCase() : null;
    const svcL = service ? String(service).toLowerCase() : null;
    const actL = action ? String(action).toLowerCase() : null;
    const stL = status ? String(status).toLowerCase() : null;
    // 热读:无 service / until,since 为空或 ≥ ring 起点,limit ≤ ring 容量
    const ringHasRange = ring.length > 0
      && !svcL
      && !until
      && (!since || since <= ring[0].ts)
      && maxLimit <= ring.length;
    if (ringHasRange) {
      const out = [];
      for (let i = ring.length - 1; i >= 0 && out.length < maxLimit; i--) {
        const e = ring[i];
        if (cnL && !(e.cn || '').toLowerCase().includes(cnL)) continue;
        if (actL && !(e.action || '').toLowerCase().includes(actL)) continue;
        if (stL && !(e.status || '').toLowerCase().includes(stL)) continue;
        out.push(e);
      }
      return out;
    }
    // 冷读:扫描磁盘
    const files = readdirSync(auditDir)
      .filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    const out = [];
    for (const f of files) {
      if (out.length >= maxLimit) break;
      const content = readFileSync(join(auditDir, f), 'utf8');
      for (const line of content.split('\n').reverse()) {
        if (!line) continue;
        let e;
        try { e = JSON.parse(line); } catch { continue; }
        if (since && e.ts < since) continue;
        if (until && e.ts > until) continue;
        if (cnL && !(e.cn || '').toLowerCase().includes(cnL)) continue;
        if (svcL && !(e.service || '').toLowerCase().includes(svcL)) continue;
        if (actL && !(e.action || '').toLowerCase().includes(actL)) continue;
        if (stL && !(e.status || '').toLowerCase().includes(stL)) continue;
        out.push(e);
        if (out.length >= maxLimit) break;
      }
    }
    return out;
  }

  function readAudit({ since, limit = 100 } = {}) {
    return readAuditFiltered({ since, limit });
  }

  function collectAuditFacets() {
    const cfg = getConfig() || {};
    const clients = new Set(Object.keys(cfg.clients || {}));
    const services = new Set(Object.keys(cfg.services || {}));
    const actions = new Set([
      'login', 'logout', 'proxy', 'resolve', 'connect', 'healthcheck',
      'admin_secrets_create', 'admin_services_create', 'admin_clients_create',
      'audit_cleared',
    ]);
    const statuses = new Set(['ok', 'error', 'denied', 'not_found', 'mfa_required']);
    for (const e of readAuditFiltered({ limit: 2000 })) {
      if (e.cn) clients.add(e.cn);
      if (e.client) clients.add(e.client);
      if (e.service) services.add(e.service);
      if (e.action) actions.add(e.action);
      if (e.status) statuses.add(e.status);
    }
    const sort = (s) => [...s].filter(Boolean).sort((a, b) => String(a).localeCompare(String(b)));
    return {
      clients: sort(clients),
      services: sort(services),
      actions: sort(actions),
      statuses: sort(statuses),
    };
  }

  function clearAuditLogs() {
    const deleted = [];
    if (!existsSync(auditDir)) return deleted;
    for (const f of readdirSync(auditDir)) {
      if (!f.startsWith('audit-')) continue;
      if (!(f.endsWith('.jsonl') || f.endsWith('.jsonl.1'))) continue;
      try {
        unlinkSync(join(auditDir, f));
        deleted.push(f);
      } catch { /* keep going */ }
    }
    return deleted;
  }

  function health() {
    return {
      ring_buffer_size: ring.length,
      ring_buffer_max: RING_MAX,
      audit_dir: auditDir,
    };
  }

  return {
    audit,
    readAudit,
    readAuditFiltered,
    collectAuditFacets,
    clearAuditLogs,
    bus,
    health,
  };
}
