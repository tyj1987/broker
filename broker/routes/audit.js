// broker/routes/audit.js — V4.3.0 server.js extraction
// 把 server.js 中的内联 audit 模块抽成工厂函数。磁盘仍是 source of truth;
// ring 是 hot cache;持久写入使用带检查点的分段哈希链，不再允许 API 清空证据。
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
import { readFileSync } from 'node:fs';
import { createAuditLedger, auditLogFiles, AuditLedgerError } from '../lib/audit-ledger.js';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const RING_MAX = 1000;

/**
 * @param {object} deps
 * @param {string} deps.auditDir
 * @param {() => object} deps.getConfig
 * @param {(value: any) => any} deps.redact   redactDeep 实现
 */
export function createAuditRoutes({ auditDir, getConfig, redact, ledgerOptions = {} }) {
  const ledger = createAuditLedger(auditDir, ledgerOptions);

  const bus = new EventEmitter();
  bus.setMaxListeners(0);

  // V4.2.1: in-memory ring buffer for hot reads.
  const ring = [];

  function audit(event) {
    // Redact before sealing. Publish to the ring/SSE only after durable commit.
    // On write/checkpoint failure the caller receives AUDIT_UNAVAILABLE (503).
    const e = ledger.append(
      redact({
        ts: new Date().toISOString(),
        id: randomUUID(),
        ...event,
      }),
    );
    if (ring.length >= RING_MAX) ring.shift();
    ring.push(e);
    setImmediate(() => bus.emit('event', e));
    return e;
  }

  function readAuditFiltered({
    client,
    cn,
    service,
    action,
    status,
    since,
    until,
    limit = 100,
  } = {}) {
    const maxLimit = Math.min(Math.max(1, limit), 5000);
    const clientL = client ? String(client).toLowerCase() : null;
    const cnExact = cn ? String(cn).toLowerCase() : null;
    const svcL = service ? String(service).toLowerCase() : null;
    const actL = action ? String(action).toLowerCase() : null;
    const stL = status ? String(status).toLowerCase() : null;
    // Only unfiltered reads fully covered by the ring may avoid disk. Filtered
    // reads could require older matching records even when the ring is full.
    const ringHasRange =
      ring.length > 0 &&
      !svcL &&
      !clientL &&
      !cnExact &&
      !actL &&
      !stL &&
      !until &&
      !since &&
      maxLimit <= ring.length;
    if (ringHasRange) {
      const out = [];
      for (let i = ring.length - 1; i >= 0 && out.length < maxLimit; i--) {
        const e = ring[i];
        if (clientL) {
          const eventCn = String(e.cn || '').toLowerCase();
          const eventClient = String(e.client || '').toLowerCase();
          if (!eventCn.includes(clientL) && !eventClient.includes(clientL)) continue;
        }
        if (cnExact && String(e.cn || '').toLowerCase() !== cnExact) continue;
        if (actL && !(e.action || '').toLowerCase().includes(actL)) continue;
        if (stL && !(e.status || '').toLowerCase().includes(stL)) continue;
        out.push(e);
      }
      return out;
    }
    // 冷读:扫描磁盘
    const files = auditLogFiles(auditDir).reverse();
    const out = [];
    for (const f of files) {
      if (out.length >= maxLimit) break;
      const content = readFileSync(join(auditDir, f), 'utf8');
      for (const line of content.split('\n').reverse()) {
        if (!line) continue;
        let e;
        try {
          e = JSON.parse(line);
        } catch {
          continue;
        }
        if (since && e.ts < since) continue;
        if (until && e.ts > until) continue;
        if (clientL) {
          const eventCn = String(e.cn || '').toLowerCase();
          const eventClient = String(e.client || '').toLowerCase();
          if (!eventCn.includes(clientL) && !eventClient.includes(clientL)) continue;
        }
        if (cnExact && String(e.cn || '').toLowerCase() !== cnExact) continue;
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
      'login',
      'logout',
      'proxy',
      'resolve',
      'connect',
      'healthcheck',
      'admin_secrets_create',
      'admin_services_create',
      'admin_clients_create',
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
    const error = new AuditLedgerError(
      'Audit evidence cannot be cleared through the API; use verified retention/export',
    );
    error.statusCode = 409;
    error.code = 'AUDIT_CLEAR_DISABLED';
    throw error;
  }

  function health() {
    return {
      ring_buffer_size: ring.length,
      ring_buffer_max: RING_MAX,
      audit_dir: auditDir,
      ledger: ledger.health(),
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
