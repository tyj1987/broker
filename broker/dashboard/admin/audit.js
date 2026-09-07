// admin/audit.js — Phase 1.4: Audit enhancements
// - filtered list (client/service/action/status/since/until/limit)
// - SSE real-time stream (auto-append new events to table)
// - JSON / CSV export
// - Anomaly highlighting: 5+ denied in a row from same cn, or unknown action
//   All admin-only; non-admin falls back to /api/v1/audit (limited view).

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentIdentity = null;
  let isAdmin = false;
  let events = [];   // newest first
  let sseSource = null;
  // Anomaly tracking: cn -> consecutive denied count (rolling).
  const deniedByCn = new Map();

  // ---- Bootstrap ----
  function init() {
    const subscribe = typeof subscribeBrokerIdentity === 'function'
      ? subscribeBrokerIdentity
      : (handler) => document.addEventListener('broker:identity', (e) => handler(e.detail));
    subscribe((ident) => {
      currentIdentity = ident;
      isAdmin = !!(ident && ident.role === 'admin');
      if (isAdmin) {
        ensureSse();
        loadFacets().then(loadAudit);
      } else {
        teardownSse();
      }
    });
    wireButtons();
  }

  function fillSelect(sel, values, current) {
    if (!sel) return;
    const keep = current != null ? current : sel.value;
    sel.innerHTML = '<option value="">全部 / All</option>';
    for (const v of values || []) {
      const opt = document.createElement('option');
      opt.value = v;
      opt.textContent = v;
      sel.appendChild(opt);
    }
    if (keep && [...sel.options].some(o => o.value === keep)) sel.value = keep;
  }

  async function loadFacets() {
    if (!isAdmin) return;
    try {
      const f = await api('/api/v1/admin/audit/facets');
      fillSelect($('#af-client'), f.clients);
      fillSelect($('#af-service'), f.services);
      fillSelect($('#af-action'), f.actions);
      fillSelect($('#af-status'), f.statuses);
    } catch (e) {
      console.warn('audit facets failed', e);
    }
  }

  // ---- Filters ----
  function readFilters() {
    const dt = (s) => s ? new Date(s).toISOString() : null;
    return {
      client:  $('#af-client')?.value.trim() || '',
      service: $('#af-service')?.value.trim() || '',
      action:  $('#af-action')?.value.trim() || '',
      status:  $('#af-status')?.value.trim() || '',
      since:   dt($('#af-since')?.value),
      until:   dt($('#af-until')?.value),
      limit:   parseInt($('#af-limit')?.value || '200', 10),
    };
  }
  function filtersToQuery(f) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
    return p.toString();
  }

  // ---- API ----
  async function loadAudit() {
    const url = isAdmin
      ? `/api/v1/admin/audit?${filtersToQuery(readFilters())}`
      : `/api/v1/audit?limit=200`;
    try {
      const r = await api(url);
      events = r.events || [];
      renderTable();
    } catch (e) {
      console.error('loadAudit failed:', e);
    }
  }
  function buildExportUrl(fmt) {
    return `/api/v1/admin/audit/export.${fmt}?${filtersToQuery(readFilters())}`;
  }

  // ---- SSE ----
  function ensureSse() {
    if (sseSource) return;
    if (typeof EventSource === 'undefined') {
      // Browser too old
      const el = $('#audit-stream-status');
      if (el) el.textContent = '⚠ 浏览器不支持 SSE';
      return;
    }
    try {
      sseSource = new EventSource('/api/v1/admin/audit/stream', { withCredentials: true });
      sseSource.addEventListener('ready', () => {
        const el = $('#audit-stream-status');
        if (el) el.textContent = '🟢 实时流已连接';
      });
      sseSource.addEventListener('audit', (e) => {
        try {
          const ev = JSON.parse(e.data);
          prependEvent(ev);
        } catch {}
      });
      sseSource.onerror = () => {
        const el = $('#audit-stream-status');
        if (el) el.textContent = '🔴 实时流断开 (刷新页面重连)';
      };
    } catch (e) {
      console.error('SSE open failed:', e);
    }
  }
  function teardownSse() {
    if (sseSource) {
      try { sseSource.close(); } catch {}
      sseSource = null;
    }
    const el = $('#audit-stream-status');
    if (el) el.textContent = '⚪ 未连接';
  }

  function prependEvent(ev) {
    // Apply current filters client-side too: the SSE stream is unfiltered
    // (server emits all events). Cheap check on the same fields.
    const f = readFilters();
    if (f.client  && !(ev.cn  || '').toLowerCase().includes(f.client.toLowerCase()))  return;
    if (f.service && !(ev.service || '').toLowerCase().includes(f.service.toLowerCase())) return;
    if (f.action  && !(ev.action  || '').toLowerCase().includes(f.action.toLowerCase()))  return;
    if (f.status  && !(ev.status  || '').toLowerCase().includes(f.status.toLowerCase()))  return;
    if (f.since && ev.ts < f.since) return;
    if (f.until && ev.ts > f.until) return;
    events.unshift(ev);
    if (events.length > f.limit) events.length = f.limit;
    renderTable();
  }

  // ---- Render ----
  function renderTable() {
    const tbody = $('#audit-table tbody');
    if (!tbody) return;
    const countEl = $('#audit-count');
    if (countEl) countEl.textContent = `${events.length} 条 / events`;
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">（无审计事件）</td></tr>';
      return;
    }
    // Update denied counts for anomaly detection
    updateAnomalyTracker();
    const anomalies = computeAnomalies();
    tbody.innerHTML = '';
    for (const e of events) {
      const tr = document.createElement('tr');
      const target = targetFor(e);
      const latency = e.latency_ms != null ? `${e.latency_ms}ms` : '';
      const status = e.status || '';
      const statusClass = statusClassFor(status);
      const anomaly = anomalies.has(e.id) ? anomalies.get(e.id) : null;
      const isAnomaly = anomaly != null;
      tr.innerHTML = `
        <td class="muted-cell" title="${esc(e.id || '')}">${esc(formatTime(e.ts))}</td>
        <td>${esc(e.cn || '')}</td>
        <td><code>${esc(e.action || '')}</code></td>
        <td>${esc(target)}</td>
        <td class="${statusClass}">${esc(status)}</td>
        <td class="muted-cell">${esc(latency)}</td>
        <td>${isAnomaly ? `<span class="badge-warn" title="${esc(anomaly)}">${esc(anomaly)}</span>` : ''}</td>
      `;
      if (isAnomaly) tr.classList.add('row-anomaly');
      tbody.appendChild(tr);
    }
  }

  function targetFor(e) {
    if (e.service) return `${e.method || ''} ${e.service}${e.path || ''}`.trim();
    if (e.name)   return e.name + (e.field ? '.' + e.field : '');
    if (e.action === 'login') return e.client || '?';
    if (e.action === 'reload') return 'broker.yaml';
    return e.reason || '';
  }
  function statusClassFor(s) {
    if (s === 'ok')     return 'status-ok';
    if (s === 'error' || s === 'denied') return 'status-error';
    if (s === 'not_found') return 'status-denied';
    return 'muted-cell';
  }
  function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ---- Anomaly detection ----
  // Tracks: 5+ consecutive denied/error from same cn in last 50 events.
  function updateAnomalyTracker() {
    deniedByCn.clear();
    for (const e of events.slice(0, 50)) {
      if (e.status === 'error' || e.status === 'denied') {
        const cn = e.cn || '?';
        deniedByCn.set(cn, (deniedByCn.get(cn) || 0) + 1);
      }
    }
  }
  function computeAnomalies() {
    const out = new Map();  // event.id -> reason
    if (events.length === 0) return out;
    // 1) 5+ consecutive denied from same cn (from newest backwards)
    let runCn = events[0].cn;
    let runCount = 0;
    for (const e of events) {
      if (e.cn !== runCn) { runCn = e.cn; runCount = 0; }
      if (e.status === 'error' || e.status === 'denied') {
        runCount++;
        if (runCount >= 5) {
          out.set(e.id, `5+ 连续失败 / ${e.cn}`);
        }
      } else runCount = 0;
    }
    // 2) 5+ total denied from same cn in last 50 (high-failure client)
    for (const [cn, count] of deniedByCn.entries()) {
      if (count >= 5) {
        // Mark ALL events of this cn in the last 50
        for (const e of events.slice(0, 50)) {
          if (e.cn === cn && (e.status === 'error' || e.status === 'denied') && !out.has(e.id)) {
            out.set(e.id, `${cn} 高失败率 / ${count} 次/50`);
          }
        }
      }
    }
    // 3) Off-hours access (00:00-06:00 local server time)
    for (const e of events) {
      if (!e.id) continue;
      const h = new Date(e.ts).getUTCHours();
      if (h >= 0 && h < 6 && !out.has(e.id)) {
        out.set(e.id, '深夜访问 / night');
      }
    }
    return out;
  }

  // ---- Wire ----
  function wireButtons() {
    const apply = $('#btn-audit-apply');
    if (apply) apply.addEventListener('click', loadAudit);
    const reset = $('#btn-audit-reset');
    if (reset) reset.addEventListener('click', () => {
      ['af-client','af-service','af-action','af-status','af-since','af-until'].forEach(id => {
        const el = $('#' + id); if (el) el.value = '';
      });
      loadAudit();
    });
    const refresh = $('#btn-audit-refresh');
    if (refresh) refresh.addEventListener('click', loadAudit);
    const exj = $('#btn-audit-export-json');
    if (exj) exj.addEventListener('click', () => downloadExport('json'));
    const exc = $('#btn-audit-export-csv');
    if (exc) exc.addEventListener('click', () => downloadExport('csv'));
    const clearBtn = $('#btn-audit-clear');
    if (clearBtn) clearBtn.addEventListener('click', clearAuditLogs);
  }

  async function clearAuditLogs() {
    if (!isAdmin) return;
    if (!confirm('确定清除全部审计日志？此操作不可恢复。\nClear ALL audit logs? This cannot be undone.')) return;
    try {
      await api('/api/v1/admin/audit', { method: 'DELETE', body: { confirm: true } });
      events = [];
      renderTable();
      await loadFacets();
      await loadAudit();
    } catch (e) {
      alert('清除失败 / Clear failed: ' + e.message);
    }
  }

  function downloadExport(fmt) {
    const url = buildExportUrl(fmt);
    // Need to include admin session cookie. Simplest: use fetch → blob.
    fetch(url, { credentials: 'include' })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `audit.${fmt}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
      })
      .catch(e => alert('导出失败 / Export failed: ' + e.message));
  }

  // Override default loadAudit from app.js for admin users (which gives
  // them filters + SSE). The window.loadAudit below is the override; if
  // it returns nothing for non-admin, app.js's default still runs.
  // Strategy: monkey-patch the button so it always calls ours.
  document.addEventListener('DOMContentLoaded', () => {
    const btn = $('#btn-audit-refresh') || $('#btn-refresh-audit');
    if (btn) btn.addEventListener('click', loadAudit);
    // Also auto-refresh on tab change
    document.addEventListener('tabchange', (e) => {
      if (e.detail?.tab === 'audit') {
        if (isAdmin) loadFacets();
        loadAudit();
      }
    });
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
