// home.js — Phase 2.1: home dashboard
// - 4 stat cards (services / secrets / clients / today's audit events)
// - quick action grid (max 6 from any of: services quick actions, common tasks)
// - recent activity (last 5 audit events)
// - admin TODO list (rotation reminders, anomaly count, stale clients, etc.)
//
// Strategy: fetch in parallel, populate incrementally. Keep DOM updates tiny —
// this is the first thing a user sees on login so it should feel snappy.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  let isAdmin = false;
  let currentIdentity = null;

  // ---- Init ----
  function init() {
    // Watch for identity so we know whether to show admin TODO
    const id = setInterval(() => {
      const text = ($('#identity')?.textContent || '').trim();
      if (text && text !== currentIdentity) {
        currentIdentity = text;
        isAdmin = /role=admin/.test(text);
        applyAdminVisibility();
        loadAll();
      }
    }, 500);
    setTimeout(() => clearInterval(id), 30000);
    wireButtons();
    setGreet();
  }

  function applyAdminVisibility() {
    document.querySelectorAll('.admin-only').forEach(el => { el.hidden = !isAdmin; });
  }

  function setGreet() {
    const cn = (currentIdentity || '').match(/CN=([^·\s]+)/)?.[1] || '管理员';
    const hour = new Date().getHours();
    const greet = hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好';
    $('#home-greet-line').textContent = `${greet}, ${cn}`;
    const dateStr = new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' });
    $('#home-subtitle').textContent = `${dateStr} · 仪表盘 · 快捷操作 · 最近活动`;
  }

  function wireButtons() {
    const open = $('#btn-home-open-audit');
    if (open) open.addEventListener('click', () => {
      const tab = document.querySelector('button[data-tab="audit"]');
      if (tab) tab.click();
    });
    $$('.stat-card').forEach(card => {
      card.addEventListener('click', () => {
        const stat = card.dataset.stat;
        const map = {
          services: 'actions',
          secrets: 'secrets',
          clients: 'admin-clients',
          'audit-today': 'audit',
        };
        const tab = map[stat];
        if (tab) {
          const btn = document.querySelector(`button[data-tab="${tab}"]`);
          if (btn) btn.click();
        }
      });
    });
  }

  // ---- Load all ----
  async function loadAll() {
    setGreet();
    setTip('加载统计中...');
    const [services, secrets, clients, audit] = await Promise.allSettled([
      fetchSafe('/api/v1/services'),
      fetchSafe('/api/v1/secrets'),
      fetchSafe('/api/v1/admin/clients'),
      fetchSafe(isAdmin ? '/api/v1/admin/audit?limit=200' : '/api/v1/audit?limit=200'),
    ]);
    renderStats(services, secrets, clients, audit);
    renderQuickActions(services);
    renderRecent(audit);
    if (isAdmin) renderTodo(services, secrets, clients, audit);
    setTip('');
  }

  async function fetchSafe(url) {
    try {
      const r = await fetch(url, { credentials: 'include' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch (e) {
      console.warn('home fetch failed', url, e.message);
      return { error: e.message };
    }
  }

  function setTip(text) {
    const el = $('#home-tip');
    if (el) el.textContent = text || '';
  }

  // ---- Render: stats ----
  function renderStats(services, secrets, clients, audit) {
    const sCount = services.status === 'fulfilled' ? (services.value.services?.length || 0) : 0;
    let secCount = 0;
    if (secrets.status === 'fulfilled') {
      const sv = secrets.value.secrets || secrets.value;
      secCount = Array.isArray(sv) ? sv.length : 0;
    }
    const cCount = clients.status === 'fulfilled' && isAdmin ? (clients.value.clients?.length || 0) : '—';
    let aCount = 0;
    if (audit.status === 'fulfilled' && audit.value.events) {
      const today = new Date().toISOString().slice(0, 10);
      aCount = audit.value.events.filter(e => (e.ts || '').slice(0, 10) === today).length;
    }
    animateNumber($('#stat-services'), sCount);
    animateNumber($('#stat-secrets'), secCount);
    animateNumber($('#stat-clients'), cCount);
    animateNumber($('#stat-audit-today'), aCount);
  }

  function animateNumber(el, target) {
    if (!el) return;
    if (typeof target !== 'number') { el.textContent = target; return; }
    el.textContent = target;
  }

  // ---- Render: quick actions ----
  function renderQuickActions(services) {
    const wrap = $('#home-quick-actions');
    if (!wrap) return;
    const out = [];
    // 1. Browse all services
    out.push(`<button class="qa-card" data-go="actions"><div class="qa-icon">⚡</div><div class="qa-body"><div class="qa-title">浏览所有服务</div><div class="qa-sub muted">调用 GitHub / OpenAI / 阿里云</div></div></button>`);
    // 2. View secrets
    out.push(`<button class="qa-card" data-go="secrets"><div class="qa-icon">🔑</div><div class="qa-body"><div class="qa-title">可见密钥</div><div class="qa-sub muted">查看你能用哪些密钥</div></div></button>`);
    // 3. Audit log
    out.push(`<button class="qa-card" data-go="audit"><div class="qa-icon">📋</div><div class="qa-body"><div class="qa-title">审计日志</div><div class="qa-sub muted">查谁在什么时候调了什么</div></div></button>`);
    // 4. Top services quick action
    if (services.status === 'fulfilled' && services.value.services?.length) {
      const top = services.value.services.slice(0, 3);
      for (const s of top) {
        const act = (s.actions && s.actions[0]) || null;
        if (!act) continue;
        out.push(`<button class="qa-card" data-service="${esc(s.name)}" data-method="${esc(act.method)}" data-path="${esc(act.path)}"><div class="qa-icon">${esc(s.name === 'github' ? '🐙' : s.name === 'openai' ? '🤖' : s.name === 'aliyun_ecs' ? '☁️' : s.name === 'alidns' ? '🌐' : '🔌')}</div><div class="qa-body"><div class="qa-title">${esc(s.name)} · ${esc(act.label || act.path)}</div><div class="qa-sub muted">${esc(act.method)} ${esc(act.path)}</div></div></button>`);
      }
    }
    wrap.innerHTML = out.join('');
    // wire up
    wrap.querySelectorAll('.qa-card').forEach(b => {
      b.addEventListener('click', async () => {
        if (b.dataset.go) {
          const tab = document.querySelector(`button[data-tab="${b.dataset.go}"]`);
          if (tab) tab.click();
          return;
        }
        if (b.dataset.service) {
          // Open Actions tab + auto-trigger the action via app.js loadServiceActions
          const tab = document.querySelector('button[data-tab="actions"]');
          if (tab) tab.click();
          // Dispatch custom event that app.js / services module can listen to
          window.dispatchEvent(new CustomEvent('home:quickcall', { detail: { service: b.dataset.service, method: b.dataset.method, path: b.dataset.path } }));
        }
      });
    });
  }

  // ---- Render: recent activity ----
  function renderRecent(audit) {
    const wrap = $('#home-recent');
    if (!wrap) return;
    if (audit.status !== 'fulfilled' || !audit.value.events) {
      wrap.innerHTML = '<div class="muted">无法加载最近活动</div>';
      return;
    }
    const ev = audit.value.events.slice(0, 5);
    if (ev.length === 0) {
      wrap.innerHTML = '<div class="muted">还没有活动</div>';
      return;
    }
    wrap.innerHTML = '<table class="recent-table"><tbody>' + ev.map(e => {
      const cls = e.status === 'ok' ? 'status-ok' : e.status === 'error' || e.status === 'denied' ? 'status-error' : 'muted-cell';
      const ts = e.ts ? e.ts.replace('T', ' ').slice(0, 19) : '';
      const target = e.service ? `${e.method || ''} ${e.service}${e.path || ''}`.trim() : (e.name || e.action || '?');
      return `<tr>
        <td class="muted-cell" style="white-space:nowrap">${esc(ts)}</td>
        <td><code>${esc(e.action || '')}</code></td>
        <td>${esc(target)}</td>
        <td class="${cls}">${esc(e.status || '')}</td>
      </tr>`;
    }).join('') + '</tbody></table>';
  }

  // ---- Render: TODO (admin) ----
  function renderTodo(services, secrets, clients, audit) {
    const wrap = $('#home-todo');
    if (!wrap) return;
    const items = [];

    // Rotation reminders: secrets without rotation metadata
    if (secrets.status === 'fulfilled') {
      const list = Array.isArray(secrets.value) ? secrets.value : (secrets.value.secrets || []);
      for (const s of list) {
        if (typeof s === 'string') continue;  // non-admin gets strings only
        const lastRotated = s.last_rotated_at;
        const policyDays = s.rotation_policy_days;
        if (!lastRotated) {
          items.push({ level: 'warn', text: `密钥 <code>${esc(s.name)}</code> 无轮换时间戳 — 建议设置轮换策略`, go: 'admin-secrets' });
        } else if (policyDays) {
          const days = Math.floor((Date.now() - new Date(lastRotated).getTime()) / 86400000);
          if (days >= policyDays) {
            items.push({ level: 'danger', text: `密钥 <code>${esc(s.name)}</code> 已 ${days} 天未轮换 (策略: ${policyDays} 天)`, go: 'admin-secrets' });
          } else if (days >= policyDays * 0.8) {
            items.push({ level: 'warn', text: `密钥 <code>${esc(s.name)}</code> 还剩 ${policyDays - days} 天到轮换期`, go: 'admin-secrets' });
          }
        }
      }
    }

    // Anomaly count
    if (audit.status === 'fulfilled' && audit.value.events) {
      const ev = audit.value.events.slice(0, 50);
      const denied = ev.filter(e => e.status === 'denied' || e.status === 'error').length;
      if (denied >= 5) {
        items.push({ level: 'danger', text: `最近 50 事件中有 ${denied} 次失败 — 请检查审计`, go: 'audit' });
      }
    }

    // Stale clients (no recent activity in 7 days)
    if (clients.status === 'fulfilled' && clients.value.clients && audit.status === 'fulfilled' && audit.value.events) {
      const recentCns = new Set(audit.value.events.map(e => e.cn).filter(Boolean));
      for (const c of clients.value.clients) {
        if (!recentCns.has(c.name) && c.role !== 'admin') {
          items.push({ level: 'info', text: `客户端 <code>${esc(c.name)}</code> 已 7 天无活动 — 考虑撤销`, go: 'admin-clients' });
        }
      }
    }

    // If everything is clean
    if (items.length === 0) {
      wrap.innerHTML = '<li class="muted">✅ 一切正常，没有待办</li>';
      return;
    }
    wrap.innerHTML = items.map(it => {
      const cls = it.level === 'danger' ? 'todo-danger' : it.level === 'warn' ? 'todo-warn' : 'todo-info';
      return `<li class="${cls}">${it.text}${it.go ? ` <button class="btn btn-sm btn-ghost" data-todo-go="${esc(it.go)}">→ 打开</button>` : ''}</li>`;
    }).join('');
    wrap.querySelectorAll('[data-todo-go]').forEach(b => {
      b.addEventListener('click', () => {
        const tab = document.querySelector(`button[data-tab="${b.dataset.todoGo}"]`);
        if (tab) tab.click();
      });
    });
  }

  // ---- Boot ----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Reload when home tab is shown (so recent activity refreshes)
  document.addEventListener('tabchange', (e) => {
    if (e.detail?.tab === 'home') loadAll();
  });
})();
