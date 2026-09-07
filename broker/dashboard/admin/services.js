// admin/services.js — Phase 1.2: Services management UI
// Loaded after app.js. Uses the same `api()` helper exposed on window.
// Pattern: list → template-driven create/edit modal → test button → permission matrix.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentIdentity = null;
  let isAdmin = false;
  let templates = {};        // id -> { label, icon, description, type, disabled }
  let services = [];         // [{ name, type, description, upstream, dashboard_actions, allowed_clients, ... }]
  let editingName = null;
  let loadedTemplatesAt = 0;

  // ---- Bootstrap ----
  function init() {
    const subscribe = typeof subscribeBrokerIdentity === 'function'
      ? subscribeBrokerIdentity
      : (handler) => document.addEventListener('broker:identity', (e) => handler(e.detail));
    subscribe((ident) => {
      currentIdentity = ident;
      isAdmin = !!(ident && ident.role === 'admin');
      if (isAdmin) {
        loadTemplates();
        loadServices();
      }
    });
    wireModal();
  }

  // ---- API ----
  async function loadTemplates(force) {
    if (!isAdmin) return;
    if (!force && Date.now() - loadedTemplatesAt < 60000) return;
    try {
      const r = await api('/api/v1/admin/service-templates');
      templates = r.templates || {};
      loadedTemplatesAt = Date.now();
      populateTemplateDropdown();
    } catch (ex) {
      console.error('Failed to load service templates:', ex);
    }
  }

  async function loadServices() {
    if (!isAdmin) return;
    try {
      const r = await api('/api/v1/admin/services');
      services = r.services || [];
      renderTable();
    } catch (ex) {
      showTableError(ex.message);
    }
  }

  async function createService(payload) {
    return api('/api/v1/admin/services', { method: 'POST', body: JSON.stringify(payload) });
  }
  async function updateService(name, payload) {
    return api(`/api/v1/admin/services/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(payload) });
  }
  async function deleteService(name) {
    return api(`/api/v1/admin/services/${encodeURIComponent(name)}`, { method: 'DELETE' });
  }
  async function testService(name, opts = {}) {
    return api(`/api/v1/admin/services/${encodeURIComponent(name)}/test`, {
      method: 'POST', body: JSON.stringify(opts || {}),
    });
  }

  // ---- Render table ----
  function renderTable() {
    const tbody = $('#admin-services-table tbody');
    if (!tbody) return;
    $('#admin-services-count').textContent = services.length ? `共 ${services.length} 个` : '';
    if (services.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">（还没有任何服务）— 点右上角"+ 新增"添加第一个。选模板会自动填好 upstream / headers。</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const s of services) {
      const tr = document.createElement('tr');
      const upstreamShort = (s.upstream || '').replace(/^https?:\/\//, '').split('/')[0] || '-';
      const ac = (s.allowed_clients || []).length;
      const actions = s.action_count || 0;
      tr.innerHTML = `
        <td><strong>${esc(s.name)}</strong></td>
        <td><code>${esc(s.type)}</code></td>
        <td class="muted-cell">${esc(upstreamShort)}</td>
        <td>${esc(s.description || '')}</td>
        <td class="muted-cell">${actions} 个 / ${ac} 客户端</td>
        <td class="row-actions">
          <button class="btn btn-sm" data-act="test" data-name="${esc(s.name)}">测试</button>
          <button class="btn btn-sm btn-primary" data-act="edit" data-name="${esc(s.name)}">编辑</button>
          <button class="btn btn-sm btn-danger" data-act="delete" data-name="${esc(s.name)}">删除</button>
        </td>`;
      tbody.appendChild(tr);
    }
    // Wire row buttons
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const act = e.currentTarget.dataset.act;
        const name = e.currentTarget.dataset.name;
        if (act === 'edit') openEditModal(name);
        else if (act === 'delete') confirmDelete(name);
        else if (act === 'test') runTest(name);
      });
    });
  }

  function showTableError(msg) {
    const tbody = $('#admin-services-table tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="status-error">加载失败: ${esc(msg)}</td></tr>`;
  }

  // ---- Template dropdown (in modal) ----
  function populateTemplateDropdown() {
    const sel = $('#svc-tpl');
    if (!sel) return;
    sel.innerHTML = '<option value="">— 自定义 (无模板) —</option>';
    for (const [id, t] of Object.entries(templates)) {
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = `${t.icon || ''} ${t.label}${t.disabled ? '（未开放）' : ''}`;
      if (t.disabled) opt.disabled = true;
      sel.appendChild(opt);
    }
  }

  // When user picks a template, pre-fill the form fields. We DO NOT touch
  // existing data on edit — only when creating from scratch.
  function applyTemplate(templateId) {
    if (!templateId) return;
    const t = templates[templateId];
    if (!t || t.disabled) return;
    // Fetch the full template (with skeleton) from a server endpoint? We don't
    // have one yet — but we can pull from a known map embedded in admin app.
    // Easiest: hit a public-ish endpoint that returns the full template. For
    // now, just type a hint; the actual fields are filled by the user (or by
    // a fetch of GET /api/v1/admin/service-templates which is sanitized).
    // TODO: expose full template skeletons from server if user wants zero-typing.
  }

  // ---- Modal: create / edit ----
  function openCreateModal() {
    editingName = null;
    $('#service-modal-title').textContent = '新增服务 / New Service';
    $('#svc-name').value = '';
    $('#svc-name').disabled = false;
    $('#svc-type').value = 'bearer';
    $('#svc-description').value = '';
    $('#svc-upstream').value = '';
    $('#svc-region').value = '';
    $('#svc-token-secret').value = '';
    $('#svc-actions').value = '';
    $('#svc-tpl').value = '';
    $('#service-error').hidden = true;
    $('#service-modal').hidden = false;
    setTimeout(() => $('#svc-name').focus(), 50);
  }

  async function openEditModal(name) {
    editingName = name;
    $('#service-modal-title').textContent = `编辑服务 / Edit: ${name}`;
    $('#svc-name').value = name;
    $('#svc-name').disabled = true;  // name is immutable on edit
    try {
      const r = await api(`/api/v1/admin/services/${encodeURIComponent(name)}`);
      const s = r;
      $('#svc-type').value = s.type || 'bearer';
      $('#svc-description').value = s.description || '';
      $('#svc-upstream').value = s.upstream || '';
      $('#svc-region').value = s.region || '';
      $('#svc-token-secret').value = s.token_secret || '';
      $('#svc-actions').value = (s.dashboard_actions || []).map(a =>
        `${a.method || 'GET'} ${a.path}${a.query ? '  query=' + JSON.stringify(a.query) : ''}  -- ${a.label}`
      ).join('\n');
      $('#svc-tpl').value = '';  // editing never re-applies template
      $('#service-error').hidden = true;
      $('#service-modal').hidden = false;
    } catch (e) {
      alert('加载失败 / Load failed: ' + e.message);
    }
  }

  function closeModal() {
    const modal = $('#service-modal');
    if (modal) modal.hidden = true;
    // Reset title so it doesn't leak into the next open
    const title = $('#service-modal-title');
    if (title) title.textContent = '新增服务 / New Service';
    editingName = null;
  }

  // ---- Save ----
  async function onSave() {
    const name = $('#svc-name').value.trim();
    const cfg = {
      name,
      type: $('#svc-type').value.trim(),
      description: $('#svc-description').value.trim(),
      upstream: $('#svc-upstream').value.trim(),
      region: $('#svc-region').value.trim() || undefined,
      token_secret: $('#svc-token-secret').value.trim() || undefined,
      dashboard_actions: parseActions($('#svc-actions').value),
    };
    if (!name) return showServiceError('请填写服务名 / Name required');
    if (cfg.dashboard_actions && cfg.dashboard_actions.length === 0 && $('#svc-actions').value.trim() !== '') {
      return showServiceError('快捷操作格式错误。示例：GET /user  -- 我的信息');
    }
    try {
      if (editingName) {
        await updateService(editingName, cfg);
      } else {
        await createService(cfg);
      }
      closeModal();
      await loadServices();
    } catch (e) {
      showServiceError(e.message || String(e));
    }
  }

  // Parse the multi-line actions textarea. One per line. Format:
  //   GET /user  -- 我的信息
  //   POST /v1/chat  query={a:b}  -- 创建对话
  function parseActions(text) {
    const out = [];
    for (const raw of (text || '').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      // Match: METHOD PATH [query=JSON] [-- LABEL]
      const m = line.match(/^([A-Z]+)\s+(\S+)(?:\s+query=(\{[^}]*\}))?(?:\s+--\s*(.+))?$/);
      if (!m) continue;
      let q;
      try { q = m[3] ? JSON.parse(m[3]) : undefined; } catch (e) { q = undefined; }
      out.push({ method: m[1], path: m[2], ...(q ? { query: q } : {}), label: (m[4] || m[2]).trim() });
    }
    return out;
  }

  function showServiceError(msg) {
    const el = $('#service-error');
    if (!el) { alert(msg); return; }
    el.textContent = msg;
    el.hidden = false;
  }

  // ---- Delete ----
  async function confirmDelete(name) {
    if (!confirm(`确定删除服务 ${name} ?\nDelete service ${name}?`)) return;
    try {
      await deleteService(name);
      await loadServices();
    } catch (e) {
      alert('删除失败 / Delete failed: ' + e.message);
    }
  }

  // ---- Test ----
  async function runTest(name) {
    const btn = document.querySelector(`button[data-act="test"][data-name="${cssEsc(name)}"]`);
    if (btn) { btn.disabled = true; btn.textContent = '测试中…'; }
    const out = $('#service-test-result');
    if (out) { out.hidden = true; out.textContent = ''; }
    try {
      const r = await testService(name, {});
      const text = formatTestResult(r);
      if (out) { out.textContent = text; out.hidden = false; out.className = r.ok ? 'status-ok' : 'status-error'; }
    } catch (e) {
      const text = '调用失败: ' + e.message;
      if (out) { out.textContent = text; out.hidden = false; out.className = 'status-error'; }
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '测试'; }
    }
  }

  function formatTestResult(r) {
    if (r.ok === false && r.error) {
      return `[ERROR] ${r.error}\n（latency ${r.latency_ms || 0}ms）`;
    }
    const lines = [];
    lines.push(`[OK] upstream_status=${r.upstream_status} latency=${r.latency_ms}ms`);
    if (r.body_preview) lines.push('--- preview ---', r.body_preview);
    return lines.join('\n');
  }

  // ---- Wire DOM ----
  function wireModal() {
    const newBtn = $('#btn-new-service');
    if (newBtn) newBtn.addEventListener('click', openCreateModal);
    const cancelBtn = $('#btn-cancel-service');
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
    const saveBtn = $('#btn-save-service');
    if (saveBtn) saveBtn.addEventListener('click', onSave);
    const tplSel = $('#svc-tpl');
    if (tplSel) tplSel.addEventListener('change', (e) => applyTemplate(e.currentTarget.value));
    const modal = $('#service-modal');
    if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.hidden) closeModal();
    });
    // The Secrets admin tab also fires on this same view; we hook reload
    // into the same "load" event so a re-visit of the tab refetches.
    document.addEventListener('tabchange', (e) => {
      if (e.detail?.tab === 'admin-services' && isAdmin) {
        loadTemplates(true);
        loadServices();
      }
    });
  }

  // ---- Util ----
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function cssEsc(s) {
    return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  }

  // ---- Go ----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
