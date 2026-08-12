// admin/secrets.js — Phase 1.1: Secrets management UI
// Loaded after app.js. Uses the same `api()` helper exposed on window.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentIdentity = null;
  let isAdmin = false;
  let secrets = []; // [{ name, type, description, created_at, updated_at, updated_by, has_value }]
  let editingName = null; // null = creating, otherwise editing existing

  // ---- Bootstrap: hook into app's boot() via interval until identity available ----
  function init() {
    // Watch identity updates (app.js updates #identity text content on boot)
    const id = setInterval(() => {
      const text = ($('#identity')?.textContent || '').trim();
      if (text && text !== currentIdentity) {
        currentIdentity = text;
        isAdmin = /role=admin/.test(text);
        applyAdminVisibility();
        if (isAdmin) {
          loadSecrets();
        }
      }
      // Stop polling after 30s — app.js will have either rendered or shown login by then
    }, 500);
    setTimeout(() => clearInterval(id), 30000);
  }

  function applyAdminVisibility() {
    $$('.admin-only').forEach(el => { el.hidden = !isAdmin; });
  }

  // ---- API ----
  async function loadSecrets() {
    if (!isAdmin) return;
    try {
      const r = await api('/api/v1/admin/secrets');
      secrets = r.secrets || [];
      renderTable();
    } catch (ex) {
      showTableError(ex.message);
    }
  }

  async function createSecret(payload) {
    return api('/api/v1/admin/secrets', { method: 'POST', body: JSON.stringify(payload) });
  }

  async function updateSecret(name, payload) {
    return api(`/api/v1/admin/secrets/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(payload) });
  }

  async function deleteSecret(name) {
    return api(`/api/v1/admin/secrets/${encodeURIComponent(name)}`, { method: 'DELETE' });
  }

  // ---- Render ----
  function renderTable() {
    const tbody = $('#admin-secrets-table tbody');
    if (!tbody) return;
    $('#admin-secrets-count').textContent = secrets.length ? `共 ${secrets.length} 个` : '';
    if (secrets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">（还没有任何密钥）— 点右上角"+ 新增"添加第一个。</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const s of secrets) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(s.name)}</code>${s.has_value ? '' : ' <span class="badge badge-denied">无值</span>'}</td>
        <td><span class="badge badge-type">${escapeHtml(s.type || 'custom')}</span></td>
        <td>${escapeHtml(s.description || '')}</td>
        <td class="muted">${formatTs(s.updated_at)}</td>
        <td>
          <button class="btn btn-sm" data-act="edit" data-name="${escapeHtml(s.name)}">编辑</button>
          <button class="btn btn-sm" data-act="delete" data-name="${escapeHtml(s.name)}">删除</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.dataset.act;
        const name = btn.dataset.name;
        if (act === 'edit') openModal(name);
        else if (act === 'delete') confirmDelete(name);
      });
    });
  }

  function showTableError(msg) {
    const tbody = $('#admin-secrets-table tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="status-error">加载失败：${escapeHtml(msg)}</td></tr>`;
  }

  function formatTs(ts) {
    if (!ts) return '-';
    try {
      return new Date(ts).toISOString().replace('T', ' ').slice(0, 19);
    } catch { return ts; }
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  // ---- Modal ----
  function openModal(name) {
    editingName = name || null;
    const modal = $('#secret-modal');
    const title = $('#secret-modal-title');
    const f = $('#secret-form');
    f.reset();
    $('#sf-error').hidden = true;
    const valEl = $('#sf-value');
    valEl.value = '';
    const nameEl = $('#sf-name');
    if (editingName) {
      title.textContent = `编辑密钥 / Edit: ${editingName}`;
      nameEl.value = editingName;
      nameEl.disabled = true;
      const s = secrets.find(x => x.name === editingName);
      if (s) {
        $('#sf-type').value = s.type || 'custom';
        $('#sf-description').value = s.description || '';
      }
      valEl.required = false;
      valEl.placeholder = '(留空表示不修改值)';
      $('#sf-value-hint').textContent = '编辑模式下：留空表示只改 type/description，不动 value。';
    } else {
      title.textContent = '新增密钥 / New Secret';
      nameEl.disabled = false;
      valEl.required = true;
      valEl.placeholder = '粘贴 token / 密钥 / 私钥 / 连接串...';
      $('#sf-value-hint').textContent = '不会保存到浏览器存储。提交后值在内存中立即清空。';
    }
    modal.hidden = false;
    setTimeout(() => nameEl.focus(), 50);
  }

  function closeModal() {
    $('#secret-modal').hidden = true;
    // Security: clear value from DOM
    $('#sf-value').value = '';
    editingName = null;
  }

  async function confirmDelete(name) {
    if (!confirm(`确定删除密钥 ${name} ？\n删除后引用它的 service 模板会立即调用失败。\nDelete secret ${name}? Services referencing it will fail immediately.`)) return;
    try {
      await deleteSecret(name);
      await loadSecrets();
    } catch (ex) {
      alert(`删除失败：${ex.message}`);
    }
  }

  async function submitForm(e) {
    e.preventDefault();
    const errEl = $('#sf-error');
    errEl.hidden = true;
    const btn = $('#btn-save-secret');
    btn.disabled = true;
    btn.textContent = '保存中...';
    try {
      if (editingName) {
        // Update: value optional, type/description always
        const payload = {
          type: $('#sf-type').value,
          description: $('#sf-description').value,
        };
        const v = $('#sf-value').value;
        if (v) payload.value = v;
        await updateSecret(editingName, payload);
      } else {
        // Create: name, value, type, description all required
        await createSecret({
          name: $('#sf-name').value.trim(),
          value: $('#sf-value').value,
          type: $('#sf-type').value,
          description: $('#sf-description').value,
        });
      }
      closeModal();
      await loadSecrets();
    } catch (ex) {
      errEl.textContent = ex.message;
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = '保存 / Save';
    }
  }

  // ---- Wire up ----
  function wireEvents() {
    const newBtn = $('#btn-new-secret');
    if (newBtn) newBtn.addEventListener('click', () => openModal(null));
    const refreshBtn = $('#btn-refresh-secrets-admin');
    if (refreshBtn) refreshBtn.addEventListener('click', loadSecrets);
    const cancelBtn = $('#btn-cancel-secret');
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
    const form = $('#secret-form');
    if (form) form.addEventListener('submit', submitForm);
    // Close modal on backdrop click
    const modal = $('#secret-modal');
    if (modal) modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
    // Escape key closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !$('#secret-modal').hidden) closeModal();
    });
  }

  // ---- Start ----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { wireEvents(); init(); });
  } else {
    wireEvents();
    init();
  }
})();
