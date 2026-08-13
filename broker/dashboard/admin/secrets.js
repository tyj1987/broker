// admin/secrets.js — Phase 1.1.1: Secrets management UI with dynamic type-aware forms
// Loaded after app.js. Uses the same `api()` helper exposed on window.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentIdentity = null;
  let isAdmin = false;
  let typeSchemas = {}; // type_id -> { label, description, fields: [...] }
  let secrets = [];     // [{ name, type, description, fields, ... }]
  let editingName = null;
  let loadedTypesAt = 0;

  // ---- Bootstrap ----
  function init() {
    const id = setInterval(() => {
      const text = ($('#identity')?.textContent || '').trim();
      if (text && text !== currentIdentity) {
        currentIdentity = text;
        isAdmin = /role=admin/.test(text);
        applyAdminVisibility();
        if (isAdmin) {
          loadTypeSchemas();
          loadSecrets();
        }
      }
    }, 500);
    setTimeout(() => clearInterval(id), 30000);
  }

  function applyAdminVisibility() {
    $$('.admin-only').forEach(el => { el.hidden = !isAdmin; });
  }

  // ---- API ----
  async function loadTypeSchemas(force) {
    if (!isAdmin) return;
    if (!force && Date.now() - loadedTypesAt < 60000) return;  // cache 60s
    try {
      const r = await api('/api/v1/admin/types');
      typeSchemas = r.types || {};
      loadedTypesAt = Date.now();
      populateTypeDropdown();
    } catch (ex) {
      console.error('Failed to load types:', ex);
    }
  }

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

  // ---- Multi-select state ----
  let selectedNames = new Set();
  function updateBulkBar() {
    const bar = $('#bulk-action-bar');
    const count = selectedNames.size;
    if (!bar) return;
    if (count === 0) {
      bar.hidden = true;
    } else {
      bar.hidden = false;
      $('#bulk-action-count').textContent = `已选 ${count} 个 / ${count} selected`;
    }
    // Sync select-all checkbox
    const allBox = $('#secrets-select-all');
    if (allBox) {
      const all = secrets.length;
      allBox.checked = all > 0 && count === all;
      allBox.indeterminate = count > 0 && count < all;
    }
  }

  // ---- Render table ----
  function renderTable() {
    const tbody = $('#admin-secrets-table tbody');
    if (!tbody) return;
    $('#admin-secrets-count').textContent = secrets.length ? `共 ${secrets.length} 个` : '';
    if (secrets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">（还没有任何密钥）— 点右上角"+ 新增"添加第一个。</td></tr>';
      updateBulkBar();
      return;
    }
    tbody.innerHTML = '';
    for (const s of secrets) {
      const tr = document.createElement('tr');
      const fieldCount = Object.keys(s.fields || {}).length;
      const fieldSummary = fieldCount > 0
        ? `${fieldCount} 字段: ${Object.keys(s.fields).slice(0, 4).join(', ')}${fieldCount > 4 ? '…' : ''}`
        : '<span class="muted">(无字段)</span>';
      const checked = selectedNames.has(s.name) ? 'checked' : '';
      tr.innerHTML = `
        <td><input type="checkbox" class="row-check" data-name="${escapeHtml(s.name)}" ${checked}></td>
        <td><code>${escapeHtml(s.name)}</code></td>
        <td><span class="badge badge-type">${escapeHtml(s.type || 'custom')}</span></td>
        <td>
          <div>${escapeHtml(s.description || '')}</div>
          <div class="muted" style="font-size:0.75rem;margin-top:2px">${fieldSummary}</div>
        </td>
        <td class="muted">${formatTs(s.updated_at)}<br><span style="font-size:0.75rem">${escapeHtml(s.updated_by || '')}</span></td>
        <td>
          <button class="btn btn-sm" data-act="edit" data-name="${escapeHtml(s.name)}">编辑</button>
          <button class="btn btn-sm" data-act="delete" data-name="${escapeHtml(s.name)}">删除</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    // Per-row checkbox
    tbody.querySelectorAll('input.row-check').forEach(cb => {
      cb.addEventListener('change', () => {
        const n = cb.dataset.name;
        if (cb.checked) selectedNames.add(n);
        else selectedNames.delete(n);
        updateBulkBar();
      });
    });
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.dataset.act;
        const name = btn.dataset.name;
        if (act === 'edit') openModal(name);
        else if (act === 'delete') confirmDelete(name);
      });
    });
    updateBulkBar();
  }

  function showTableError(msg) {
    const tbody = $('#admin-secrets-table tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="status-error">加载失败：${escapeHtml(msg)}</td></tr>`;
  }

  function formatTs(ts) {
    if (!ts) return '-';
    try { return new Date(ts).toISOString().replace('T', ' ').slice(0, 19); }
    catch { return ts; }
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  // ---- Type dropdown ----
  // Group types by their "section" inferred from label prefix
  function populateTypeDropdown() {
    const sel = $('#sf-type');
    if (!sel) return;
    const prev = sel.value;
    const groups = {
      '通用 / General': [],
      '代码平台 / Code': [],
      'AI 服务 / AI': [],
      '云厂商 / Cloud': [],
      '基础设施 / Infra': [],
      '通讯通知 / Messaging': [],
      '监控 / Observability': [],
      '支付 / Payment': [],
      '其他 / Other': [],
    };
    for (const [id, schema] of Object.entries(typeSchemas)) {
      const label = schema.label || id;
      let group = '其他 / Other';
      if (/github|gitlab|gitee|bitbucket|code/i.test(id + label)) group = '代码平台 / Code';
      else if (/openai|anthropic|google.?ai|mistral|cohere|deepseek|zhipu|moonshot|qwen|gemini|claude/i.test(id + label)) group = 'AI 服务 / AI';
      else if (/aliyun|tencent|aws|gcp|cloudflare|oss|cos|s3/i.test(id + label)) group = '云厂商 / Cloud';
      else if (/ssh|database|redis|mongo|postgres|mysql|smtp|sendgrid|mailgun|slack|discord|feishu|dingtalk|telegram|webhook|github_pat|gitlab_pat|gitee_pat/i.test(id + label)) group = '基础设施 / Infra';
      else if (/sentry|datadog|prometheus|grafana|datadog|newrelic/i.test(id + label)) group = '监控 / Observability';
      else if (/stripe|pay|alipay|wechat_pay|微信/i.test(id + label)) group = '支付 / Payment';
      else if (/custom|jwt|oauth|random|jwt_secret/i.test(id)) group = '通用 / General';
      groups[group].push({ id, label });
    }
    sel.innerHTML = '';
    for (const [groupName, items] of Object.entries(groups)) {
      if (items.length === 0) continue;
      const og = document.createElement('optgroup');
      og.label = groupName;
      for (const { id, label } of items.sort((a, b) => a.label.localeCompare(b.label))) {
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = `${label} (${id})`;
        og.appendChild(opt);
      }
      sel.appendChild(og);
    }
    if (prev && typeSchemas[prev]) sel.value = prev;
    // Add change listener (re-render fields) — only once
    if (!sel.dataset.wired) {
      sel.addEventListener('change', () => renderFieldsForType(sel.value));
      sel.dataset.wired = '1';
    }
  }

  // ---- Field rendering (dynamic per type schema) ----
  function renderFieldsForType(type, currentValues, opts) {
    const schema = typeSchemas[type];
    const container = $('#sf-fields-container');
    if (!container) return;
    container.innerHTML = '';
    if (!schema) {
      container.innerHTML = '<p class="muted">类型未加载，刷新页面重试</p>';
      return;
    }
    // Compute effective initial values: prefer existing values, fall back to schema defaults
    const initialValues = {};
    for (const f of schema.fields) {
      if (currentValues && currentValues[f.name] !== undefined && currentValues[f.name] !== '') {
        initialValues[f.name] = currentValues[f.name];
      } else if (f.default !== undefined) {
        initialValues[f.name] = f.default;
      } else if (f.kind === 'checkbox') {
        initialValues[f.name] = false;
      } else {
        initialValues[f.name] = '';
      }
    }
    for (const f of schema.fields) {
      if (f.show_when) {
        if (initialValues[f.show_when.field] !== f.show_when.equals) {
          const wrap = document.createElement('div');
          wrap.className = 'sf-field';
          wrap.dataset.field = f.name;
          wrap.hidden = true;
          wrap.appendChild(buildFieldInput(f, initialValues[f.name], opts));
          container.appendChild(wrap);
          continue;
        }
      }
      const wrap = document.createElement('div');
      wrap.className = 'sf-field';
      wrap.dataset.field = f.name;
      wrap.appendChild(buildFieldInput(f, initialValues[f.name], opts));
      container.appendChild(wrap);
    }
    for (const f of schema.fields.filter(x => x.show_when)) {
      const triggerEl = container.querySelector(`[name="sf-f-${f.show_when.field}"]`);
      if (triggerEl) {
        triggerEl.addEventListener('change', () => {
          const vals = collectFieldValues();
          for (const field of schema.fields) {
            const wrap = container.querySelector(`.sf-field[data-field="${field.name}"]`);
            if (!wrap) continue;
            if (field.show_when) {
              wrap.hidden = vals[field.show_when.field] !== field.show_when.equals;
            }
          }
        });
      }
    }
  }

  function buildFieldInput(f, currentValue, opts) {
    const isEdit = opts && opts.isEdit;
    // Use DIV (not LABEL) — label-wrapped textareas/inputs can be reparented by browser HTML parser.
    const wrap = document.createElement('div');
    wrap.className = 'sf-field-label';
    const isRequired = f.required && !(isEdit && f.sensitive);
    const labelText = f.label + (isRequired ? ' *' : '');
    const helpText = f.help || '';
    let inputHtml = '';
    let afterHtml = '';
    const val = currentValue !== undefined ? currentValue : (f.default !== undefined ? f.default : '');
    const isSensitive = !!f.sensitive;
    const id = `sf-f-${f.name}`;
    if (f.kind === 'select') {
      const optsHtml = (f.options || []).map(o => `<option value="${escapeHtml(o.value)}"${String(val) === String(o.value) ? ' selected' : ''}>${escapeHtml(o.label)}</option>`).join('');
      inputHtml = `<select id="${id}" name="${id}"${isRequired ? ' required' : ''}>${optsHtml}</select>`;
    } else if (f.kind === 'textarea') {
      const displayVal = isSensitive && val ? '••••••••' : val;
      const isKeyLike = /-----BEGIN/.test(String(val));
      const rows = isKeyLike ? 6 : 3;
      const fieldId = `sf-f-${f.name}`;
      inputHtml = `<textarea id="${fieldId}" name="${fieldId}" rows="${rows}"${isRequired ? ' required' : ''} placeholder="${escapeHtml(f.placeholder || '')}">${escapeHtml(displayVal || '')}</textarea>`;
      // File upload button for fields flagged with file_upload: true
      if (f.file_upload) {
        const fileInputId = `${fieldId}-file`;
        const fileNameId = `${fieldId}-filename`;
        afterHtml = `
          <div class="sf-file-upload">
            <input type="file" id="${fileInputId}" data-target="${fieldId}" data-filename="${fileNameId}" style="display:none" />
            <button type="button" class="btn btn-sm" data-file-trigger="${fileInputId}">📁 上传文件 / Upload</button>
            <span id="${fileNameId}" class="muted" style="margin-left:6px;font-size:0.85rem"></span>
            <span class="hint" style="margin-top:2px">点 "上传文件" 选择 .pem / .key / .pub — 内容自动填入上方文本框</span>
          </div>`;
      }
    } else if (f.kind === 'checkbox') {
      inputHtml = `<label class="sf-checkbox"><input id="${id}" name="${id}" type="checkbox"${val ? ' checked' : ''}> ${escapeHtml(f.label)}</label>`;
      wrap.classList.add('sf-field-checkbox');
    } else if (f.kind === 'number') {
      inputHtml = `<input id="${id}" name="${id}" type="number" value="${escapeHtml(val || '')}"${isRequired ? ' required' : ''} placeholder="${escapeHtml(f.placeholder || '')}">`;
    } else if (f.kind === 'password') {
      // Always show as password with an eye-toggle button
      inputHtml = `
        <div class="sf-pw-wrap">
          <input id="${id}" name="${id}" type="password" value="${escapeHtml(val || '')}"${isRequired ? ' required' : ''} placeholder="${escapeHtml(f.placeholder || '')}" autocomplete="new-password">
          <button type="button" class="sf-eye" data-eye-for="${id}" title="显示/隐藏" aria-label="显示/隐藏">👁</button>
        </div>`;
    } else {
      // text or default
      inputHtml = `<input id="${id}" name="${id}" type="text" value="${escapeHtml(val || '')}"${isRequired ? ' required' : ''} placeholder="${escapeHtml(f.placeholder || '')}">`;
    }
    if (f.kind === 'checkbox') {
      wrap.innerHTML = helpText ? `${inputHtml}<div class="hint" style="margin-top:4px">${escapeHtml(helpText)}</div>` : inputHtml;
    } else {
      wrap.innerHTML = `<div class="sf-field-label-text">${escapeHtml(labelText)}</div>${inputHtml}${afterHtml}${helpText ? `<div class="hint">${escapeHtml(helpText)}</div>` : ''}`;
    }
    return wrap;
  }

  function collectFieldValues() {
    const schema = typeSchemas[$('#sf-type').value];
    if (!schema) return {};
    const out = {};
    for (const f of schema.fields) {
      const el = $(`#sf-f-${f.name}`);
      if (!el) continue;
      if (f.kind === 'checkbox') out[f.name] = el.checked;
      else if (f.kind === 'number') out[f.name] = el.value === '' ? null : Number(el.value);
      else out[f.name] = el.value;
    }
    return out;
  }

  // ---- Modal ----
  async function openModal(name) {
    editingName = name || null;
    if (Object.keys(typeSchemas).length === 0) await loadTypeSchemas(true);
    populateTypeDropdown();
    const modal = $('#secret-modal');
    const title = $('#secret-modal-title');
    const f = $('#secret-form');
    f.reset();
    $('#sf-error').hidden = true;
    const descEl = $('#secret-modal-type-desc');
    const nameEl = $('#sf-name');
    if (editingName) {
      title.textContent = `编辑密钥 / Edit: ${editingName}`;
      nameEl.value = editingName;
      nameEl.disabled = true;
      const s = secrets.find(x => x.name === editingName);
      if (s) {
        $('#sf-type').value = s.type || 'custom';
        $('#sf-type').disabled = true;  // type is identity — changing = delete+recreate
        $('#sf-description').value = s.description || '';
        descEl.textContent = (typeSchemas[s.type]?.description || '') + ' (编辑模式下字段已脱敏显示为 •)';
        renderFieldsForType(s.type, s.fields || {}, { isEdit: true });
        // For sensitive fields, clear the masked value so user must type to change.
        // The HTML `required` attribute is already skipped for sensitive+edit in buildFieldInput.
        for (const f of (typeSchemas[s.type]?.fields || [])) {
          if (f.sensitive) {
            const el = $(`#sf-f-${f.name}`);
            if (el) el.value = '';
          }
        }
      }
    } else {
      title.textContent = '新增密钥 / New Secret';
      nameEl.disabled = false;
      $('#sf-type').disabled = false;
      $('#sf-type').value = 'custom';
      descEl.textContent = typeSchemas['custom']?.description || '';
      renderFieldsForType('custom');
    }
    modal.hidden = false;
    setTimeout(() => nameEl.focus(), 50);
  }

  function closeModal() {
    $('#secret-modal').hidden = true;
    // Security: clear all field values from DOM
    $$('#sf-fields-container input, #sf-fields-container textarea').forEach(el => { el.value = ''; });
    $('#sf-fields-container').innerHTML = '';
    $('#sf-name').disabled = false;
    $('#sf-type').disabled = false;
    $('#sf-description').disabled = false;
    $('#btn-save-secret').style.display = '';
    $('#btn-cancel-secret').textContent = '取消 / Cancel';
    $('#sf-error').hidden = true;
    // Reset modal title so copy/view modal titles don't leak into the next open
    const title = $('#secret-modal-title');
    if (title) title.textContent = '新增密钥 / New Secret';
    editingName = null;
  }

  async function confirmDelete(name) {
    if (!confirm(`确定删除密钥 ${name}？\n删除后引用它的 service 模板会立即调用失败。\nDelete secret ${name}? Services referencing it will fail immediately.`)) return;
    try {
      await deleteSecret(name);
      selectedNames.delete(name);
      await loadSecrets();
    } catch (ex) {
      alert(`删除失败：${ex.message}`);
    }
  }

  async function confirmBulkDelete() {
    const names = Array.from(selectedNames);
    if (names.length === 0) return;
    const sample = names.slice(0, 5).join(', ') + (names.length > 5 ? ` ... +${names.length - 5}` : '');
    if (!confirm(`确定删除以下 ${names.length} 个密钥？\n${sample}\n\n删除后引用它们的 service 模板会立即调用失败。\n\nDelete ${names.length} secrets? Services referencing them will fail immediately.`)) return;
    const bar = $('#bulk-action-bar');
    const origHtml = bar ? bar.innerHTML : '';
    if (bar) bar.innerHTML = `<span>删除中... 0/${names.length}</span>`;
    let ok = 0, fail = 0;
    const failed = [];
    for (let i = 0; i < names.length; i++) {
      const n = names[i];
      try {
        await deleteSecret(n);
        selectedNames.delete(n);
        ok++;
      } catch (ex) {
        fail++;
        failed.push(`${n}: ${ex.message}`);
      }
      if (bar) bar.innerHTML = `<span>删除中... ${i + 1}/${names.length} (成功 ${ok} 失败 ${fail})</span>`;
    }
    if (bar) bar.innerHTML = origHtml;
    if (failed.length) {
      alert(`完成：成功 ${ok}，失败 ${fail}\n失败明细：\n${failed.join('\n')}`);
    } else {
      console.log(`bulk delete: ${ok} removed, 0 failed`);
    }
    await loadSecrets();
  }

  // ---- Eye toggle (password show/hide) ----
  function wireEyeToggle() {
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-eye-for]');
      if (!btn) return;
      const id = btn.dataset.eyeFor;
      const input = document.getElementById(id);
      if (!input) return;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
        btn.title = '隐藏 / Hide';
      } else {
        input.type = 'password';
        btn.textContent = '👁';
        btn.title = '显示 / Show';
      }
      // Keep focus and caret position
      input.focus();
    });
  }

  // ---- File upload (textarea with file_upload: true) ----
  function wireFileUpload() {
    // Trigger buttons — open the hidden file input
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-file-trigger]');
      if (!btn) return;
      const id = btn.dataset.fileTrigger;
      const input = document.getElementById(id);
      if (input) input.click();
    });
    // File input change — read content, fill target textarea
    document.addEventListener('change', async (e) => {
      const input = e.target;
      if (!input.matches('input[type=file][data-target]')) return;
      const file = input.files && input.files[0];
      if (!file) return;
      // Refuse huge files (>1 MB) — should never happen for keys/certs but protect anyway
      if (file.size > 1024 * 1024) {
        alert(`文件过大 (${(file.size/1024).toFixed(0)} KB > 1024 KB)，请检查`);
        input.value = '';
        return;
      }
      const targetId = input.dataset.target;
      const fileNameId = input.dataset.filename;
      const ta = document.getElementById(targetId);
      if (!ta) return;
      try {
        const text = await file.text();
        ta.value = text;
        // Show filename
        const fn = document.getElementById(fileNameId);
        if (fn) fn.textContent = `✓ 已加载 ${file.name} (${file.size} 字节)`;
        // Trigger any 'change' listeners (so the form knows the value changed)
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      } catch (err) {
        alert(`读取文件失败: ${err.message}`);
      }
    });
  }

  async function submitForm(e) {
    e.preventDefault();
    const errEl = $('#sf-error');
    errEl.hidden = true;
    const btn = $('#btn-save-secret');
    btn.disabled = true;
    btn.textContent = '保存中...';
    try {
      const fields = collectFieldValues();
      if (editingName) {
        // Only send fields that user actively filled (clear sensitive empty fields = keep existing)
        const existing = secrets.find(s => s.name === editingName);
        const merged = { ...(existing?.fields || {}) };
        for (const [k, v] of Object.entries(fields)) {
          // If user left sensitive field empty, don't overwrite
          const schema = typeSchemas[$('#sf-type').value];
          const fieldDef = schema?.fields.find(f => f.name === k);
          if (fieldDef?.sensitive && (v === '' || v === null || v === undefined)) continue;
          merged[k] = v;
        }
        await updateSecret(editingName, {
          description: $('#sf-description').value,
          fields: merged,
        });
      } else {
        await createSecret({
          name: $('#sf-name').value.trim(),
          type: $('#sf-type').value,
          description: $('#sf-description').value,
          fields,
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
    const modal = $('#secret-modal');
    if (modal) modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !$('#secret-modal').hidden) closeModal();
    });
    // Bulk action bar
    const bulkDelete = $('#btn-bulk-delete');
    if (bulkDelete) bulkDelete.addEventListener('click', confirmBulkDelete);
    const bulkClear = $('#btn-bulk-clear');
    if (bulkClear) bulkClear.addEventListener('click', () => {
      selectedNames.clear();
      renderTable();
    });
    const selectAll = $('#secrets-select-all');
    if (selectAll) selectAll.addEventListener('change', () => {
      if (selectAll.checked) {
        for (const s of secrets) selectedNames.add(s.name);
      } else {
        selectedNames.clear();
      }
      renderTable();
    });
    // Eye toggle + file upload (event-delegated)
    wireEyeToggle();
    wireFileUpload();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { wireEvents(); init(); });
  } else {
    wireEvents();
    init();
  }
})();
