// broker/dashboard/api-keys.js — v3.0 M2-C API Key 管理
// 监听 'tabchange' 事件（detail.tab === 'api-keys'）→ loadKeys()
// 创建：POST /api/v1/api-keys → 弹窗一次性显示完整 key
// 撤销：DELETE /api/v1/api-keys/:id
// Usage: GET /api/v1/api-keys/:id/usage（admin only）
//
// 工具函数 $ / $$ / api() / escapeHtml() 来自 app.js（全局）。
// 复用 me.js 的 IIFE + 'use strict' 模式，零新依赖，纯 vanilla JS。

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const CATALOG_GROUPS = [
    ['#ak-catalog-services', '服务 / Services'],
    ['#ak-catalog-operations', '操作 / Operations'],
    ['#ak-catalog-accounts', '账户 / Accounts'],
    ['#ak-catalog-resources', '资源 / Resources'],
    ['#ak-catalog-environments', '环境 / Environments'],
    ['#ak-catalog-secrets', '密钥引用 / Secret refs'],
  ];

  function selectedValues(field) {
    return $$(`#ak-permission-picker input[name="${field}"]:checked`).map((input) => input.value);
  }

  function renderCatalog(catalog) {
    for (const [selector, title] of CATALOG_GROUPS) {
      const host = $(selector);
      if (!host) continue;
      const field = host.dataset.field;
      const values = Array.isArray(catalog?.[field.replace('allowed_', '')])
        ? catalog[field.replace('allowed_', '')]
        : [];
      host.innerHTML = '';
      const heading = document.createElement('p');
      heading.className = 'hint';
      heading.textContent = title;
      host.appendChild(heading);
      if (values.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = '没有单独登记的项目。使用默认全部权限时，这一项不按名单拦截。';
        host.appendChild(empty);
        continue;
      }
      for (const value of values) {
        const label = document.createElement('label');
        label.style.display = 'block';
        label.style.margin = '4px 0';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.name = field;
        input.value = value;
        input.checked = true;
        label.appendChild(input);
        label.appendChild(document.createTextNode(' ' + value));
        host.appendChild(label);
      }
    }
  }

  async function loadCatalog() {
    try {
      const response = await api('/api/v1/api-keys/permission-catalog');
      renderCatalog(response.catalog || {});
    } catch (ex) {
      setStatus('#create-key-status', '权限名单加载失败: ' + (ex.message || ex), 'err');
    }
  }

  function setPickerVisible(visible) {
    const picker = $('#ak-permission-picker');
    if (picker) picker.hidden = !visible;
  }

  // ---- 加载列表 ----
  async function loadKeys() {
    const tbody = $('#api-keys-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7" class="muted">加载中… / loading…</td></tr>';
    try {
      const r = await api('/api/v1/api-keys');
      const keys = r.keys || [];
      if (keys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">还没有 API Key。点上方表单创建一个。</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      for (const k of keys) {
        tbody.appendChild(renderRow(k));
      }
    } catch (ex) {
      tbody.innerHTML = '<tr><td colspan="7" style="color:#e74c3c">加载失败: ' + escapeHtml(String(ex.message || ex)) + '</td></tr>';
      console.error('loadKeys failed', ex);
    }
  }

  // 状态判断: active / revoked / expired
  function computeStatus(k) {
    if (k.revoked) return { label: '已撤销 / revoked', cls: 'badge-denied' };
    if (k.expires_at && new Date(k.expires_at) < new Date()) return { label: '已过期 / expired', cls: 'badge-denied' };
    return { label: 'active / 有效', cls: 'badge-ok' };
  }

  function renderRow(k) {
    const tr = document.createElement('tr');
    const status = computeStatus(k);
    const lastUsed = k.last_used_at || '(未使用 / never)';
    const expires = k.expires_at || '永久 / never';
    const scopes = (k.scopes || []).join(', ') || '—';
    // 操作按钮: 撤销（active 状态才显示）+ 查看 usage（admin only）
    const actions = [];
    if (!k.revoked) {
      actions.push(`<button type="button" class="btn btn-sm btn-danger" data-action="revoke" data-id="${escapeHtml(k.id)}" data-label="${escapeHtml(k.name)}">撤销 / Revoke</button>`);
    }
    actions.push(`<button type="button" class="btn btn-sm" data-action="usage" data-id="${escapeHtml(k.id)}" data-label="${escapeHtml(k.name)}" data-fp="${escapeHtml(k.fingerprint_prefix || '')}">查看 usage</button>`);
    tr.innerHTML =
      '<td><code>' + escapeHtml(k.name) + '</code></td>' +
      '<td><code class="small">' + escapeHtml(k.fingerprint_prefix || (k.id || '').slice(0, 8) + '...') + '</code></td>' +
      '<td><code class="small">' + escapeHtml(scopes) + '</code></td>' +
      '<td><code class="small">' + escapeHtml(lastUsed) + '</code></td>' +
      '<td><code class="small">' + escapeHtml(expires) + '</code></td>' +
      '<td><span class="badge ' + status.cls + '">' + status.label + '</span></td>' +
      '<td>' + actions.join(' ') + '</td>';
    return tr;
  }

  // ---- 创建 ----
  async function submitCreate(ev) {
    ev.preventDefault();
    const form = ev.target;
    setStatus('#create-key-status', '创建中…', '');

    const name = (form.name.value || '').trim();
    const scopes = [];
    if (form.scope_operations.checked) scopes.push('operations:execute');
    if (form.scope_resolve.checked) scopes.push('secrets:resolve');
    if (form.scope_proxy.checked) scopes.push('services:proxy');
    if (scopes.length === 0) {
      setStatus('#create-key-status', '❌ 至少勾选一个 scope', 'err');
      return;
    }
    const grantRegistered = $('#ak-grant-registered')?.checked === true;
    const operationConstraints = grantRegistered ? {} : {
      allowed_services: selectedValues('allowed_services'),
      allowed_operations: selectedValues('allowed_operations'),
      allowed_accounts: selectedValues('allowed_accounts'),
      allowed_resources: selectedValues('allowed_resources'),
      allowed_environments: selectedValues('allowed_environments'),
      allowed_secrets: selectedValues('allowed_secrets'),
    };
    if (!grantRegistered && scopes.includes('operations:execute')) {
      const missing = ['allowed_services', 'allowed_operations', 'allowed_accounts', 'allowed_environments']
        .filter((field) => operationConstraints[field].length === 0);
      if (missing.length > 0) {
        setStatus('#create-key-status', `❌ 请至少勾选一项，或改回默认全部权限: ${missing.join(', ')}`, 'err');
        return;
      }
      if (Object.values(operationConstraints).flat().includes('*')) {
        setStatus('#create-key-status', '❌ 不允许手填通配符；请勾选列出的权限，或使用默认全部权限', 'err');
        return;
      }
    }
    const verify = (form.verify.value || '').trim();
    if (!verify) {
      setStatus('#create-key-status', '❌ 二次验证必填 (TOTP code 或 password)', 'err');
      return;
    }
    const ttlRaw = form.ttl_seconds.value;
    const body = {
      name,
      scopes,
      verify,
      ...operationConstraints,
      ...(grantRegistered ? { use_registered_permissions: true } : {}),
    };
    if (ttlRaw !== '0') body.ttl_seconds = parseInt(ttlRaw, 10);

    try {
      const r = await api('/api/v1/api-keys', { method: 'POST', body: JSON.stringify(body) });
      // r = { key: { id, name, scopes, expires_at, ... }, secret: 'mb_test_xxx...' }
      showNewKeyModal(r.key, r.secret);
      setStatus('#create-key-status', '✅ 已创建！请立即复制完整 key', 'ok');
      form.reset();
      // TTL 回到默认 7d
      $('#ak-ttl').value = '604800';
      $('#ak-scope-operations').checked = true;
      $('#ak-scope-resolve').checked = false;
      $('#ak-scope-proxy').checked = false;
      const grantAll = $('#ak-grant-registered');
      if (grantAll) grantAll.checked = true;
      setPickerVisible(false);
      $('#ak-verify').value = '';  // 安全: 清空 verify 字段
      await loadKeys();
    } catch (ex) {
      setStatus('#create-key-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  function showNewKeyModal(key, secret) {
    $('#ak-newkey-label').textContent = key.name;
    $('#ak-newkey-scopes').textContent = (key.scopes || []).join(', ');
    $('#ak-newkey-expires').textContent = key.expires_at || '永久 / never';
    $('#ak-newkey-secret').value = secret;
    $('#ak-newkey-modal').hidden = false;
  }

  function closeNewKeyModal() {
    $('#ak-newkey-modal').hidden = true;
    // 安全: 关闭后清空 textarea
    $('#ak-newkey-secret').value = '';
  }

  function copyNewKey() {
    const ta = $('#ak-newkey-secret');
    if (!ta) return;
    ta.select();
    try {
      // execCommand 兼容老浏览器; modern 用 navigator.clipboard
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ta.value).catch(() => document.execCommand('copy'));
      } else {
        document.execCommand('copy');
      }
      const btn = $('#btn-copy-newkey');
      const old = btn.textContent;
      btn.textContent = '✓ 已复制 / Copied';
      setTimeout(() => { btn.textContent = old; }, 1500);
    } catch (e) {
      console.warn('copy failed', e);
    }
  }

  // ---- 撤销 ----
  async function revokeKey(id, label) {
    if (!confirm(`确认撤销 API Key "${label}"?\n\n此操作不可恢复。该 key 立即失效。\n\nRevoke "${label}"? This cannot be undone.`)) return;
    try {
      await api('/api/v1/api-keys/' + id, { method: 'DELETE' });
      await loadKeys();
    } catch (ex) {
      alert('撤销失败: ' + (ex.message || ex));
    }
  }

  // ---- 查看 usage ----
  async function loadUsage(id, label, fp) {
    $('#ak-usage-label').textContent = label;
    $('#ak-usage-fp').textContent = fp || '';
    $('#ak-usage-tbody').innerHTML = '<tr><td colspan="5" class="muted">加载中…</td></tr>';
    $('#ak-usage-modal').hidden = false;
    try {
      const r = await api('/api/v1/api-keys/' + id + '/usage?limit=50');
      const events = r.events || [];
      if (events.length === 0) {
        $('#ak-usage-tbody').innerHTML = '<tr><td colspan="5" class="muted">还没有使用记录 / no usage yet</td></tr>';
        return;
      }
      $('#ak-usage-tbody').innerHTML = '';
      for (const e of events) {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td><code class="small">' + escapeHtml(e.ts || '') + '</code></td>' +
          '<td><code>' + escapeHtml(e.action || '') + '</code></td>' +
          '<td><code>' + escapeHtml(e.method || '') + '</code></td>' +
          '<td><code class="small">' + escapeHtml(e.path || e.upstream || '') + '</code></td>' +
          '<td><code>' + escapeHtml(String(e.status || '')) + '</code></td>';
        $('#ak-usage-tbody').appendChild(tr);
      }
    } catch (ex) {
      $('#ak-usage-tbody').innerHTML = '<tr><td colspan="5" style="color:#e74c3c">加载失败: ' + escapeHtml(String(ex.message || ex)) + '</td></tr>';
    }
  }

  // ---- 委托事件: 表格里的 revoke / usage 按钮 ----
  function onTableClick(ev) {
    const btn = ev.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;
    const label = btn.dataset.label || id;
    if (action === 'revoke') revokeKey(id, label);
    else if (action === 'usage') loadUsage(id, label, btn.dataset.fp);
  }

  // ---- helpers ----
  function setStatus(sel, msg, cls) {
    const el = $(sel);
    if (!el) return;
    el.textContent = msg;
    el.className = 'status ' + (cls || '');
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // ---- 初始化 ----
  function init() {
    const form = $('#form-create-key');
    if (form) form.addEventListener('submit', submitCreate);
    const btnRefresh = $('#btn-refresh-keys');
    if (btnRefresh) btnRefresh.addEventListener('click', loadKeys);
    const tbody = $('#api-keys-tbody');
    if (tbody) tbody.addEventListener('click', onTableClick);
    const closeNew = $('#btn-close-newkey');
    if (closeNew) closeNew.addEventListener('click', closeNewKeyModal);
    const copyBtn = $('#btn-copy-newkey');
    if (copyBtn) copyBtn.addEventListener('click', copyNewKey);
    const closeUsage = $('#btn-close-usage');
    if (closeUsage) closeUsage.addEventListener('click', () => { $('#ak-usage-modal').hidden = true; });
    const grantAll = $('#ak-grant-registered');
    if (grantAll) {
      grantAll.addEventListener('change', () => {
        setPickerVisible(!grantAll.checked);
        if (!grantAll.checked) loadCatalog();
      });
    }
    const checkAll = $('#ak-check-all');
    if (checkAll) checkAll.addEventListener('click', () => {
      $$('#ak-permission-picker input[type="checkbox"]').forEach((input) => { input.checked = true; });
    });
    const checkNone = $('#ak-check-none');
    if (checkNone) checkNone.addEventListener('click', () => {
      $$('#ak-permission-picker input[type="checkbox"]').forEach((input) => { input.checked = false; });
    });

    // 监听 tabchange 事件（app.js 在切 tab 时 dispatch）
    document.addEventListener('tabchange', (ev) => {
      if (ev && ev.detail && ev.detail.tab === 'api-keys') {
        loadKeys();
        if ($('#ak-grant-registered')?.checked === false) loadCatalog();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
