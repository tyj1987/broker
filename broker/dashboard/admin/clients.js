// admin/clients.js — Phase 1.3: Clients (devices) management UI
// Lists clients, supports create / edit / delete / enroll (issue cert) /
// rotate / revoke / download bundle. The bundle is a zip with the secret
// key — never logged or persisted to localStorage.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentIdentity = null;
  let isAdmin = false;
  let clients = [];   // [{ name, role, cert_fingerprint_sha256, cert_present_on_disk, last_seen_ms_ago, ... }]
  let pkiWritable = true;  // false on production with read-only pki/
  let editingName = null;

  // ---- Bootstrap ----
  function init() {
    const subscribe = typeof subscribeBrokerIdentity === 'function'
      ? subscribeBrokerIdentity
      : (handler) => document.addEventListener('broker:identity', (e) => handler(e.detail));
    subscribe((ident) => {
      currentIdentity = ident;
      isAdmin = !!(ident && ident.role === 'admin');
      if (isAdmin) loadClients();
    });
    wireModal();
    wireBundleModal();
  }

  // ---- API ----
  async function loadClients() {
    if (!isAdmin) return;
    try {
      const r = await api('/api/v1/admin/clients');
      clients = r.clients || [];
      pkiWritable = r.pki_writable !== false;  // default to true if absent
      const banner = $('#pki-readonly-banner');
      if (banner) banner.hidden = pkiWritable;
      renderTable();
    } catch (ex) {
      showTableError(ex.message);
    }
  }
  async function createClient(payload) {
    return api('/api/v1/admin/clients', { method: 'POST', body: JSON.stringify(payload) });
  }
  async function updateClient(name, payload) {
    return api(`/api/v1/admin/clients/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(payload) });
  }
  async function deleteClient(name) {
    return api(`/api/v1/admin/clients/${encodeURIComponent(name)}`, { method: 'DELETE' });
  }
  async function enrollClient(name) {
    return api(`/api/v1/admin/clients/${encodeURIComponent(name)}/enrollment`, { method: 'POST', body: '{}' });
  }
  async function rotateClient(name) {
    return api(`/api/v1/admin/clients/${encodeURIComponent(name)}/rotate`, { method: 'POST', body: '{}' });
  }
  async function revokeClient(name) {
    return api(`/api/v1/admin/clients/${encodeURIComponent(name)}/revoke`, { method: 'POST', body: '{}' });
  }
  function downloadBundleUrl(name) {
    return `/api/v1/admin/clients/${encodeURIComponent(name)}/bundle`;
  }

  // ---- Render table ----
  function renderTable() {
    const tbody = $('#admin-clients-table tbody');
    if (!tbody) return;
    $('#admin-clients-count').textContent = clients.length ? `共 ${clients.length} 个` : '';
    if (clients.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">（还没有任何客户端）— 点右上角"+ 新增"添加第一个。</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const c of clients) {
      const tr = document.createElement('tr');
      const lastSeen = c.last_seen_ms_ago == null ? '—' : formatMs(c.last_seen_ms_ago);
      const fpShort = c.cert_fingerprint_sha256
        ? c.cert_fingerprint_sha256.split(':').slice(0, 3).join(':') + '...'
        : '<span class="muted-cell">无</span>';
      const certStatus = c.cert_present_on_disk
        ? '<span class="badge-ok">✓ 已签发</span>'
        : (c.cert_fingerprint_sha256 ? '<span class="badge-warn">⚠ 配置有 fp, 文件缺失</span>' : '<span class="muted-cell">未签发</span>');
      // When pki/ is read-only, disable buttons that would write a new cert.
      // Operator should use scripts/issue-client-cert.sh instead.
      const dis = (cond) => cond ? '' : 'disabled';
      const readonlyDis = pkiWritable ? '' : 'disabled';
      tr.innerHTML = `
        <td><strong>${esc(c.name)}</strong></td>
        <td><code>${esc(c.role)}</code></td>
        <td>${certStatus}</td>
        <td class="muted-cell" title="${esc(c.cert_fingerprint_sha256 || '')}">${fpShort}</td>
        <td class="muted-cell">${lastSeen}</td>
        <td class="muted-cell">${c.allow_password_login ? '是' : '否'}</td>
        <td class="row-actions">
          <button class="btn btn-sm" data-act="enroll" data-name="${esc(c.name)}" ${readonlyDis}>签发/补发</button>
          <button class="btn btn-sm" data-act="rotate" data-name="${esc(c.name)}" ${dis(c.cert_present_on_disk && pkiWritable)}>轮换</button>
          <button class="btn btn-sm" data-act="revoke" data-name="${esc(c.name)}" ${dis(c.cert_fingerprint_sha256)}>撤销</button>
          <button class="btn btn-sm" data-act="bundle" data-name="${esc(c.name)}" ${dis(c.cert_present_on_disk)}>下载</button>
          <button class="btn btn-sm btn-primary" data-act="edit" data-name="${esc(c.name)}">编辑</button>
          <button class="btn btn-sm btn-danger" data-act="delete" data-name="${esc(c.name)}">删除</button>
        </td>`;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const act = e.currentTarget.dataset.act;
        const name = e.currentTarget.dataset.name;
        if (act === 'edit') openEditModal(name);
        else if (act === 'delete') confirmDelete(name);
        else if (act === 'enroll') runEnroll(name);
        else if (act === 'rotate') runRotate(name);
        else if (act === 'revoke') confirmRevoke(name);
        else if (act === 'bundle') downloadBundle(name);
      });
    });
  }

  function showTableError(msg) {
    const tbody = $('#admin-clients-table tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="status-error">加载失败: ${esc(msg)}</td></tr>`;
  }

  // ---- Modal: create / edit ----
  function openCreateModal() {
    editingName = null;
    $('#client-modal-title').textContent = '新增客户端 / New Client';
    $('#cl-name').value = '';
    $('#cl-name').disabled = false;
    $('#cl-role').value = 'developer';
    $('#cl-allow-pw').checked = false;
    $('#cl-password').value = '';
    $('#cl-rate').value = '100/hour';
    $('#cl-description').value = '';
    $('#cl-allowed-resolve').value = '';
    $('#cl-allowed-proxy').value = '';
    $('#cl-error').hidden = true;
    $('#client-modal').hidden = false;
    setTimeout(() => $('#cl-name').focus(), 50);
  }

  async function openEditModal(name) {
    editingName = name;
    $('#client-modal-title').textContent = `编辑客户端 / Edit: ${name}`;
    $('#cl-name').value = name;
    $('#cl-name').disabled = true;
    try {
      const r = await api(`/api/v1/admin/clients/${encodeURIComponent(name)}`);
      $('#cl-role').value = r.role || 'developer';
      $('#cl-allow-pw').checked = !!r.allow_password_login;
      $('#cl-password').value = '';  // never show existing password
      $('#cl-rate').value = r.rate_limit || '100/hour';
      $('#cl-description').value = r.description || '';
      $('#cl-allowed-resolve').value = (r.allowed_resolve || []).join('\n');
      $('#cl-allowed-proxy').value = (r.allowed_proxy || [])
        .map(p => typeof p === 'string' ? p : (p.service ? p.service + (p.paths ? '  paths=' + JSON.stringify(p.paths) : '') : JSON.stringify(p)))
        .join('\n');
      $('#cl-error').hidden = true;
      $('#client-modal').hidden = false;
    } catch (e) {
      alert('加载失败 / Load failed: ' + e.message);
    }
  }

  function closeModal() {
    const modal = $('#client-modal');
    if (modal) modal.hidden = true;
    const title = $('#client-modal-title');
    if (title) title.textContent = '新增客户端 / New Client';
    editingName = null;
  }

  // ---- Save ----
  async function onSave() {
    const name = $('#cl-name').value.trim();
    const cfg = {
      name,
      role: $('#cl-role').value,
      allow_password_login: $('#cl-allow-pw').checked,
      rate_limit: $('#cl-rate').value.trim() || undefined,
      description: $('#cl-description').value.trim() || undefined,
      allowed_resolve: parseLines($('#cl-allowed-resolve').value),
      allowed_proxy: parseProxyLines($('#cl-allowed-proxy').value),
    };
    const pw = $('#cl-password').value;
    if (pw) cfg.password = pw;
    if (editingName && pw === '') {
      // Explicit "clear password" only if checkbox says "no password login".
      if (!cfg.allow_password_login) cfg.password = null;
    }
    if (!name) return showClientError('请填写客户端名 / Name required');
    try {
      if (editingName) await updateClient(editingName, cfg);
      else await createClient(cfg);
      closeModal();
      await loadClients();
    } catch (e) {
      showClientError(e.message || String(e));
    }
  }

  function parseLines(text) {
    return (text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  }
  function parseProxyLines(text) {
    return (text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(line => {
      // "service" or "service  paths=["^/.*"]"
      const m = line.match(/^(\S+)(?:\s+paths=(\{[^}]*\}|\[[^\]]*\]))?$/);
      if (!m) return line;
      let paths;
      try { paths = m[2] ? JSON.parse(m[2]) : undefined; } catch { paths = undefined; }
      return paths ? { service: m[1], paths } : m[1];
    });
  }

  function showClientError(msg) {
    const el = $('#cl-error');
    if (!el) { alert(msg); return; }
    el.textContent = msg;
    el.hidden = false;
  }

  // ---- Lifecycle actions ----
  async function confirmDelete(name) {
    if (!confirm(`确定删除客户端 ${name} ?\n将同时删除本地证书文件（不可恢复）。\nDelete client ${name}?`)) return;
    try {
      await deleteClient(name);
      await loadClients();
    } catch (e) {
      alert('删除失败 / Delete failed: ' + e.message);
    }
  }
  async function confirmRevoke(name) {
    if (!confirm(`确定撤销 ${name} 的证书？\n将立即从 broker 配置中移除指纹，设备下次连接会被拒。\nRevoke cert for ${name}?`)) return;
    try {
      await revokeClient(name);
      await loadClients();
    } catch (e) {
      alert('撤销失败 / Revoke failed: ' + e.message);
    }
  }

  async function runEnroll(name) {
    const btn = document.querySelector(`button[data-act="enroll"][data-name="${cssEsc(name)}"]`);
    if (btn) { btn.disabled = true; btn.textContent = '签发中…'; }
    try {
      const r = await enrollClient(name);
      showEnrollResult(r);
      await loadClients();
    } catch (e) {
      showEnrollResult({ ok: false, error: e.message });
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '签发/补发'; }
    }
  }
  async function runRotate(name) {
    if (!confirm(`轮换 ${name} 的证书？\n旧 cert 仍会保留在磁盘上直到自然过期，但 broker 只会接受新 cert。\nRotate ${name}?`)) return;
    const btn = document.querySelector(`button[data-act="rotate"][data-name="${cssEsc(name)}"]`);
    if (btn) { btn.disabled = true; btn.textContent = '轮换中…'; }
    try {
      const r = await rotateClient(name);
      showEnrollResult(r);
      await loadClients();
    } catch (e) {
      showEnrollResult({ ok: false, error: e.message });
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '轮换'; }
    }
  }

  function showEnrollResult(r) {
    const modal = $('#enroll-result-modal');
    const out = $('#enroll-result-body');
    if (!modal || !out) { alert(r.ok ? 'OK' : ('失败: ' + r.error)); return; }
    if (!r.ok) {
      out.innerHTML = `<div class="status-error">${esc(r.error || '未知错误')}</div>`;
    } else {
      // We show the cert and key in copyable textareas so the admin can
      // manually deliver them (or use the bundle download). NEVER log or
      // persist to localStorage from this code path.
      out.innerHTML = `
        <p class="status-ok">✓ 签发成功</p>
        <p class="hint"><strong>指纹 / Fingerprint:</strong> <code>${esc(r.fingerprint_sha256)}</code></p>
        <p class="hint" style="color:#b94545"><strong>⚠ ${esc(r.warning)}</strong></p>
        <label>证书 / Cert (PEM)
          <textarea id="enroll-cert" rows="6" readonly>${esc(r.cert_pem)}</textarea>
        </label>
        <label>私钥 / Key (PEM) — 一次性显示
          <textarea id="enroll-key" rows="8" readonly>${esc(r.key_pem)}</textarea>
        </label>
        <div class="modal-actions">
          <button class="btn" id="btn-copy-cert">复制证书</button>
          <button class="btn" id="btn-copy-key">复制私钥</button>
          <a class="btn btn-primary" href="${downloadBundleUrl(r.name)}" download="${r.name}-bundle.zip">下载 zip 安装包</a>
        </div>
      `;
      // Wire copy buttons (only after render)
      setTimeout(() => {
        const copy = async (id) => {
          const el = document.getElementById(id);
          if (!el) return;
          el.select();
          try { await navigator.clipboard.writeText(el.value); } catch {}
        };
        const a = $('#btn-copy-cert'); if (a) a.addEventListener('click', () => copy('enroll-cert'));
        const b = $('#btn-copy-key'); if (b) b.addEventListener('click', () => copy('enroll-key'));
      }, 0);
    }
    modal.hidden = false;
  }

  function closeEnrollResult() {
    const m = $('#enroll-result-modal');
    if (m) m.hidden = true;
  }

  function downloadBundle(name) {
    // Direct download. Browser will save the zip. Operator must deliver it
    // to the device out-of-band (it contains the secret key).
    const a = document.createElement('a');
    a.href = downloadBundleUrl(name);
    a.download = `${name}-bundle.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  // ---- Wire ----
  function wireModal() {
    const newBtn = $('#btn-new-client');
    if (newBtn) newBtn.addEventListener('click', openCreateModal);
    const refreshBtn = $('#btn-refresh-clients-admin');
    if (refreshBtn) refreshBtn.addEventListener('click', loadClients);
    const cancelBtn = $('#btn-cancel-client');
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
    const saveBtn = $('#btn-save-client');
    if (saveBtn) saveBtn.addEventListener('click', onSave);
    const modal = $('#client-modal');
    if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.hidden) closeModal();
    });
  }
  function wireBundleModal() {
    const close = $('#btn-close-enroll-result');
    if (close) close.addEventListener('click', closeEnrollResult);
    const modal = $('#enroll-result-modal');
    if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) closeEnrollResult(); });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.hidden) closeEnrollResult();
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
  function formatMs(ms) {
    if (ms < 60_000) return `${Math.floor(ms/1000)}s 前`;
    if (ms < 3_600_000) return `${Math.floor(ms/60_000)}m 前`;
    if (ms < 86_400_000) return `${Math.floor(ms/3_600_000)}h 前`;
    return `${Math.floor(ms/86_400_000)}d 前`;
  }

  // ---- Go ----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
