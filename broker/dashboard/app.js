// Secret Broker Dashboard - vanilla JS
// AI Actions 视图：登录（mTLS 或密码）→ 服务列表 → 快速动作 / 自定义请求 → 代理响应
// 所有 API 调用带 cookie（session token），密钥永不渲染到页面。

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, opts = {}, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(path, {
      credentials: 'include',
      signal: ctrl.signal,
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
  } catch (ex) {
    if (ex && ex.name === 'AbortError') {
      const err = new Error(`请求超时（${timeoutMs / 1000}s），请检查网络后重试`);
      err.status = 0;
      throw err;
    }
    throw ex;
  } finally {
    clearTimeout(timer);
  }
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = typeof body === 'string' ? body : (body.error || JSON.stringify(body));
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return body;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

let identity = null;
let currentServices = [];

function showApp() {
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
}
function showLogin() {
  $('#app-view').hidden = true;
  $('#login-view').hidden = false;
  $('#login-password').value = '';
}

// ---------- 登录 ----------
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  const client = $('#login-client').value.trim();
  const password = $('#login-password').value;
  const btn = e.target.querySelector('button[type=submit]');
  btn.disabled = true; btn.textContent = '登录中...';
  try {
    await api('/api/v1/login', { method: 'POST', body: JSON.stringify({ client, password }) });
    await boot();
  } catch (ex) {
    err.textContent = `登录失败：${ex.message}`;
    err.hidden = false;
  } finally {
    btn.disabled = false; btn.textContent = '登录 / Login';
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/v1/logout', { method: 'POST' }); } catch {}
  showLogin();
});

// ---------- 身份 ----------
async function loadIdentity() {
  identity = await api('/api/v1/identity');
  $('#identity').textContent = `CN=${identity.cn} · role=${identity.role}${identity.via === 'session' ? ' · session' : ''}`;
}

// ---------- Tab 切换 ----------
$$('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'));
    $$('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $(`#tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ---------- 服务列表（AI Actions 核心） ----------
async function loadServices() {
  const r = await api('/api/v1/services');
  currentServices = r.services || [];
  const wrap = $('#services');
  if (currentServices.length === 0) {
    wrap.innerHTML = '<div class="card"><p class="muted">（还没有配置任何服务）</p></div>';
    return;
  }
  wrap.innerHTML = '';
  for (const svc of currentServices) wrap.appendChild(renderServiceCard(svc));
  bindServiceEvents(wrap);
}

function renderServiceCard(svc) {
  const card = document.createElement('div');
  card.className = 'card service-card';
  card.dataset.service = svc.name;

  const badges = `
    <span class="badge badge-type">${escapeHtml(svc.type)}</span>
    ${svc.allowed
      ? '<span class="badge badge-ok">可调用</span>'
      : '<span class="badge badge-denied">未授权</span>'}
    ${svc.region ? `<span class="badge badge-type">${escapeHtml(svc.region)}</span>` : ''}`;

  const actionsHtml = (svc.actions || []).map((a, i) =>
    `<button class="btn btn-sm btn-action" data-svc="${escapeHtml(svc.name)}" data-idx="${i}">${escapeHtml(a.label || a.path || '动作')}</button>`
  ).join('');

  card.innerHTML = `
    <div class="service-head">
      <div>
        <h3 class="service-name">${escapeHtml(svc.name)}</h3>
        <p class="service-desc">${escapeHtml(svc.description || svc.upstream || '')}</p>
      </div>
      <div class="badges">${badges}</div>
    </div>
    ${actionsHtml ? `<div class="quick-actions"><span class="muted">快速动作：</span>${actionsHtml}</div>` : ''}
    <details class="custom-form">
      <summary>自定义请求 / Custom request</summary>
      <div class="form-row">
        <label>Method
          <select class="cf-method">
            ${['GET', 'POST', 'PATCH', 'PUT', 'DELETE'].map(m => `<option>${m}</option>`).join('')}
          </select>
        </label>
        <label class="grow">Path
          <input class="cf-path" type="text" placeholder="/user" value="/">
        </label>
      </div>
      <div class="form-row">
        <label class="grow">Query (JSON, 可选)
          <input class="cf-query" type="text" placeholder='{"per_page":"5"}' value="">
        </label>
      </div>
      <div class="form-row">
        <label class="grow">Headers (JSON, 可选)
          <input class="cf-headers" type="text" placeholder='{"Accept":"application/json"}' value="">
        </label>
      </div>
      <div class="form-row">
        <label class="grow">Body (JSON, 可选)
          <textarea class="cf-body" rows="3" placeholder='{"key":"value"}'></textarea>
        </label>
      </div>
      <div class="form-row">
        <button class="btn btn-primary btn-sm cf-send" data-svc="${escapeHtml(svc.name)}">发送 / Send</button>
        <span class="muted">broker 服务端注入密钥后转发，响应不落此页以外。</span>
      </div>
    </details>
  `;
  return card;
}

function bindServiceEvents(container) {
  // 快速动作
  container.querySelectorAll('.btn-action').forEach(btn => {
    btn.addEventListener('click', async () => {
      const svc = currentServices.find(s => s.name === btn.dataset.svc);
      const action = (svc && svc.actions[+btn.dataset.idx]) || null;
      if (!action) return;
      const label = action.label || action.path;
      const old = btn.textContent;
      btn.textContent = '调用中...';
      try {
        await runProxy(svc.name, {
          method: action.method || 'GET',
          path: action.path || '/',
          query: action.query || undefined,
          headers: action.headers || undefined,
          body: action.body || undefined,
        });
      } finally {
        btn.textContent = old;
      }
    });
  });
  // 自定义请求
  container.querySelectorAll('.cf-send').forEach(btn => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.service-card');
      const svcName = btn.dataset.svc;
      const old = btn.textContent;
      let payload;
      try {
        payload = {
          method: card.querySelector('.cf-method').value,
          path: card.querySelector('.cf-path').value.trim() || '/',
          query: parseJsonField(card.querySelector('.cf-query').value),
          headers: parseJsonField(card.querySelector('.cf-headers').value),
          body: parseJsonField(card.querySelector('.cf-body').value),
        };
      } catch (ex) {
        showResponse(svcName, null, ex.message, true);
        return;
      }
      btn.textContent = '发送中...';
      try {
        await runProxy(svcName, payload);
      } finally {
        btn.textContent = old;
      }
    });
  });
}

function parseJsonField(s) {
  if (!s || !s.trim()) return undefined;
  return JSON.parse(s); // 抛错由调用方捕获
}

// ---------- 代理调用 ----------
async function runProxy(svcName, payload) {
  const t0 = performance.now();
  try {
    // 代理要转发到外部 API，可能较慢，给 90s
    const r = await api(`/api/v1/proxy/${encodeURIComponent(svcName)}`, { method: 'POST', body: JSON.stringify(payload) }, 90000);
    showResponse(svcName, r, null, false, Math.round(performance.now() - t0), payload);
  } catch (ex) {
    showResponse(svcName, null, ex.message, true, Math.round(performance.now() - t0), payload);
  }
}

function showResponse(svcName, body, error, isError, latency, payload) {
  const panel = $('#response-panel');
  panel.hidden = false;
  $('#resp-title').textContent = `${svcName} · ${payload ? `${payload.method} ${payload.path}` : '请求'}`;
  const statusEl = $('#resp-status');
  if (isError) {
    statusEl.textContent = error && /^\d{3}$/.test(error.split(' ')[0]) ? error.split(' ')[0] : 'ERR';
    statusEl.className = 'badge badge-denied';
  } else {
    statusEl.textContent = 'OK';
    statusEl.className = 'badge badge-ok';
  }
  $('#resp-latency').textContent = latency != null ? `${latency}ms` : '-';
  const bodyEl = $('#resp-body');
  if (error) {
    bodyEl.textContent = error;
  } else if (typeof body === 'string') {
    bodyEl.textContent = body;
  } else {
    try {
      bodyEl.textContent = typeof body === 'object' ? JSON.stringify(body, null, 2) : String(body);
    } catch {
      bodyEl.textContent = String(body);
    }
  }
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

$('#btn-close-response').addEventListener('click', () => {
  $('#response-panel').hidden = true;
});

// ---------- 审计 ----------
async function loadAudit() {
  const limit = $('#audit-limit').value || 50;
  const tbody = $('#audit-table tbody');
  tbody.innerHTML = '<tr><td colspan="6">加载中...</td></tr>';
  try {
    const r = await api(`/api/v1/audit?limit=${limit}`);
    const events = r.events || [];
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">（无审计事件）</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const e of events) {
      const target = e.secret || (e.service ? `${e.service}${e.path || ''}` : `${e.method || ''} ${e.path || ''}`);
      const latency = e.latency_ms ? `${e.latency_ms}ms` : '-';
      const status = e.status || e.upstream_status || '-';
      const cls = e.status === 'denied' ? 'status-denied'
                : (e.upstream_status >= 400 || e.status === 'error' || e.status === 'not_found') ? 'status-error'
                : 'status-ok';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml((e.ts || '').replace('T', ' ').slice(0, 19))}</td>
        <td>${escapeHtml(e.cn || '-')}</td>
        <td>${escapeHtml(e.action || '-')}</td>
        <td><code>${escapeHtml(target || '-')}</code></td>
        <td class="${cls}">${escapeHtml(String(status))}</td>
        <td>${escapeHtml(latency)}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="status-error">${escapeHtml(e.message)}</td></tr>`;
  }
}

$('#btn-refresh-audit').addEventListener('click', loadAudit);

// ---------- 密钥列表 ----------
async function loadSecrets() {
  const tbody = $('#secrets-table tbody');
  tbody.innerHTML = '<tr><td colspan="2">加载中...</td></tr>';
  try {
    const r = await api('/api/v1/secrets');
    const list = r.secrets || [];
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" class="muted">（无可访问的密钥）</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const name of list) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><code>${escapeHtml(name)}</code></td>
        <td><button class="btn btn-sm" data-name="${escapeHtml(name)}">resolve</button></td>`;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-name]').forEach(btn => {
      btn.addEventListener('click', () => resolveSecret(btn.dataset.name, btn));
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="2" class="status-error">${escapeHtml(e.message)}</td></tr>`;
  }
}

async function resolveSecret(name, btn) {
  btn.disabled = true; btn.textContent = '...';
  try {
    const r = await api('/api/v1/secrets/resolve', { method: 'POST', body: JSON.stringify({ name }) });
    const masked = r.value.length > 8 ? r.value.slice(0, 4) + '****' + r.value.slice(-4) : '****';
    btn.textContent = `已取 (${masked})`;
    if (confirm(`密钥 ${name} 已取到 (${masked})\n完整值复制到剪贴板吗？（会写入剪贴板，建议用完清除）`)) {
      await navigator.clipboard.writeText(r.value);
    }
  } catch (e) {
    btn.textContent = '失败';
    alert(`Resolve 失败: ${e.message}`);
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = 'resolve'; }, 3000);
  }
}

$('#btn-refresh-secrets').addEventListener('click', loadSecrets);

// ---------- 启动 ----------
async function boot() {
  let ident;
  try {
    ident = await api('/api/v1/identity');
  } catch (e) {
    // 无有效会话 → 留在登录页
    showLogin();
    return;
  }
  identity = ident;
  $('#identity').textContent = `CN=${identity.cn} · role=${identity.role}${identity.via === 'session' ? ' · session' : ''}`;
  // 身份有效：立即进入主视图。后续数据加载失败只显示错误，不把用户踢回登录页。
  showApp();
  loadServices().catch(e => {
    const wrap = $('#services');
    if (wrap) wrap.innerHTML = `<div class="card"><p class="status-error">服务列表加载失败：${escapeHtml(e.message)}</p></div>`;
  });
  loadAudit().catch(() => {});
  loadSecrets().catch(() => {});
}

boot();
