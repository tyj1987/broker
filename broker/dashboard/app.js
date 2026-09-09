// Secret Broker Dashboard - vanilla JS
// AI Actions 视图：登录（mTLS 或密码）→ 服务列表 → 快速动作 / 自定义请求 → 代理响应
// 所有 API 调用带 cookie（session token），密钥永不渲染到页面。

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, opts = {}, timeoutMs = 15000) {
  // Auto-stringify object bodies so callers can pass `body: { ... }` directly.
  // fetch() with a plain object sends "[object Object]" which breaks JSON.parse on server.
  const merged = { ...opts };
  if (merged.body && typeof merged.body === 'object' && !(merged.body instanceof FormData) && !(merged.body instanceof Blob) && !(merged.body instanceof ArrayBuffer)) {
    merged.body = JSON.stringify(merged.body);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(path, {
      credentials: 'include',
      signal: ctrl.signal,
      ...merged,
      headers: { 'Content-Type': 'application/json', ...(merged.headers || {}) },
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

function applyAdminVisibility(isAdmin) {
  document.querySelectorAll('.admin-only').forEach(el => { el.hidden = !isAdmin; });
}

function emitBrokerIdentity(ident) {
  identity = ident || null;
  window.__brokerIdentity = identity;
  window.__brokerIdentityReady = true;
  const el = $('#identity');
  if (el) {
    el.textContent = identity
      ? `CN=${identity.cn} · role=${identity.role}${identity.via === 'session' ? ' · session' : ''}`
      : '';
  }
  applyAdminVisibility(!!(identity && identity.role === 'admin'));
  document.dispatchEvent(new CustomEvent('broker:identity', { detail: identity }));
}

function subscribeBrokerIdentity(handler) {
  document.addEventListener('broker:identity', (e) => handler(e.detail));
  if (window.__brokerIdentityReady) handler(window.__brokerIdentity);
}

function showApp() {
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
}
function showLogin() {
  $('#app-view').hidden = true;
  $('#login-view').hidden = false;
  $('#login-password').value = '';
}

function fromBase64Url(value) {
  const padded = String(value).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const raw = atob(padded);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function toBase64Url(value) {
  if (value == null) return null;
  const bytes = new Uint8Array(value);
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function browserOptions(options) {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    user: options.user ? { ...options.user, id: fromBase64Url(options.user.id) } : undefined,
    allowCredentials: options.allowCredentials?.map((item) => ({ ...item, id: fromBase64Url(item.id) })),
    excludeCredentials: options.excludeCredentials?.map((item) => ({ ...item, id: fromBase64Url(item.id) })),
  };
}

function credentialJson(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: response.attestationObject ? toBase64Url(response.attestationObject) : undefined,
      authenticatorData: response.authenticatorData ? toBase64Url(response.authenticatorData) : undefined,
      signature: response.signature ? toBase64Url(response.signature) : undefined,
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
      transports: typeof response.getTransports === 'function' ? response.getTransports() : undefined,
    },
  };
}

async function beginWebAuthnLogin() {
  const client = $('#login-client').value.trim();
  if (!client || !window.PublicKeyCredential) throw new Error('此浏览器不支持安全密钥登录');
  const flow = await api('/api/v2/auth/webauthn/begin', { method: 'POST', body: { client } });
  const assertion = await navigator.credentials.get({ publicKey: browserOptions(flow.options) });
  if (!assertion) throw new Error('未取得安全密钥响应');
  await api('/api/v2/auth/webauthn/finish', {
    method: 'POST', body: { flow_id: flow.flow_id, response: credentialJson(assertion) },
  });
}

async function registerWebAuthn(label) {
  if (!window.PublicKeyCredential) throw new Error('此浏览器不支持安全密钥注册');
  const flow = await api('/api/v2/me/webauthn/registration/begin', { method: 'POST', body: { label } });
  const credential = await navigator.credentials.create({ publicKey: browserOptions(flow.options) });
  if (!credential) throw new Error('未取得安全密钥响应');
  return api('/api/v2/me/webauthn/registration/finish', {
    method: 'POST', body: { flow_id: flow.flow_id, response: credentialJson(credential) },
  });
}

window.brokerWebAuthn = { register: registerWebAuthn };

$('#btn-webauthn-login').addEventListener('click', async () => {
  const err = $('#login-error');
  err.hidden = true;
  try { await beginWebAuthnLogin(); await boot(); }
  catch (ex) { err.textContent = `安全密钥登录失败：${ex.message}`; err.hidden = false; }
});

// ---------- 登录 ----------
let _pendingMfaToken = null;  // server 返的 mfa_token，等用户输完 6 位 code 再提交
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  err.className = 'status-error';
  const client = $('#login-client').value.trim();
  const password = $('#login-password').value;
  const mfaCode = $('#login-mfa-code').value.trim();
  const mfaWrap = $('#login-mfa-wrap');
  const btn = e.target.querySelector('button[type=submit]');
  const originalLabel = _pendingMfaToken ? '验证 2FA / Verify' : '登录 / Login';
  btn.disabled = true; btn.textContent = '处理中...';
  try {
    if (_pendingMfaToken) {
      // 第二步：提交 2FA code
      await api('/api/v1/login/mfa', { method: 'POST', body: { mfa_token: _pendingMfaToken, code: mfaCode } });
      _pendingMfaToken = null;
      mfaWrap.hidden = true;
      $('#login-mfa-code').value = '';
      await boot();
      return;
    }
    // 第一步：密码登录
    const r1 = await api('/api/v1/login', { method: 'POST', body: { client, password } });
    if (r1 && r1.mfa_required) {
      // 需要 2FA：显示输入框，等用户填完再提交
      _pendingMfaToken = r1.mfa_token || null;
      mfaWrap.hidden = false;
      err.textContent = '需要二次验证 — 输 6 位 TOTP code 或恢复码 / 2FA required';
      err.className = 'status-warn';
      err.hidden = false;
      btn.disabled = false; btn.textContent = '验证 2FA / Verify';
      $('#login-mfa-code').focus();
      return;
    }
    // 没要求 2FA：直接 boot
    await boot();
  } catch (ex) {
    err.textContent = `登录失败：${ex.message}`;
    err.hidden = false;
    err.className = 'status-error';
  } finally {
    btn.disabled = false; btn.textContent = _pendingMfaToken ? '验证 2FA / Verify' : '登录 / Login';
  }
});

// 用户在 mfa 输入框按 Enter 也提交
$('#login-mfa-code').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); $('#login-form').requestSubmit(); }
});



$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/v1/logout', { method: 'POST' }); } catch {}
  // 清掉 MFA 状态，让下次登录从头开始
  _pendingMfaToken = null;
  const mfaWrap = $('#login-mfa-wrap');
  if (mfaWrap) mfaWrap.hidden = true;
  const mfaCode = $('#login-mfa-code');
  if (mfaCode) mfaCode.value = '';
  emitBrokerIdentity(null);
  showLogin();
});

// ---------- 身份 ----------
async function loadIdentity() {
  const ident = await api('/api/v1/identity');
  emitBrokerIdentity(ident);
}

// ---------- Tab 切换 ----------
function switchTab(name) {
  const btn = document.querySelector(`button[data-tab="${name}"]`);
  if (btn) btn.click();
  // emit for modules that listen
  document.dispatchEvent(new CustomEvent('tabchange', { detail: { tab: name } }));
}
$$('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'));
    $$('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const tabId = `tab-${btn.dataset.tab}`;
    const tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.classList.add('active');
    // Refresh data for tabs that need it (avoid stale data after admin write).
    // Actions / secrets / audit load lazily so login does not fan out 8 API calls.
    if (btn.dataset.tab === 'actions') loadServices();
    if (btn.dataset.tab === 'secrets') loadSecrets();
    if (btn.dataset.tab === 'audit') loadAudit();
    if (btn.dataset.tab === 'me') {
      // v3.0: 通知 me.js 加载 (用专属事件名避免和 tabchange 撞)
      document.dispatchEvent(new CustomEvent('me-tab-opened'));
    }
    // Notify modules
    document.dispatchEvent(new CustomEvent('tabchange', { detail: { tab: btn.dataset.tab } }));
  });
});

// ---------- v3.0 上线提示横幅 (v3.0 release banner，引导到 me tab) ----------
// 点击带 [data-switch-tab] 的链接 → 切到对应 tab (banner / 文案中可点的入口通用)
// Click delegation: any [data-switch-tab] link switches tab (used by v3 banner & future inline tips)
document.addEventListener('click', (e) => {
  const link = e.target.closest('[data-switch-tab]');
  if (!link) return;
  e.preventDefault();
  const name = link.getAttribute('data-switch-tab');
  if (!name) return;
  switchTab(name);
  // 滚到顶部，让用户看到新 tab 的内容 (scroll to top so user sees the new tab content)
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// 关闭按钮 + localStorage 持久化 (close button + localStorage persistence)
const V3_BANNER_KEY = 'v3-banner-dismissed';
function dismissV3Banner() {
  const banner = document.getElementById('v3-banner');
  if (banner) banner.hidden = true;
  try { localStorage.setItem(V3_BANNER_KEY, 'true'); } catch {}
}

// 启动时检查：用户已关过 → 不再显示 (on boot, hide if user already dismissed)
function initV3Banner() {
  let dismissed = false;
  try { dismissed = localStorage.getItem(V3_BANNER_KEY) === 'true'; } catch {}
  if (dismissed) {
    const banner = document.getElementById('v3-banner');
    if (banner) banner.hidden = true;
  }
  const closeBtn = document.getElementById('v3-banner-close');
  if (closeBtn) closeBtn.addEventListener('click', dismissV3Banner);
}

// app.js 是 <body> 末加载，DOM 通常已就绪；用 readyState 双保险
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initV3Banner);
} else {
  initV3Banner();
}

// ---------- Phase 2.2: Keyboard shortcuts ----------
// Style: Gmail-like two-key sequences. `g h` = go home, `g a` = go actions, etc.
// `?` shows help. `Esc` closes any open modal/help.
let _pendingG = false;
let _gTimeout = null;
const KEY_MAP = {
  'h': 'home',
  'r': 'approvals',
  'a': 'actions',
  's': 'secrets',
  'u': 'audit',
  'd': 'docs',
  'k': 'admin-secrets',
  'p': 'admin-services',
  'c': 'admin-clients',
};
document.addEventListener('keydown', (e) => {
  // Don't interfere with typing in inputs
  const t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'Escape') {
    // Close any open modal or help
    const help = document.querySelector('#kb-help');
    if (help) { help.remove(); return; }
    document.querySelectorAll('.modal:not([hidden])').forEach(m => m.hidden = true);
    return;
  }
  if (e.key === '?' || (e.shiftKey && e.key === '/')) {
    e.preventDefault();
    showHelp();
    return;
  }
  if (_pendingG) {
    _pendingG = false;
    clearTimeout(_gTimeout);
    const target = KEY_MAP[e.key.toLowerCase()];
    if (target) {
      e.preventDefault();
      switchTab(target);
    }
    return;
  }
  if (e.key === 'g') {
    _pendingG = true;
    _gTimeout = setTimeout(() => { _pendingG = false; }, 1500);
  }
});

function showHelp() {
  if (document.querySelector('#kb-help')) return;
  const div = document.createElement('div');
  div.id = 'kb-help';
  div.className = 'kb-help';
  div.innerHTML = `
    <div class="kb-help-card">
      <h3>键盘快捷键 / Keyboard shortcuts</h3>
      <table>
        <tr><td><kbd>g</kbd> <kbd>h</kbd></td><td>跳到首页 / Home</td></tr>
        <tr><td><kbd>g</kbd> <kbd>a</kbd></td><td>跳到动作 / Actions</td></tr>
        <tr><td><kbd>g</kbd> <kbd>s</kbd></td><td>跳到密钥 / Secrets</td></tr>
        <tr><td><kbd>g</kbd> <kbd>u</kbd></td><td>跳到审计 / Audit</td></tr>
        <tr><td><kbd>g</kbd> <kbd>d</kbd></td><td>跳到文档 / Docs</td></tr>
        <tr><td><kbd>g</kbd> <kbd>k</kbd></td><td>跳到密钥管理 / Manage</td></tr>
        <tr><td><kbd>g</kbd> <kbd>p</kbd></td><td>跳到服务管理 / Services</td></tr>
        <tr><td><kbd>g</kbd> <kbd>c</kbd></td><td>跳到设备管理 / Devices</td></tr>
        <tr><td><kbd>Esc</kbd></td><td>关闭弹窗 / Close modal</td></tr>
      </table>
      <p class="muted">在输入框里按这些键不会触发。</p>
      <button class="btn btn-sm" id="kb-help-close">关闭 / Close</button>
    </div>
  `;
  document.body.appendChild(div);
  document.querySelector('#kb-help-close')?.addEventListener('click', () => div.remove());
  // close on backdrop click
  div.addEventListener('click', (ev) => { if (ev.target === div) div.remove(); });
}

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

  // v3.1 M5.5: service 依赖的 secret 健康度 badge
  // 复用 healthcheck 5 维 status 颜色 (.hc-badge)
  let secretBadge = '';
  if (svc.token_secret) {
    if (svc.secret_health) {
      const sh = svc.secret_health;
      // secret_health.status 是 healthcheck 5 维之一
      const latency = sh.latency_ms != null ? ` ${sh.latency_ms}ms` : '';
      secretBadge = `<span class="hc-badge ${escapeHtml(sh.status)}" title="${escapeHtml(sh.detail || '')}">🔑 ${escapeHtml(svc.token_secret)}: ${escapeHtml(sh.status)}${latency}</span>`;
    } else {
      // 配置了 token_secret 但没 healthcheck 数据
      secretBadge = `<span class="hc-badge skipped" title="no healthcheck data yet">🔑 ${escapeHtml(svc.token_secret)}: unknown</span>`;
    }
  }

  const badges = `
    <span class="badge badge-type">${escapeHtml(svc.type)}</span>
    ${svc.allowed
      ? '<span class="badge badge-ok">可调用</span>'
      : '<span class="badge badge-denied">未授权</span>'}
    ${svc.region ? `<span class="badge badge-type">${escapeHtml(svc.region)}</span>` : ''}
    ${secretBadge}`;

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
  const limitEl = $('#audit-limit') || $('#af-limit');
  const limit = limitEl ? (limitEl.value || 50) : 50;
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

$('#btn-audit-refresh').addEventListener('click', loadAudit);

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
    for (const entry of list) {
      // /api/v1/secrets may return either:
      // - string array (non-admin or before Phase 2)
      // - object array (admin: {name, type, description, ...})
      const name = typeof entry === 'string' ? entry : entry.name;
      const desc = typeof entry === 'object' ? (entry.description || '') : '';
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><code>${escapeHtml(name)}</code>${desc ? `<br><span class="muted" style="font-size:11px">${escapeHtml(desc)}</span>` : ''}</td>
        <td><button class="btn btn-sm" data-act="show" data-name="${escapeHtml(name)}">显示 / Show</button>
            <button class="btn btn-sm" data-act="copy" data-name="${escapeHtml(name)}">复制 / Copy</button></td>`;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-name]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (btn.dataset.act === 'show') showSecretValue(btn.dataset.name, btn);
        else if (btn.dataset.act === 'copy') copySecretValue(btn.dataset.name, btn);
      });
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="2" class="status-error">${escapeHtml(e.message)}</td></tr>`;
  }
}

async function showSecretValue(name, btn) {
  const oldText = btn.textContent;
  btn.disabled = true; btn.textContent = '...';
  try {
    const r = await api('/api/v1/secrets/resolve', { method: 'POST', body: JSON.stringify({ name }) });
    showSecretModal(name, r);
    btn.textContent = oldText;
  } catch (e) {
    alert(`Resolve 失败: ${e.message}`);
    btn.textContent = oldText;
  } finally {
    btn.disabled = false;
  }
}

async function copySecretValue(name, btn) {
  const oldText = '复制 / Copy';
  btn.disabled = true; btn.textContent = '...';
  try {
    const r = await api('/api/v1/secrets/resolve', { method: 'POST', body: JSON.stringify({ name }) });
    // Always copy JSON for multi-field secrets so user gets full context
    const toCopy = r.fields && Object.keys(r.fields).length > 1
      ? JSON.stringify(r.fields, null, 2)
      : r.value;
    try {
      await navigator.clipboard.writeText(toCopy);
      btn.textContent = '已复制 ✓';
      setTimeout(() => { btn.textContent = oldText; btn.disabled = false; }, 1500);
      return;
    } catch (clipErr) {
      // Clipboard API often fails in non-HTTPS or non-focused contexts.
      // Show the manual-copy fallback modal, but re-enable the button so the
      // user can also retry the clipboard API from the modal's own "再试一次" button.
      showSecretModal(name, r, toCopy);
      btn.textContent = oldText;
      btn.disabled = false;
      return;
    }
  } catch (e) {
    alert(`Resolve 失败: ${e.message}`);
    btn.textContent = oldText;
    btn.disabled = false;
  }
}

function showSecretModal(name, resolveResult, preselectedForCopy) {
  // Reuse the secret-modal for displaying the value (with select+copy)
  const modal = $('#secret-modal');
  const title = $('#secret-modal-title');
  const f = $('#secret-form');
  f.reset();
  $('#sf-name').value = name;
  $('#sf-name').disabled = true;
  $('#sf-type').value = resolveResult.type || 'custom';
  $('#sf-type').disabled = true;
  $('#sf-description').value = '(当前查看模式 — 无法编辑)';
  $('#sf-description').disabled = true;
  // Build display in fields-container (use .sf-field wrapper for consistency with edit mode)
  const container = $('#sf-fields-container');
  container.innerHTML = '';
  const fields = resolveResult.fields || {};
  const fieldNames = Object.keys(fields);
  for (const fname of fieldNames) {
    const val = fields[fname];
    const wrap = document.createElement('div');
    wrap.className = 'sf-field';
    wrap.dataset.field = fname;
    const isMulti = fieldNames.length > 1;
    const display = isMulti
      ? `<pre class="sf-display-value">${escapeHtml(String(val == null ? '' : val))}</pre>`
      : `<input type="text" value="${escapeHtml(String(val == null ? '' : val))}" readonly class="sf-display-value">`;
    wrap.innerHTML = `<div class="sf-field-label"><div class="sf-field-label-text">${escapeHtml(fname)}${isMulti ? '' : ' (只读)'}</div>${display}</div>`;
    container.appendChild(wrap);
  }
  // If clipboard failed, replace the field display with a prominent copy area
  // and pre-select the text so Ctrl+C / Cmd+C copies immediately.
  const errEl = $('#sf-error');
  if (preselectedForCopy) {
    container.innerHTML = `
      <div class="sf-field" style="grid-column: 1 / -1">
        <div class="sf-field-label">
          <div class="sf-field-label-text">剪贴板被浏览器拦截 — 请手动复制 / Clipboard blocked — copy manually</div>
          <textarea id="copy-fallback" readonly rows="10"
            style="width:100%;font-family:var(--mono);font-size:13px;padding:10px;border:1px solid var(--border);border-radius:4px;background:#0a0a0a;color:#e0e0e0"
            onclick="this.select();" onfocus="this.select();">${escapeHtml(preselectedForCopy)}</textarea>
          <div class="hint" style="margin-top:6px">
            <button type="button" class="btn btn-sm" id="btn-retry-copy">再试一次复制 / Retry clipboard</button>
            <button type="button" class="btn btn-sm" id="btn-select-all">全选 / Select all</button>
          </div>
        </div>
      </div>`;
    errEl.hidden = true;
    title.textContent = `复制 / Copy: ${name}`;
    // Auto-select the textarea contents after the modal renders
    setTimeout(() => {
      const ta = $('#copy-fallback');
      if (ta) { ta.focus(); ta.select(); }
      // Wire up the action buttons
      const retry = $('#btn-retry-copy');
      if (retry) retry.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(preselectedForCopy);
          retry.textContent = '已复制 ✓ / Copied!';
          setTimeout(() => closeSecretModalClean(), 1000);
        } catch (e) {
          retry.textContent = '还是不行 — 用全选 / Still blocked — use select all';
        }
      });
      const sel = $('#btn-select-all');
      if (sel) sel.addEventListener('click', () => {
        const ta = $('#copy-fallback');
        if (ta) { ta.focus(); ta.select(); }
      });
    }, 50);
  } else {
    errEl.hidden = true;
    title.textContent = `查看密钥 / View: ${name}`;
  }
  // Hide save button (this is view mode); cancel becomes "Close"
  $('#btn-save-secret').style.display = 'none';
  $('#btn-cancel-secret').textContent = '关闭 / Close';
  modal.hidden = false;
}

function closeSecretModalClean() {
  const modal = $('#secret-modal');
  modal.hidden = true;
  $('#sf-name').disabled = false;
  $('#sf-type').disabled = false;
  $('#sf-description').disabled = false;
  $('#btn-save-secret').style.display = '';
  $('#btn-cancel-secret').textContent = '取消 / Cancel';
  $('#sf-fields-container').innerHTML = '';
  $('#sf-error').hidden = true;
}

$('#btn-refresh-secrets').addEventListener('click', loadSecrets);

// ---------- 启动 ----------
async function boot() {
  let ident;
  try {
    ident = await api('/api/v1/identity');
  } catch (e) {
    // 无有效会话 → 留在登录页
    emitBrokerIdentity(null);
    showLogin();
    return;
  }
  // 身份事件立刻显示 admin Tab；不要再轮询 #identity 文本（30s 窗口会漏掉登录）。
  emitBrokerIdentity(ident);
  showApp();
  if (location.pathname === '/approvals') switchTab('approvals');
}

boot();
