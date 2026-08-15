// dashboard/me.js — 我的资料 self-service
// Loaded after app.js. 任何已登录 client 都能用。

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let currentMe = null;
  let isAdmin = false;
  let totpPending = null;  // { secret, recovery_codes } — 暂存 setup 结果

  // ---- 加载 + 渲染 ----
  async function loadMe() {
    try {
      const r = await api('/api/v1/me');
      currentMe = r;
      render(r);
    } catch (ex) {
      console.error('loadMe failed', ex);
      const el = $('#me-tab');
      if (el) el.innerHTML = '<p style="color:#e74c3c">加载失败: ' + escapeHtml(String(ex.message || ex)) + '</p>';
    }
  }

  function render(me) {
    if (!me) return;
    $('#me-name').textContent = me.name;
    $('#me-role').textContent = me.role;
    $('#me-cn').textContent = me.cn;
    $('#me-allow-pw').textContent = me.allow_password_login ? '✅ 启用' : '❌ 禁用';
    $('#me-pw-set-at').textContent = me.password_set_at || '(无)';
    $('#me-cert-fp').textContent = me.cert_fingerprint_sha256 || '(无)';
    $('#me-cert-exp').textContent = me.cert_expires_at || '(无)';
    $('#me-cert-exp2').textContent = me.cert_expires_at || '(无)';
    $('#me-rate-limit').textContent = me.rate_limit;
    // 2FA 状态
    const totpEnabled = !!me.totp_enabled;
    $('#me-2fa').textContent = totpEnabled
      ? `✅ TOTP 启用 (剩 ${me.totp_recovery_codes_remaining} 个恢复码)`
      : '❌ 未启用 TOTP';
    // TOTP 视图切换
    if (totpPending) {
      $('#totp-disabled-view').hidden = true;
      $('#totp-pending-view').hidden = false;
      $('#totp-enabled-view').hidden = true;
    } else if (totpEnabled) {
      $('#totp-disabled-view').hidden = true;
      $('#totp-pending-view').hidden = true;
      $('#totp-enabled-view').hidden = false;
      $('#totp-enabled-at').textContent = me.totp_enabled_at;
      $('#totp-recovery-remaining').textContent = me.totp_recovery_codes_remaining;
    } else {
      $('#totp-disabled-view').hidden = false;
      $('#totp-pending-view').hidden = true;
      $('#totp-enabled-view').hidden = true;
    }
  }

  // ---- 改密码 ----
  async function submitChangePassword(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = {
      old_password: fd.get('old_password'),
      new_password: fd.get('new_password'),
    };
    if (body.new_password !== fd.get('new_password2')) {
      setStatus('#change-pw-status', '两次输入的新密码不一致', 'err');
      return;
    }
    try {
      const r = await api('/api/v1/me/change-password', { method: 'POST', body });
      setStatus('#change-pw-status', '✅ 改完，' + r.password_set_at, 'ok');
      ev.target.reset();
      // 改完 password 后要重新登录（强制下线其他 session 不影响当前）
      // 简单做法：刷新页面让用户重登
      setTimeout(() => location.reload(), 1500);
    } catch (ex) {
      setStatus('#change-pw-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  // ---- 启 TOTP ----
  async function submitTotpSetup(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      const r = await api('/api/v1/me/totp/setup', {
        method: 'POST',
        body: { password: fd.get('password') },
      });
      totpPending = { secret: r.secret, recovery_codes: r.recovery_codes };
      // 渲染 pending 视图
      $('#totp-otpauth-url').textContent = r.otpauth_url;
      $('#totp-secret').textContent = r.secret;
      const list = $('#totp-recovery-codes');
      list.innerHTML = '';
      r.recovery_codes.forEach((c) => {
        const li = document.createElement('li');
        li.textContent = c;
        list.appendChild(li);
      });
      // 渲染 QR code
      renderQrCode(r.otpauth_url);
      setStatus('#totp-setup-status', '✅ 密钥已生成，请扫码并 verify', 'ok');
      render(currentMe);
    } catch (ex) {
      setStatus('#totp-setup-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  // 简易 QR 渲染：用 Google Chart API（如果离线可以替换成纯 JS QR 库）
  function renderQrCode(otpauthUrl) {
    const old = $('#totp-qr');
    if (old) old.remove();
    const img = document.createElement('img');
    img.id = 'totp-qr';
    img.alt = 'TOTP QR';
    img.style = 'background:#fff;padding:8px;display:block;margin:8px 0;width:200px;height:200px;';
    // 使用 api.qrserver.com 渲染（公网/内网都能用）
    const chartUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(otpauthUrl);
    img.src = chartUrl;
    const anchor = $('#totp-otpauth-url');
    if (anchor) anchor.parentNode.insertBefore(img, anchor.nextSibling);
  }

  async function submitTotpVerify(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const code = fd.get('code');
    try {
      const r = await api('/api/v1/me/totp/verify', { method: 'POST', body: { code } });
      totpPending = null;
      setStatus('#totp-verify-status', '✅ TOTP 已激活，剩 ' + r.recovery_codes_remaining + ' 个恢复码', 'ok');
      await loadMe();
    } catch (ex) {
      setStatus('#totp-verify-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  function cancelTotpSetup() {
    totpPending = null;
    render(currentMe);
  }

  async function submitTotpDisable(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    if (!confirm('关 TOTP 后账号只用密码登录。确认？')) return;
    try {
      const r = await api('/api/v1/me/totp/disable', { method: 'POST', body: { code: fd.get('code') } });
      setStatus('#totp-disable-status', '✅ TOTP 已关', 'ok');
      await loadMe();
    } catch (ex) {
      setStatus('#totp-disable-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  // ---- rotate cert ----
  async function submitRotateCert(ev) {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      const r = await api('/api/v1/me/rotate-cert', {
        method: 'POST',
        body: { verify: fd.get('verify') },
      });
      $('#rotate-cert-pem').value = r.cert_pem;
      $('#rotate-key-pem').value = r.key_pem;
      $('#rotate-cert-fp').textContent = r.fingerprint_sha256;
      $('#rotate-cert-result').hidden = false;
      setStatus('#rotate-cert-status', '✅ 新 cert 已生成，请立刻保存', 'ok');
    } catch (ex) {
      setStatus('#rotate-cert-status', '❌ ' + (ex.message || ex), 'err');
    }
  }

  // ---- 我的活动 ----
  async function loadAudit() {
    try {
      const r = await api('/api/v1/me/audit?limit=100');
      const tbody = $('#me-audit-table tbody');
      tbody.innerHTML = '';
      for (const e of (r.events || [])) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + escapeHtml(e.ts || '') + '</td>' +
                       '<td>' + escapeHtml(e.action || '') + '</td>' +
                       '<td>' + escapeHtml(e.method || '') + '</td>' +
                       '<td>' + escapeHtml(e.path || e.upstream || '') + '</td>' +
                       '<td>' + escapeHtml(e.status || '') + '</td>';
        tbody.appendChild(tr);
      }
    } catch (ex) {
      console.error('audit load failed', ex);
    }
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

  // ---- 监听 tab 切换 ----
  function init() {
    // 表单
    const fpw = $('#form-change-pw'); if (fpw) fpw.addEventListener('submit', submitChangePassword);
    const fs = $('#form-totp-setup');  if (fs) fs.addEventListener('submit', submitTotpSetup);
    const fv = $('#form-totp-verify'); if (fv) fv.addEventListener('submit', submitTotpVerify);
    const fd = $('#form-totp-disable'); if (fd) fd.addEventListener('submit', submitTotpDisable);
    const fr = $('#form-rotate-cert'); if (fr) fr.addEventListener('submit', submitRotateCert);
    const cancel = $('#btn-totp-cancel'); if (cancel) cancel.addEventListener('click', cancelTotpSetup);
    const btnAudit = $('#btn-load-audit'); if (btnAudit) btnAudit.addEventListener('click', loadAudit);

    // tab 切换 (监听 hashchange 或 button click)
    document.addEventListener('me-tab-opened', loadMe);
    document.addEventListener('me-tab-opened', loadAudit);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
