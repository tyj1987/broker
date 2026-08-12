// Secret Broker Dashboard - vanilla JS
// 因为 mTLS 在浏览器里没法直接发起，所有 API 调用都通过
// 浏览器 fetch + 预信任 ca.crt（需要把 ca.crt 加到系统信任库或浏览器证书）
// 或：通过 reverse proxy 注入 client cert（推荐）

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'include',
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error(`${res.status} ${typeof body === 'string' ? body : JSON.stringify(body)}`);
  return body;
}

// 标签切换
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// 身份
async function loadIdentity() {
  try {
    const id = await api('/api/v1/identity');
    document.getElementById('identity').textContent =
      `CN=${id.cn} · role=${id.role} · fp=${id.fingerprint_sha256}`;
  } catch (e) {
    document.getElementById('identity').textContent = `⚠ ${e.message}`;
  }
}
loadIdentity();

// 密钥列表
async function loadSecrets() {
  const tbody = document.querySelector('#secrets-table tbody');
  tbody.innerHTML = '<tr><td colspan="2">加载中...</td></tr>';
  try {
    const r = await api('/api/v1/secrets');
    const list = r.secrets || [];
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" style="color:#8b949e">（无可访问的密钥）</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const name of list) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><code>${escapeHtml(name)}</code></td>
        <td><button class="btn" data-name="${escapeHtml(name)}">resolve</button></td>`;
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
    // 实际生产应该只显示在弹窗里，复制到剪贴板
    if (confirm(`密钥 ${name} 已取到 (${masked})\n完整值复制到剪贴板吗？\n（会写入剪贴板，建议用完清除）`)) {
      await navigator.clipboard.writeText(r.value);
    }
  } catch (e) {
    btn.textContent = '失败';
    alert(`Resolve 失败: ${e.message}`);
  } finally {
    setTimeout(() => { btn.disabled = false; btn.textContent = 'resolve'; }, 3000);
  }
}

document.getElementById('btn-refresh-secrets').addEventListener('click', loadSecrets);
loadSecrets();

// 审计
async function loadAudit() {
  const limit = document.getElementById('audit-limit').value || 50;
  const sinceVal = document.getElementById('audit-since').value;
  const since = sinceVal ? new Date(sinceVal).toISOString() : '';
  const tbody = document.querySelector('#audit-table tbody');
  tbody.innerHTML = '<tr><td colspan="6">加载中...</td></tr>';
  try {
    const r = await api(`/api/v1/audit?limit=${limit}${since ? `&since=${encodeURIComponent(since)}` : ''}`);
    const events = r.events || [];
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:#8b949e">（无审计事件）</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const e of events) {
      const target = e.secret || (e.service ? `${e.service}${e.path || ''}` : e.method + ' ' + e.path);
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

document.getElementById('btn-refresh-audit').addEventListener('click', loadAudit);
loadAudit();

// 轮转
document.getElementById('btn-rotate').addEventListener('click', async () => {
  const name = document.getElementById('rotate-name').value.trim();
  if (!name) { alert('请输入 secret name'); return; }
  const result = document.getElementById('rotate-result');
  result.textContent = '触发中...';
  try {
    const r = await api(`/api/v1/rotate/${encodeURIComponent(name)}`, { method: 'POST' });
    result.textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    result.textContent = 'ERROR: ' + e.message;
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}
