// broker/routes/ssh-proxy.js — V4.1 任务 12
// 端点:
//   POST /api/v1/ssh/exec      — 调 broker 替 AI 在目标机执行命令
//   POST /api/v1/ssh/tunnel    — 打开本地端口转发
//   POST /api/v1/ssh/tunnel/stop — 关掉指定 tunnel
//   GET  /api/v1/ssh/tunnels   — 列出活跃 tunnels (admin)
//
// 安全: 私钥永远不离开 broker;只回 stdout/stderr/exit code。
// 限流: rateLimit 防止滥用。审计: deps.audit 记录每次调用。

import { sshExec, sshTunnel, stopTunnel, listTunnels, parseSshTarget, validateCommand } from '../ssh-proxy.js';

export async function handleSshProxy(req, res, route, deps) {
  const { method, pathname: p } = route;
  const { send, jsonError, readBody, audit, ctx, config, rateLimit, getSecret } = deps;

  if (p === '/api/v1/ssh/exec' && method === 'POST') {
    await handleExec(req, res, { send, jsonError, readBody, audit, ctx, config, rateLimit, getSecret });
    return true;
  }
  if (p === '/api/v1/ssh/tunnel' && method === 'POST') {
    await handleTunnel(req, res, { send, jsonError, readBody, audit, ctx, config, rateLimit, getSecret });
    return true;
  }
  if (p === '/api/v1/ssh/tunnel/stop' && method === 'POST') {
    await handleTunnelStop(req, res, { send, jsonError, readBody, audit, ctx });
    return true;
  }
  if (p === '/api/v1/ssh/tunnels' && method === 'GET') {
    handleTunnelList(res, { send, jsonError, ctx, config });
    return true;
  }
  return false;
}

async function handleExec(req, res, { send, jsonError, readBody, audit, ctx, config, rateLimit, getSecret }) {
  if (!ctx?.client) return jsonError(res, 401, 'Authentication required');
  if (ctx.client.security_profile === 'strict') return jsonError(res, 403, 'Strict profile forbids free-form SSH');
  if (rateLimit && !rateLimit(ctx, 'ssh.exec')) return jsonError(res, 429, 'Too many ssh exec requests');
  const body = await readBody(req) || {};
  const { target, command, secret_name, secretName, timeout_ms, timeoutMs } = body;
  if (!target) return jsonError(res, 400, 'target required (user@host[:port])');
  if (!command) return jsonError(res, 400, 'command required');
  let parsed;
  try { parsed = parseSshTarget(target); validateCommand(command); }
  catch (e) { return jsonError(res, 400, e.message); }
  const sName = secretName || secret_name || 'ssh.connection';
  let secret;
  try {
    secret = await getSecret(sName, ctx);
  } catch (e) {
    audit?.({ action: 'ssh_exec', status: 'denied', reason: 'secret_unavailable', target, cn: ctx.cn });
    return jsonError(res, 404, `ssh secret ${sName} not accessible`);
  }
  if (!secret || !secret.private_key) {
    audit?.({ action: 'ssh_exec', status: 'denied', reason: 'no_private_key', target, cn: ctx.cn });
    return jsonError(res, 400, `secret ${sName} has no private_key`);
  }
  try {
    const r = await sshExec({ target, command, secret }, {
      audit, requestId: ctx.requestId, timeoutMs: timeoutMs || timeout_ms,
    });
    send(res, 200, {
      ok: r.ok,
      exitCode: r.exitCode,
      stdout: r.stdout,
      stderr: r.stderr,
      duration_ms: r.duration_ms,
      target,
    });
  } catch (e) {
    jsonError(res, 502, `ssh exec failed: ${e.message}`);
  }
}

async function handleTunnel(req, res, { send, jsonError, readBody, audit, ctx, config, rateLimit, getSecret }) {
  if (!ctx?.client) return jsonError(res, 401, 'Authentication required');
  if (ctx.client.security_profile === 'strict') return jsonError(res, 403, 'Strict profile forbids free-form SSH');
  if (rateLimit && !rateLimit(ctx, 'ssh.tunnel')) return jsonError(res, 429, 'Too many ssh tunnel requests');
  const body = await readBody(req) || {};
  const { target, local_port, localPort, remote_host, remoteHost, remote_port, remotePort, secret_name, secretName } = body;
  if (!target) return jsonError(res, 400, 'target required');
  const lp = localPort || local_port;
  const rh = remoteHost || remote_host;
  const rp = remotePort || remote_port;
  if (!lp || !rh || !rp) return jsonError(res, 400, 'local_port / remote_host / remote_port required');
  const sName = secretName || secret_name || 'ssh.connection';
  let secret;
  try { secret = await getSecret(sName, ctx); }
  catch (e) {
    audit?.({ action: 'ssh_tunnel_open', status: 'denied', reason: 'secret_unavailable', target, cn: ctx.cn });
    return jsonError(res, 404, `ssh secret ${sName} not accessible`);
  }
  if (!secret || !secret.private_key) {
    return jsonError(res, 400, `secret ${sName} has no private_key`);
  }
  try {
    const t = await sshTunnel({ target, localPort: lp, remoteHost: rh, remotePort: rp, secret }, { audit });
    send(res, 200, {
      ok: true,
      id: t.id,
      localPort: t.localPort,
      remote: t.remote,
      target: t.target,
      startedAt: t.startedAt,
    });
  } catch (e) {
    jsonError(res, 400, `tunnel open failed: ${e.message}`);
  }
}

async function handleTunnelStop(req, res, { send, jsonError, readBody, audit, ctx }) {
  if (!ctx?.client) return jsonError(res, 401, 'Authentication required');
  const body = await readBody(req) || {};
  const { id } = body;
  if (!id) return jsonError(res, 400, 'id required');
  const ok = await stopTunnel(id, audit);
  if (!ok) return jsonError(res, 404, 'tunnel not found');
  send(res, 200, { ok: true, id });
}

async function handleTunnelList(res, { send, jsonError, ctx, config }) {
  if (!ctx?.client) return jsonError(res, 401, 'Authentication required');
  const items = listTunnels();
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ ok: true, count: items.length, items }));
}
