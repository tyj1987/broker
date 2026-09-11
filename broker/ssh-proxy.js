// broker/ssh-proxy.js — V4.1 任务 12: SSH Proxy
// 目标: AI 用 broker 当跳板执行 SSH 命令,broker 用 secret 里的私钥连目标。
// 私钥永远不离开 broker 进程,AI 只看到 stdout/stderr。
//
// 实现策略: 不引入 ssh2 依赖,用系统 ssh (OpenSSH client) 子进程。
// 临时文件存放私钥(0600),spawn 完即删。
// 跨平台: Linux/macOS 用 /usr/bin/ssh,Windows 用 PATH 里的 ssh.exe (Win10 1809+ / Win11 自带)。
//
// 注入点:
//   - executor 替换 spawn,测试用
//   - secretStore.getSecret 读 secret (注入使测试不依赖 sops)
//   - audit 写审计
//   - fsImpl 替换 fs (测试用内存 fs)

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

// ============================================================
// 常量
// ============================================================
const MAX_OUTPUT_BYTES = 10 * 1024 * 1024;  // 10MB 防止恶意命令返回天量数据
const DEFAULT_TIMEOUT_MS = 5 * 60_000;       // 5 分钟
const KEY_DIR_PREFIX = 'broker-ssh-';
const ACTIVE_TUNNELS = new Map();  // id -> { process, target, startedAt, secretName }

// ============================================================
// 验证 + 净化
// ============================================================
const HOST_RE = /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$/;
const PORT_RE = /^(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/;
const USER_RE = /^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$/;

/**
 * Validate and parse a "user@host:port" target string. Throws on invalid input.
 * Also rejects shell metacharacters to prevent command injection when the
 * target is concatenated into a shell command.
 */
export function parseSshTarget(target) {
  if (!target || typeof target !== 'string') {
    throw new Error('ssh target required (format: user@host[:port])');
  }
  if (target.length > 256) throw new Error('ssh target too long');
  if (/[\s;&|<>`$'"\\]/.test(target)) {
    throw new Error('ssh target contains shell metacharacters');
  }
  const m = /^([^@]+)@([^:]+)(?::(\d+))?$/.exec(target);
  if (!m) throw new Error('ssh target must be user@host[:port]');
  const [, user, host, portStr] = m;
  if (!USER_RE.test(user)) throw new Error(`invalid ssh username: ${user.slice(0, 20)}`);
  if (!HOST_RE.test(host)) throw new Error(`invalid ssh host: ${host.slice(0, 50)}`);
  if (portStr && !PORT_RE.test(portStr)) throw new Error(`invalid ssh port: ${portStr}`);
  return { user, host, port: portStr ? parseInt(portStr, 10) : 22 };
}

/**
 * Validate a remote command string before passing it as a single argv to `ssh`.
 *
 * Policy (intentionally narrow):
 * - Reject newline / CR / NUL so the command cannot split into multiple remote
 *   lines or smuggle argv boundaries when logged/handled as text.
 * - Allow `$`, backticks, and backslash: the string is executed by the *remote*
 *   shell after `ssh --`, so those characters are normal for remote scripts.
 *   Local injection is avoided by never interpolating this string into a local shell.
 */
export function validateCommand(command) {
  if (!command || typeof command !== 'string') {
    throw new Error('command required');
  }
  if (command.length > 4096) throw new Error('command too long (>4KB)');
  // Disallow newline / CR / NUL only (see docstring).
  if (/[\n\r\0]/.test(command)) {
    throw new Error('command contains newline/null');
  }
  return command;
}

// ============================================================
// SSH材料生命周期
// ============================================================
function validateKnownHosts(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('ssh secret with verified known_hosts required');
  }
  if (value.length > 16 * 1024 || /[\r\0]/.test(value)) {
    throw new Error('known_hosts is invalid or too large');
  }
  const lines = value.trim().split('\n').filter(Boolean);
  const valid = lines.every(line => {
    const fields = line.trim().split(/\s+/);
    const offset = fields[0]?.startsWith('@') ? 1 : 0;
    return fields.length >= offset + 3
      && /^(ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521))$/.test(fields[offset + 1] || '')
      && /^[A-Za-z0-9+/]+={0,2}$/.test(fields[offset + 2] || '');
  });
  if (!lines.length || !valid) throw new Error('known_hosts must contain OpenSSH host key entries');
  return value.trim() + '\n';
}

function configuredTarget(secret, requestedTarget) {
  if (!secret || !secret.private_key) throw new Error('ssh secret with private_key required');
  if (!secret.host || !secret.username) throw new Error('ssh secret host and username required');
  const port = secret.port || 22;
  const configured = parseSshTarget(`${secret.username}@${secret.host}:${port}`);
  if (requestedTarget) {
    const requested = parseSshTarget(requestedTarget);
    if (requested.user !== configured.user || requested.host !== configured.host || requested.port !== configured.port) {
      throw new Error('requested target does not match ssh secret target');
    }
  }
  return configured;
}

function writeSshMaterial(fsImpl, secret) {
  const dir = fsImpl.mkdtempSync(join(tmpdir(), KEY_DIR_PREFIX));
  const keyPath = join(dir, 'id_key');
  const knownHostsPath = join(dir, 'known_hosts');
  fsImpl.writeFileSync(keyPath, secret.private_key, { mode: 0o600 });
  fsImpl.chmodSync(keyPath, 0o600);
  fsImpl.writeFileSync(knownHostsPath, validateKnownHosts(secret.known_hosts), { mode: 0o600 });
  fsImpl.chmodSync(knownHostsPath, 0o600);
  return { dir, keyPath, knownHostsPath };
}

function cleanupKeyDir(fsImpl, dir) {
  try {
    if (fsImpl.existsSync(dir)) fsImpl.rmSync(dir, { recursive: true, force: true });
  } catch (_e) { /* swallow; tmpfs 会自己清 */ }
}

// ============================================================
// sshExec
// ============================================================

/**
 * Execute a command on a remote host via broker-managed SSH.
 *
 * @param {object} opts
 * @param {string} opts.target         "user@host[:port]"
 * @param {string} opts.command        shell command (single argument)
 * @param {object} opts.secret         { private_key, jump_target?, jump_key?, ... }  (私有字段,不返回给 AI)
 * @param {object} [deps]
 * @param {object} [deps.fsImpl]       fs 注入(测试)
 * @param {Function} [deps.executor]   spawn 注入(测试)
 * @param {object} [deps.audit]        audit 函数
 * @param {string} [deps.requestId]    request id
 * @param {number} [deps.timeoutMs]    timeout, default 5min
 * @returns {Promise<{ok:boolean, exitCode:number|null, stdout:string, stderr:string, duration_ms:number}>}
 */
export async function sshExec(opts, deps = {}) {
  const target = configuredTarget(opts.secret, opts.target);
  const command = validateCommand(opts.command);
  const fsImpl = deps.fsImpl || { writeFileSync, chmodSync, rmSync, existsSync, mkdtempSync };
  const executor = deps.executor || defaultExecutor;
  const startedAt = Date.now();
  const { dir, keyPath, knownHostsPath } = writeSshMaterial(fsImpl, opts.secret);
  const args = [
    '-i', keyPath,
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'BatchMode=yes',
    '-o', 'LogLevel=ERROR',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'GlobalKnownHostsFile=/dev/null',
    '-p', String(target.port),
    `${target.user}@${target.host}`,
    '--',
    command,
  ];
  try {
    const result = await executor('ssh', args, { timeoutMs: deps.timeoutMs || DEFAULT_TIMEOUT_MS });
    deps.audit?.({
      action: 'ssh_exec',
      status: result.exitCode === 0 ? 'ok' : 'error',
      target: opts.target,
      exitCode: result.exitCode,
      duration_ms: Date.now() - startedAt,
      request_id: deps.requestId,
    });
    return {
      ok: result.exitCode === 0,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      duration_ms: Date.now() - startedAt,
    };
  } catch (e) {
    deps.audit?.({
      action: 'ssh_exec',
      status: 'error',
      target: opts.target,
      error: String(e?.message || e),
      duration_ms: Date.now() - startedAt,
      request_id: deps.requestId,
    });
    throw e;
  } finally {
    cleanupKeyDir(fsImpl, dir);
  }
}

/**
 * Default executor: spawn system ssh, collect stdout/stderr with size cap.
 */
function defaultExecutor(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false, windowsHide: true });
    } catch (e) { return reject(new Error(`spawn failed: ${e.message}`)); }
    let stdout = '', stderr = '';
    let killed = false;
    let timer = null;
    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        killed = true;
        try { child.kill('SIGKILL'); } catch (_e) { /* */ }
        reject(new Error(`ssh timeout after ${opts.timeoutMs}ms`));
      }, opts.timeoutMs);
    }
    child.stdout.on('data', (d) => {
      if (stdout.length < MAX_OUTPUT_BYTES) stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d) => {
      if (stderr.length < MAX_OUTPUT_BYTES) stderr += d.toString('utf8');
    });
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      if (!killed) reject(new Error(`ssh spawn error: ${e.message}`));
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (killed) return;  // already rejected
      resolve({ exitCode: code, stdout, stderr });
    });
  });
}

// ============================================================
// sshTunnel (本地端口转发 -L)
// ============================================================

/**
 * Start a local port forward via broker-managed SSH. Returns a handle
 * with stop() to close the tunnel. AI never sees the private key.
 *
 * @param {object} opts
 * @param {string} opts.target         "user@host[:port]"  (SSH endpoint)
 * @param {number} opts.localPort      local port to bind
 * @param {string} opts.remoteHost     remote host (e.g. "db.internal")
 * @param {number} opts.remotePort     remote port (e.g. 5432)
 * @param {object} opts.secret         { private_key }
 * @param {object} [deps]              { fsImpl, executor, audit }
 * @returns {Promise<{id:string, stop:()=>Promise<void>}>}
 */
export async function sshTunnel(opts, deps = {}) {
  const target = configuredTarget(opts.secret, opts.target);
  if (!opts.localPort || !PORT_RE.test(String(opts.localPort))) {
    throw new Error('localPort must be 1-65535');
  }
  if (!opts.remoteHost || !HOST_RE.test(opts.remoteHost)) {
    throw new Error('remoteHost invalid');
  }
  if (!opts.remotePort || !PORT_RE.test(String(opts.remotePort))) {
    throw new Error('remotePort must be 1-65535');
  }
  const fsImpl = deps.fsImpl || { writeFileSync, chmodSync, rmSync, existsSync, mkdtempSync };
  const executor = deps.executor || ((cmd, args) => {
    // 不通过 defaultExecutor (它有 timeout),tunnel 是 long-running
    return new Promise((resolve, reject) => {
      try {
        const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false, windowsHide: true });
        resolve({ child });
      } catch (e) { reject(e); }
    });
  });
  const { dir, keyPath, knownHostsPath } = writeSshMaterial(fsImpl, opts.secret);
  const args = [
    '-i', keyPath,
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'BatchMode=yes',
    '-o', 'LogLevel=ERROR',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'GlobalKnownHostsFile=/dev/null',
    '-o', 'ExitOnForwardFailure=yes',
    '-N',                  // no command, just forward
    '-L', `${opts.localPort}:${opts.remoteHost}:${opts.remotePort}`,
    '-p', String(target.port),
    `${target.user}@${target.host}`,
  ];
  const id = randomUUID();
  const startedAt = new Date().toISOString();
  const { child } = await executor('ssh', args);
  const tunnel = {
    id,
    child,
    target: opts.target,
    localPort: opts.localPort,
    remoteHost: opts.remoteHost,
    remotePort: opts.remotePort,
    startedAt,
    keyDir: dir,
  };
  ACTIVE_TUNNELS.set(id, tunnel);
  // child 退出时自动清理
  child.on('close', () => {
    ACTIVE_TUNNELS.delete(id);
    cleanupKeyDir(fsImpl, dir);
  });
  deps.audit?.({
    action: 'ssh_tunnel_open',
    status: 'ok',
    target: opts.target,
    localPort: opts.localPort,
    remote: `${opts.remoteHost}:${opts.remotePort}`,
    tunnel_id: id,
  });
  return {
    id,
    localPort: opts.localPort,
    remote: `${opts.remoteHost}:${opts.remotePort}`,
    target: opts.target,
    startedAt,
    stop: async () => stopTunnel(id, deps.audit),
  };
}

export async function stopTunnel(id, audit) {
  const t = ACTIVE_TUNNELS.get(id);
  if (!t) return false;
  try { t.child.kill('SIGTERM'); } catch (_e) { /* */ }
  // 给 1s 让它优雅退出,否则 SIGKILL
  setTimeout(() => {
    try { t.child.kill('SIGKILL'); } catch (_e) { /* */ }
  }, 1000);
  ACTIVE_TUNNELS.delete(id);
  audit?.({ action: 'ssh_tunnel_close', status: 'ok', tunnel_id: id });
  return true;
}

export function listTunnels() {
  // 元数据,绝不含凭据
  return Array.from(ACTIVE_TUNNELS.values()).map(t => ({
    id: t.id,
    target: t.target,
    localPort: t.localPort,
    remote: `${t.remoteHost}:${t.remotePort}`,
    startedAt: t.startedAt,
  }));
}

export default { sshExec, sshTunnel, stopTunnel, listTunnels, parseSshTarget, validateCommand };
