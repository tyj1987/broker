// broker-test/test-ssh-proxy.js — V4.1 任务 12
// 覆盖: target 验证 / command 验证 / sshExec 注入 / 私钥零接触 / 错误 / tunnel 生命周期 / 凭据零接触

import {
  sshExec,
  sshTunnel,
  stopTunnel,
  listTunnels,
  parseSshTarget,
  validateCommand,
} from '../broker/ssh-proxy.js';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// parseSshTarget
// ============================================================
section('parseSshTarget');
{
  const t = parseSshTarget('app@10.0.1.5');
  ok('basic user@host', t.user === 'app' && t.host === '10.0.1.5' && t.port === 22);
}
{
  const t = parseSshTarget('admin@bastion.example.com:7222');
  ok('with port', t.user === 'admin' && t.host === 'bastion.example.com' && t.port === 7222);
}
{
  const t = parseSshTarget('jump_user@10.0.0.1');
  ok('underscore user', t.user === 'jump_user');
}
{
  let threw = false;
  try { parseSshTarget('app@host;rm -rf /'); } catch (e) { threw = /shell metacharacter/.test(e.message); }
  ok('rejects ; in host', threw);
}
{
  let threw = false;
  try { parseSshTarget('app@host`whoami`'); } catch (e) { threw = /shell metacharacter/.test(e.message); }
  ok('rejects backtick', threw);
}
{
  let threw = false;
  try { parseSshTarget('app@host|tee'); } catch (e) { threw = /shell metacharacter/.test(e.message); }
  ok('rejects pipe', threw);
}
{
  let threw = false;
  try { parseSshTarget('app@host $IFS'); } catch (e) { threw = /shell metacharacter/.test(e.message); }
  ok('rejects $ in target', threw);
}
{
  let threw = false;
  try { parseSshTarget('bad-host'); } catch (e) { threw = /user@host/.test(e.message); }
  ok('rejects no @ format', threw);
}
{
  let threw = false;
  try { parseSshTarget('app@host:99999'); } catch (e) { threw = /invalid ssh port/.test(e.message); }
  ok('rejects port out of range', threw);
}
{
  let threw = false;
  try { parseSshTarget('app@-bad-host-.com'); } catch (e) { threw = /invalid ssh host/.test(e.message); }
  ok('rejects malformed host', threw);
}
{
  let threw = false;
  try { parseSshTarget('-rf@host'); } catch (e) { threw = /invalid ssh username/.test(e.message); }
  ok('rejects username starting with -', threw);
}

// ============================================================
// validateCommand
// ============================================================
section('validateCommand');
{
  ok('valid simple cmd', validateCommand('ls -la') === 'ls -la');
  ok('valid with quoted spaces', validateCommand("grep 'foo bar' /tmp/x") === "grep 'foo bar' /tmp/x");
}
{
  let threw = false;
  try { validateCommand('ls\nrm -rf /'); } catch (e) { threw = /newline/.test(e.message); }
  ok('rejects newline in command', threw);
}
{
  let threw = false;
  try { validateCommand('ls\0rm'); } catch (e) { threw = /null|newline/.test(e.message); }
  ok('rejects NUL in command', threw);
}
{
  let threw = false;
  try { validateCommand('a'.repeat(5000)); } catch (e) { threw = /too long/.test(e.message); }
  ok('rejects command >4KB', threw);
}
{
  let threw = false;
  try { validateCommand(''); } catch (e) { threw = /required/.test(e.message); }
  ok('rejects empty command', threw);
}

// ============================================================
// sshExec: 注入 executor
// ============================================================
section('sshExec (mocked executor)');
{
  let captured = null;
  const executor = async (cmd, args, opts) => {
    captured = { cmd, args, opts };
    return { exitCode: 0, stdout: 'hello\n', stderr: '' };
  };
  const auditCalls = [];
  const r = await sshExec(
    { target: 'app@10.0.1.5', command: 'systemctl status nginx', secret: { private_key: 'FAKE-KEY-CONTENT' } },
    { executor, audit: (e) => auditCalls.push(e) }
  );
  ok('executor called with ssh', captured.cmd === 'ssh');
  ok('args include -i key', captured.args.some(a => a === '-i'));
  ok('args include private key path', captured.args.some(a => a.includes('id_key')));
  ok('args include BatchMode', captured.args.includes('-o') && captured.args.includes('BatchMode=yes'));
  ok('args include -- separator', captured.args.includes('--'));
  ok('args target is user@host', captured.args.includes('app@10.0.1.5'));
  ok('args command after --', captured.args[captured.args.length - 1] === 'systemctl status nginx');
  ok('returns ok=true', r.ok === true);
  ok('returns stdout', r.stdout === 'hello\n');
  ok('returns exitCode=0', r.exitCode === 0);
  ok('audit ok', auditCalls.some(a => a.action === 'ssh_exec' && a.status === 'ok'));
  ok('audit does NOT include private_key', !JSON.stringify(auditCalls).includes('FAKE-KEY-CONTENT'));
  ok('returns duration_ms', typeof r.duration_ms === 'number');
}

// ============================================================
// sshExec: 错误路径
// ============================================================
section('sshExec error paths');
{
  let threw = false;
  try {
    await sshExec({ target: 'a@b', command: 'c', secret: null }, { executor: async () => ({ exitCode: 0, stdout: '', stderr: '' }) });
  } catch (e) { threw = /private_key required/.test(e.message); }
  ok('missing secret throws', threw);
}
{
  let threw = false;
  try {
    await sshExec({ target: 'a@b', command: 'c', secret: {} }, { executor: async () => ({ exitCode: 0, stdout: '', stderr: '' }) });
  } catch (e) { threw = /private_key required/.test(e.message); }
  ok('secret without private_key throws', threw);
}
{
  const r = await sshExec(
    { target: 'a@b', command: 'c', secret: { private_key: 'k' } },
    { executor: async () => ({ exitCode: 1, stdout: '', stderr: 'Permission denied' }) }
  );
  ok('non-zero exit returns ok=false', r.ok === false);
  ok('returns stderr', r.stderr === 'Permission denied');
  ok('returns exitCode=1', r.exitCode === 1);
}
{
  let threw = false;
  try {
    await sshExec(
      { target: 'a@b', command: 'c', secret: { private_key: 'k' } },
      { executor: async () => { throw new Error('spawn ENOENT'); } }
    );
  } catch (e) { threw = /spawn ENOENT/.test(e.message); }
  ok('executor error propagates', threw);
}

// ============================================================
// 私钥文件清理
// ============================================================
section('key file lifecycle');
{
  // 用真实 fs,但 keydir 在 tmpdir,测试后清掉
  const calls = [];
  const fsImpl = {
    mkdtempSync: (prefix) => { const d = `${prefix}X`; calls.push(['mkdtemp', d]); return d; },
    writeFileSync: (p, c) => { calls.push(['write', p, c]); },
    chmodSync: (p) => { calls.push(['chmod', p]); },
    existsSync: (p) => { calls.push(['exists', p]); return true; },
    rmSync: (p) => { calls.push(['rm', p]); },
  };
  await sshExec(
    { target: 'a@b', command: 'c', secret: { private_key: 'SECRET-CONTENT' } },
    { executor: async () => ({ exitCode: 0, stdout: '', stderr: '' }), fsImpl }
  );
  ok('key dir created in tmp', calls.some(c => c[0] === 'mkdtemp' && c[1].includes('broker-ssh-')));
  ok('key file written with 0600', calls.some(c => c[0] === 'write' && c[2] === 'SECRET-CONTENT'));
  ok('chmod 0600 applied', calls.some(c => c[0] === 'chmod'));
  ok('key dir cleaned up', calls.some(c => c[0] === 'rm'));
}

// ============================================================
// sshTunnel: 注入 child_process 风格
// ============================================================
section('sshTunnel');
{
  let killed = false;
  const fakeChild = {
    on: (ev, cb) => { if (ev === 'close') fakeChild._closeCb = cb; },
    kill: (sig) => { killed = true; fakeChild._sig = sig; },
  };
  const executor = async () => ({ child: fakeChild });
  const t = await sshTunnel(
    { target: 'app@db.internal:22', localPort: 5432, remoteHost: 'db.svc', remotePort: 5432, secret: { private_key: 'k' } },
    { executor, audit: () => {} }
  );
  ok('tunnel has id', typeof t.id === 'string' && t.id.length > 0);
  ok('tunnel has stop()', typeof t.stop === 'function');
  ok('tunnel metadata correct', t.localPort === 5432 && t.remote === 'db.svc:5432');
  ok('tunnel listed in ACTIVE_TUNNELS', listTunnels().some(x => x.id === t.id));
  // 关掉
  const stopped = await stopTunnel(t.id, () => {});
  ok('stop returns true', stopped === true);
  ok('child SIGTERM sent', killed && fakeChild._sig === 'SIGTERM');
  // 异步 close
  fakeChild._closeCb?.(0);
  ok('tunnel removed after close', !listTunnels().some(x => x.id === t.id));
}

{
  // tunnel 参数校验
  let threw = false;
  try { await sshTunnel({ target: 'a@b', localPort: 99999, remoteHost: 'h', remotePort: 22, secret: { private_key: 'k' } }, { executor: async () => ({ child: { on: () => {} } }) }); } catch (e) { threw = /localPort/.test(e.message); }
  ok('rejects bad localPort', threw);
}
{
  let threw = false;
  try { await sshTunnel({ target: 'a@b', localPort: 22, remoteHost: 'bad host!', remotePort: 22, secret: { private_key: 'k' } }, { executor: async () => ({ child: { on: () => {} } }) }); } catch (e) { threw = /remoteHost/.test(e.message); }
  ok('rejects bad remoteHost', threw);
}

// ============================================================
// 凭据零接触
// ============================================================
section('zero credential leakage');
{
  // AI 拿到 sshExec 的返回值,不应该包含 private_key
  const r = await sshExec(
    { target: 'a@b', command: 'c', secret: { private_key: 'GHp_LEAK_ME_xxxxxxxxxxxxx' } },
    { executor: async () => ({ exitCode: 0, stdout: 'ok', stderr: '' }) }
  );
  const txt = JSON.stringify(r);
  ok('result does not contain private_key', !txt.includes('GHp_LEAK_ME'));
  ok('result does not contain key path', !txt.includes('id_key'));
}
{
  // listTunnels 也不应泄漏
  const fakeChild = { on: () => {}, kill: () => {} };
  await sshTunnel(
    { target: 'a@b', localPort: 3333, remoteHost: 'h', remotePort: 22, secret: { private_key: 'LEAK-KEY' } },
    { executor: async () => ({ child: fakeChild }) }
  );
  const items = listTunnels();
  const txt = JSON.stringify(items);
  ok('listTunnels does not leak private_key', !txt.includes('LEAK-KEY'));
  ok('listTunnels does not leak keyPath', !txt.includes('id_key'));
}

// ============================================================
console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
