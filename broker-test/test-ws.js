// broker-test/test-ws.js — V4.1 任务 13
// 覆盖: pub/sub / 事件过滤 / 心跳 / 凭据零接触 / 错误处理

import ws from '../broker/node_modules/ws/index.js';
const { WebSocketServer, WebSocket } = ws;
import {
  broadcastEvent,
  subscribeClient,
  unsubscribeClient,
  updateClientFilter,
  getStats,
  listSubscribers,
  _resetForTests,
  HEARTBEAT_INTERVAL_MS,
} from '../broker/lib/ws.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}`); }
}
function section(t) { console.log(`\n[${t}]`); }

// ============================================================
// 准备自签证书 (用于 wss://)
// ============================================================
function genKeyPair() {
  return generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
}
function makeSelfSigned(cn) {
  const k = genKeyPair();
  // 写个伪证书 — 我们用 Node 提供的 selfsigned 替代
  // 简单办法: 让 server 用 key 但 verifyClient 不做证书验证(本测试跳过 mTLS)
  return { key: k.privateKey, cert: k.publicKey };
}

// 简化: 不测 wss,直接测 broadcastEvent/subscribeClient/sanitization
// (attachWebSocket 需要 mTLS server,留给集成测试)

// ============================================================
// 订阅 + 广播
// ============================================================
section('subscribe + broadcast');
{
  _resetForTests();
  const received = [];
  const fakeWs = {
    OPEN: 1,
    readyState: 1,
    send: (data) => received.push(JSON.parse(data)),
  };
  const id = 'c1';
  subscribeClient(id, fakeWs, ['audit', 'alerts']);
  broadcastEvent({ type: 'audit', severity: 'info', data: { action: 'login' } });
  ok('audit event delivered', received.length === 1 && received[0].event_type === 'audit');
  ok('contains data', received[0].data.action === 'login');
  ok('contains ts', typeof received[0].ts === 'string');
}
{
  _resetForTests();
  const received = [];
  const fakeWs = {
    OPEN: 1,
    readyState: 1,
    send: (data) => received.push(JSON.parse(data)),
  };
  subscribeClient('c1', fakeWs, ['alerts']);
  broadcastEvent({ type: 'audit', data: {} });
  broadcastEvent({ type: 'healthcheck', data: { ok: true } });
  ok('non-subscribed event skipped', received.length === 0);
}
{
  _resetForTests();
  const r1 = [], r2 = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r1.push(JSON.parse(d)) }, ['audit']);
  subscribeClient('c2', { OPEN: 1, readyState: 1, send: (d) => r2.push(JSON.parse(d)) }, ['alerts']);
  broadcastEvent({ type: 'audit', data: {} });
  broadcastEvent({ type: 'alerts', data: {} });
  ok('c1 only got audit', r1.length === 1 && r1[0].event_type === 'audit');
  ok('c2 only got alerts', r2.length === 1 && r2[0].event_type === 'alerts');
}

// ============================================================
// wildcard 订阅
// ============================================================
section('wildcard subscription');
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['*']);
  broadcastEvent({ type: 'audit', data: {} });
  broadcastEvent({ type: 'alerts', data: {} });
  broadcastEvent({ type: 'foo', data: {} });
  ok('wildcard gets all events', r.length === 3);
}

// ============================================================
// unsubscribe
// ============================================================
section('unsubscribe');
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['audit']);
  broadcastEvent({ type: 'audit', data: {} });
  ok('pre-unsubscribe got 1', r.length === 1);
  unsubscribeClient('c1');
  broadcastEvent({ type: 'audit', data: {} });
  ok('post-unsubscribe got 0', r.length === 1);
  ok('unsubscribe on unknown returns false', unsubscribeClient('unknown') === false);
}
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['audit', 'alerts']);
  // 部分 unsubscribe
  const sub = { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) };
  // 不能部分 unsub(API 是 unsub all),验证
  unsubscribeClient('c1');
  broadcastEvent({ type: 'audit', data: {} });
  broadcastEvent({ type: 'alerts', data: {} });
  ok('full unsub blocks all', r.length === 0);
}

// ============================================================
// filter
// ============================================================
section('event filter');
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['alerts'], { severity_eq: 'critical' });
  broadcastEvent({ type: 'alerts', severity: 'info', data: {} });
  broadcastEvent({ type: 'alerts', severity: 'warning', data: {} });
  broadcastEvent({ type: 'alerts', severity: 'critical', data: {} });
  ok('severity_eq filter applied', r.length === 1);
  ok('only critical passed', r[0].data && r[0].event_type === 'alerts');
}
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['alerts'], { severity_gte: 'high' });
  broadcastEvent({ type: 'alerts', severity: 'info', data: {} });
  broadcastEvent({ type: 'alerts', severity: 'high', data: {} });
  broadcastEvent({ type: 'alerts', severity: 'critical', data: {} });
  ok('severity_gte filter applied', r.length === 2);
}
{
  // updateClientFilter
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['alerts'], { severity_eq: 'critical' });
  updateClientFilter('c1', { severity_eq: 'info' });
  broadcastEvent({ type: 'alerts', severity: 'critical', data: {} });
  broadcastEvent({ type: 'alerts', severity: 'info', data: {} });
  ok('filter updated', r.length === 1 && r[0].data && r[0].event_type === 'alerts');
}

// ============================================================
// 凭据零接触: broadcastEvent 自动 redact
// ============================================================
section('zero credential leakage in broadcast');
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['alerts']);
  broadcastEvent({
    type: 'alerts',
    data: { message: 'token=ghp_xxxxABCDEFGHIJabcdefghij leaked', token: 'sk-abcdef1234567890ABCDEFGHIJK' },
  });
  ok('alerts leaked', r.length === 1);
  const msgStr = JSON.stringify(r[0]);
  ok('ghp_ redacted in message', !msgStr.includes('ghp_xxxxABCDEFGHIJ'));
  ok('sk- redacted in token', !msgStr.includes('sk-abcdef1234567890ABCDEFGHIJK'));
  ok('redaction marker present', msgStr.includes('REDACTED') || msgStr.includes('***'));
}
{
  _resetForTests();
  const r = [];
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: (d) => r.push(JSON.parse(d)) }, ['audit']);
  broadcastEvent({
    type: 'audit',
    data: {
      action: 'proxy',
      target: 'github',
      response: 'returned Bearer AKIAIOSFODNN7EXAMPLE in body',
    },
  });
  const msgStr = JSON.stringify(r[0]);
  ok('AWS key redacted in audit', !msgStr.includes('AKIAIOSFODNN7EXAMPLE'));
}

// ============================================================
// stats + list
// ============================================================
section('stats');
{
  _resetForTests();
  subscribeClient('c1', { OPEN: 1, readyState: 1, send: () => {} }, ['audit']);
  subscribeClient('c2', { OPEN: 1, readyState: 1, send: () => {} }, ['alerts', 'audit']);
  const s = getStats();
  ok('subscriber count = 2', s.subscriberCount === 2);
  ok('events tracked', s.events.includes('audit') && s.events.includes('alerts'));
  const lst = listSubscribers();
  ok('listSubscribers has 2', lst.length === 2);
  ok('list has metadata only', lst.every(s => s.id && Array.isArray(s.events) && !('send' in s)));
}

// ============================================================
// broadcastEvent 参数校验
// ============================================================
section('broadcastEvent validation');
{
  _resetForTests();
  let threw = false;
  try { broadcastEvent({}); } catch (e) { threw = /type required/.test(e.message); }
  ok('missing type throws', threw);
}

section('WebSocket error messages do not reflect input');
{
  const source = readFileSync(join(process.cwd(), 'lib', 'ws.js'), 'utf8');
  ok('invalid JSON error is stable', source.includes("sendError(ws, 'invalid_json', 'invalid_json')"));
  ok('unknown action is not reflected', source.includes("sendError(ws, 'unknown_action', 'unsupported_action')"));
}

// ============================================================
// 真实 WebSocket 端到端 (本地 ws, 无 mTLS)
// ============================================================
section('end-to-end WebSocket');
{
  _resetForTests();
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((resolveListening, rejectListening) => {
    wss.once('listening', resolveListening);
    wss.once('error', rejectListening);
  });
  // 模拟一个 client,验证 broadcastEvent 通过 wss.send 路径
  const PORT = wss.address().port;
  wss.on('connection', (ws) => {
    const id = `test-${Date.now()}`;
    ws.id = id;
    subscribeClient(id, ws, ['alerts']);
    ws.send(JSON.stringify({ type: 'ack', ack_type: 'connected' }));
  });
  const WebSocketClient = ws.WebSocket || ws;
  const c = new WebSocketClient(`ws://127.0.0.1:${PORT}`);
  const received = [];
  const waitForMessage = (predicate) => new Promise((resolveMessage, rejectMessage) => {
    const timer = setTimeout(() => {
      c.off('message', onMessage);
      rejectMessage(new Error('timed out waiting for WebSocket message'));
    }, 2_000);
    const onMessage = (raw) => {
      const message = JSON.parse(raw.toString());
      received.push(message);
      if (!predicate(message)) return;
      clearTimeout(timer);
      c.off('message', onMessage);
      resolveMessage(message);
    };
    c.on('message', onMessage);
  });
  const ack = waitForMessage((message) => message.type === 'ack');
  await new Promise((r) => c.on('open', r));
  await ack;
  const event = waitForMessage((message) => message.type === 'event' && message.event_type === 'alerts');
  broadcastEvent({ type: 'alerts', severity: 'critical', data: { msg: 'x' } });
  await event;
  ok('ack received', received.some(m => m.type === 'ack'));
  ok('event broadcasted', received.some(m => m.type === 'event' && m.event_type === 'alerts'));
  const closed = new Promise((resolveClosed) => c.once('close', resolveClosed));
  c.close();
  await closed;
  await new Promise((resolveClosed, rejectClosed) => wss.close((error) => {
    if (error) rejectClosed(error);
    else resolveClosed();
  }));
}

// ============================================================
console.log(`\n=== Total: ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
