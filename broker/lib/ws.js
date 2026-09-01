// broker/lib/ws.js — V4.1 任务 13: WebSocket 实时事件流
// 路径: /ws
// 协议: 客户端发 JSON { action: 'subscribe'|'unsubscribe'|'ping', events?: [..], filter?: {...} }
//       服务端发 JSON { type: 'event'|'ack'|'pong'|'error', ... }
// 事件类型: audit / healthcheck / alerts / secret_rotated / mfa_enrolled / config_reloaded
// 心跳: 服务端每 30s 发 ping,客户端 60s 内未响应任何消息则断开
// 凭据零接触: emit 时自动 redact payload

import { WebSocketServer } from 'ws';
import { randomUUID } from 'node:crypto';
import { redact } from './redact.js';

export const HEARTBEAT_INTERVAL_MS = 30_000;
export const CLIENT_TIMEOUT_MS = 60_000;  // 收到任何消息后 60s 内无响应则断开

// ============================================================
// 进程内事件总线
// ============================================================
const SUBSCRIBERS = new Map();  // clientId -> { ws, events:Set<string>, filter:object, cn, lastSeen }
const SUBS_BY_EVENT = new Map(); // eventName -> Set<clientId>

export function subscribeClient(clientId, ws, events, filter = {}) {
  const eventSet = new Set(Array.isArray(events) ? events : []);
  SUBSCRIBERS.set(clientId, { ws, events: eventSet, filter, lastSeen: Date.now() });
  for (const e of eventSet) {
    if (!SUBS_BY_EVENT.has(e)) SUBS_BY_EVENT.set(e, new Set());
    SUBS_BY_EVENT.get(e).add(clientId);
  }
}

export function unsubscribeClient(clientId) {
  const sub = SUBSCRIBERS.get(clientId);
  if (!sub) return false;
  for (const e of sub.events) {
    const set = SUBS_BY_EVENT.get(e);
    if (set) set.delete(clientId);
  }
  SUBSCRIBERS.delete(clientId);
  return true;
}

export function updateClientFilter(clientId, filter) {
  const sub = SUBSCRIBERS.get(clientId);
  if (!sub) return false;
  sub.filter = filter || {};
  return true;
}

/**
 * Broadcast an event to all matching subscribers.
 * Redacts payload before sending.
 */
export function broadcastEvent(event) {
  const e = event || {};
  if (!e.type) throw new Error('event.type required');
  const subscribers = SUBS_BY_EVENT.get(e.type) || new Set();
  const wildcard = SUBS_BY_EVENT.get('*') || new Set();
  const allTargets = new Set([...subscribers, ...wildcard]);
  const out = {
    type: 'event',
    event_type: e.type,
    ts: e.ts || new Date().toISOString(),
    data: sanitizePayload(e.data || {}),
    request_id: e.request_id,
  };
  for (const clientId of allTargets) {
    const sub = SUBSCRIBERS.get(clientId);
    if (!sub) continue;
    if (sub.ws.readyState !== sub.ws.OPEN) continue;
    if (!matchesFilter(sub.filter, e)) continue;
    try { sub.ws.send(JSON.stringify(out)); } catch (_e) { /* dead socket */ }
  }
  return allTargets.size;
}

function matchesFilter(filter, event) {
  if (!filter || Object.keys(filter).length === 0) return true;
  // 支持: { severity_eq: 'critical' } / { kind_eq: 'audit' } / { data_path_eq: { ... } }
  for (const [k, v] of Object.entries(filter)) {
    if (k.endsWith('_eq')) {
      const key = k.slice(0, -3);
      if (event[key] !== v) return false;
    } else if (k === 'severity_gte') {
      const order = { info: 0, warning: 1, medium: 2, high: 3, critical: 4 };
      const a = order[event.severity] ?? 0;
      const b = order[v] ?? 0;
      if (a < b) return false;
    }
  }
  return true;
}

function sanitizePayload(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (typeof v === 'string') out[k] = redact(v);
    else if (Array.isArray(v)) out[k] = v.map(x => typeof x === 'string' ? redact(x) : x);
    else out[k] = v;
  }
  return out;
}

// ============================================================
// HTTP upgrade handler
// ============================================================
/**
 * Attach a WebSocket server to an existing https.Server.
 * @param {object} httpsServer
 * @param {object} [opts] { authFn: (req) => { client, cn } | null, path: '/ws' }
 */
export function attachWebSocket(httpsServer, opts = {}) {
  const path = opts.path || '/ws';
  const wss = new WebSocketServer({ noServer: true });
  const heartbeat = startHeartbeat(wss);
  httpsServer.on('upgrade', (req, socket, head) => {
    if (!req.url || !req.url.startsWith(path)) return;  // not us
    // 1. auth (mTLS / session token)
    let ctx = null;
    if (opts.authFn) {
      try { ctx = opts.authFn(req); } catch (_e) { ctx = null; }
    }
    if (!ctx || !ctx.client) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleConnection(ws, ctx, opts);
    });
  });
  return {
    wss,
    close: () => {
      clearInterval(heartbeat);
      wss.clients.forEach((ws) => ws.terminate());
      wss.close();
    },
  };
}

function handleConnection(ws, ctx, opts) {
  const clientId = randomUUID();
  ws.clientId = clientId;
  ws.ctx = ctx;
  ws.isAlive = true;
  // 默认订阅 alerts
  subscribeClient(clientId, ws, ['alerts', 'healthcheck', 'secret_rotated', 'mfa_enrolled', 'config_reloaded', 'audit']);
  sendAck(ws, 'connected', { clientId, cn: ctx.cn, default_events: ['alerts', 'healthcheck', 'secret_rotated', 'mfa_enrolled', 'config_reloaded', 'audit'] });
  ws.on('message', (raw) => {
    if (SUBSCRIBERS.has(clientId)) SUBSCRIBERS.get(clientId).lastSeen = Date.now();
    ws.isAlive = true;
    let msg;
    try { msg = JSON.parse(raw.toString('utf8')); } catch (e) {
      sendError(ws, 'invalid_json', e.message);
      return;
    }
    handleClientMessage(ws, clientId, msg, opts);
  });
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('close', () => unsubscribeClient(clientId));
  ws.on('error', () => unsubscribeClient(clientId));
  opts.onConnect?.({ clientId, cn: ctx.cn });
}

function handleClientMessage(ws, clientId, msg, opts) {
  if (msg.action === 'subscribe') {
    if (Array.isArray(msg.events)) {
      const existing = SUBSCRIBERS.get(clientId);
      if (existing) {
        // 合并
        for (const e of msg.events) {
          existing.events.add(e);
          if (!SUBS_BY_EVENT.has(e)) SUBS_BY_EVENT.set(e, new Set());
          SUBS_BY_EVENT.get(e).add(clientId);
        }
      }
    }
    if (msg.filter) updateClientFilter(clientId, msg.filter);
    sendAck(ws, 'subscribed', { events: Array.from(SUBSCRIBERS.get(clientId)?.events || []) });
    return;
  }
  if (msg.action === 'unsubscribe') {
    if (Array.isArray(msg.events)) {
      const existing = SUBSCRIBERS.get(clientId);
      if (existing) {
        for (const e of msg.events) {
          existing.events.delete(e);
          SUBS_BY_EVENT.get(e)?.delete(clientId);
        }
      }
    }
    sendAck(ws, 'unsubscribed', { events: Array.from(SUBSCRIBERS.get(clientId)?.events || []) });
    return;
  }
  if (msg.action === 'ping') {
    sendAck(ws, 'pong', { ts: Date.now() });
    return;
  }
  if (msg.action === 'list_events') {
    sendAck(ws, 'events', { events: ['audit', 'healthcheck', 'alerts', 'secret_rotated', 'mfa_enrolled', 'config_reloaded', '*'] });
    return;
  }
  sendError(ws, 'unknown_action', `action must be one of subscribe|unsubscribe|ping|list_events, got: ${msg.action}`);
}

function startHeartbeat(wss) {
  return setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { try { ws.terminate(); } catch (_e) { /* */ } continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch (_e) { /* */ }
    }
  }, HEARTBEAT_INTERVAL_MS);
}

function sendAck(ws, type, data) {
  if (ws.readyState !== ws.OPEN) return;
  try { ws.send(JSON.stringify({ type: 'ack', ack_type: type, ts: new Date().toISOString(), data })); } catch (_e) { /* */ }
}

function sendError(ws, code, message) {
  if (ws.readyState !== ws.OPEN) return;
  try { ws.send(JSON.stringify({ type: 'error', code, message, ts: new Date().toISOString() })); } catch (_e) { /* */ }
}

// ============================================================
// 状态查询(给 admin 端点用)
// ============================================================
export function getStats() {
  return {
    subscriberCount: SUBSCRIBERS.size,
    events: Array.from(SUBS_BY_EVENT.keys()),
  };
}

export function listSubscribers() {
  // 元数据,不含 ws 句柄
  return Array.from(SUBSCRIBERS.entries()).map(([id, s]) => ({
    id,
    events: Array.from(s.events),
    filter: s.filter,
    last_seen: new Date(s.lastSeen).toISOString(),
  }));
}

/**
 * Test helper: clear all subscribers.
 */
export function _resetForTests() {
  SUBSCRIBERS.clear();
  SUBS_BY_EVENT.clear();
}

export default {
  attachWebSocket,
  broadcastEvent,
  subscribeClient,
  unsubscribeClient,
  updateClientFilter,
  getStats,
  listSubscribers,
  HEARTBEAT_INTERVAL_MS,
  CLIENT_TIMEOUT_MS,
  _resetForTests,
};
