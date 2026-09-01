// broker/lib/alerting.js — V4 多渠道告警
// Channels: console (always), slack/feishu/dingtalk/discord webhook (configurable),
// email (SMTP, optional).
//
// Pure function over (event, config) — does not perform IO itself except
// through injected sinks. Tests can pass mock sinks.

import { redact } from './redact.js';

const SEVERITY_ORDER = { info: 0, warning: 1, medium: 2, high: 3, critical: 4 };

/**
 * Resolve which channels a given event should go to.
 * @param {object} cfg     broker config
 * @param {object} event   { severity, title, detail, actions, ts }
 * @returns {Array<{type, target, payload}>}
 */
export function routeEvent(cfg, event) {
  if (!cfg || !cfg.alerting || !cfg.alerting.channels) return [];
  const out = [];
  for (const ch of cfg.alerting.channels) {
    if (!matchesTrigger(ch, event)) continue;
    out.push({
      type: ch.type,
      target: resolveTarget(ch),
      payload: buildPayload(ch, event),
    });
  }
  // sort by severity
  out.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));
  return out;
}

function matchesTrigger(channel, event) {
  if (!channel.events || channel.events.length === 0) return true;
  if (channel.events.includes('*')) return true;  // wildcard
  return channel.events.includes(event.title) || channel.events.includes(event.kind);
}

function resolveTarget(channel) {
  // For 'webhook' types, target is the URL
  // For 'email', target is the SMTP secret
  // For 'console', target is null (we just log)
  if (channel.type === 'console') return null;
  if (channel.url) return channel.url;
  if (channel.smtp) return channel.smtp;
  return null;
}

function buildPayload(channel, event) {
  const safe = {
    severity: event.severity,
    title: redact(event.title || ''),
    detail: redact(event.detail || ''),
    actions: event.actions || [],
    ts: event.ts || new Date().toISOString(),
    request_id: event.request_id,
  };
  if (channel.type === 'slack_webhook' || channel.type === 'feishu_webhook'
      || channel.type === 'dingtalk_webhook' || channel.type === 'discord_webhook') {
    return {
      text: `*[${safe.severity}]* ${safe.title}\n${safe.detail}`,
      // Slack expects blocks/attachments; for simplicity we use text.
      // The webhook can format with markdown.
    };
  }
  if (channel.type === 'email') {
    return {
      subject: `[${safe.severity}] ${safe.title}`,
      body: `${safe.detail}\n\nRequest ID: ${safe.request_id || 'n/a'}\nTS: ${safe.ts}`,
    };
  }
  return safe;
}

/**
 * Send event through one channel sink. Returns { ok, error? }.
 * Sinks can be: console.log, fetch to webhook URL, SMTP transport.
 * Caller is responsible for providing a working send function.
 *
 * @param {{type:string, target:string|null, payload:object}} route
 * @param {{
 *   fetchImpl?: typeof fetch,
 *   consoleImpl?: Console,
 *   emailImpl?: (to, msg) => Promise<void>,
 * }} sinks
 * @returns {Promise<{ok:boolean, error?:string}>}
 */
export async function dispatchAlert(route, sinks = {}) {
  const fetchImpl = sinks.fetchImpl || globalThis.fetch;
  const consoleImpl = sinks.consoleImpl || console;
  // 凭据零接触: 分发前对 payload 中所有可能含凭据的字符串字段做 redact
  const safePayload = sanitizePayload(route.payload);
  try {
    if (route.type === 'console') {
      const level = safePayload.severity === 'critical' || safePayload.severity === 'high' ? 'error'
        : safePayload.severity === 'warning' || safePayload.severity === 'medium' ? 'warn'
        : 'info';
      consoleImpl[level](`[alert] ${safePayload.title}: ${safePayload.detail}`);
      return { ok: true };
    }
    if (route.type === 'slack_webhook' || route.type === 'feishu_webhook'
        || route.type === 'dingtalk_webhook' || route.type === 'discord_webhook') {
      if (!route.target) return { ok: false, error: 'no webhook url' };
      const res = await fetchImpl(route.target, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(safePayload),
      });
      if (!res.ok) return { ok: false, error: `webhook ${res.status}` };
      return { ok: true };
    }
    if (route.type === 'email') {
      if (!sinks.emailImpl) return { ok: false, error: 'no email impl' };
      await sinks.emailImpl(route.target, safePayload);
      return { ok: true };
    }
    return { ok: false, error: `unknown channel type: ${route.type}` };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
}

function sanitizePayload(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (typeof v === 'string') {
      out[k] = redact(v);
    } else if (Array.isArray(v)) {
      out[k] = v.map(item => typeof item === 'string' ? redact(item) : item);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Send an event through all channels.
 * @param {object} cfg
 * @param {object} event
 * @param {object} sinks
 * @returns {Promise<Array<{route, result: {ok, error?}}>>}
 */
export async function alert(cfg, event, sinks) {
  const routes = routeEvent(cfg, event);
  if (routes.length === 0) return [];
  return Promise.all(routes.map(async (r) => ({ route: r, result: await dispatchAlert(r, sinks) })));
}

export default { routeEvent, dispatchAlert, alert };
