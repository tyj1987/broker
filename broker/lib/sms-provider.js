// broker/lib/sms-provider.js — V4 pluggable SMS provider interface
// Sends one-time codes for SMS-based second factor.
// Provider implementations are pluggable. Production never falls back to a stub.

/**
 * @typedef {Object} SmsSendResult
 * @property {string} message_id
 * @property {number} [cost]   in local currency (cents)
 * @property {string} [provider]  which provider handled it
 */

/**
 * @typedef {Object} SmsProvider
 * @property {string} name
 * @property {(phone:string, code:string, opts?:object) => Promise<SmsSendResult>} send
 * @property {(messageId:string) => Promise<{status: 'sent'|'delivered'|'failed'}>} [query]
 */

/**
 * No-op stub for tests and local development. It deliberately does not log
 * the phone number or code.
 */
export const stubSmsProvider = {
  name: 'stub',
  async send(phone, code, opts = {}) {
    if (process.env.NODE_ENV === 'production' && opts.allow_stub !== true) {
      throw new Error('stub SMS provider is disabled in production');
    }
    return { message_id: `stub-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, provider: 'stub' };
  },
};

const FORBIDDEN_WEBHOOK_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function normalizeWebhookHeaders(value) {
  if (value === undefined) return { 'content-type': 'application/json' };
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('webhook SMS headers must be an object');
  }
  const headers = { 'content-type': 'application/json' };
  for (const [rawName, rawValue] of Object.entries(value)) {
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name) || FORBIDDEN_WEBHOOK_HEADERS.has(name)) {
      throw new Error(`webhook SMS header is not allowed: ${rawName}`);
    }
    if (typeof rawValue !== 'string' || /[\r\n]/.test(rawValue)) {
      throw new Error(`webhook SMS header has an invalid value: ${rawName}`);
    }
    headers[name] = rawValue;
  }
  return headers;
}

function validateWebhookUrl(value, allowInsecure) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('webhook SMS provider requires a valid URL');
  }
  if ((!allowInsecure && url.protocol !== 'https:')
    || (allowInsecure && !['http:', 'https:'].includes(url.protocol))
    || url.username || url.password || url.search || url.hash || !url.hostname) {
    throw new Error('webhook SMS URL must be an HTTPS origin-relative endpoint without credentials, query, or fragment');
  }
  return url.toString();
}

/**
 * Webhook-based provider. POSTs a JSON payload to the configured URL.
 * Suitable for self-hosted gateways or in-cluster senders.
 */
export function makeWebhookSmsProvider(opts, dependencies = {}) {
  if (!opts || !opts.url) {
    throw new Error('webhook SMS provider requires { url }');
  }
  const allowInsecure = opts.allow_insecure === true && process.env.NODE_ENV !== 'production';
  const url = validateWebhookUrl(opts.url, allowInsecure);
  const headers = normalizeWebhookHeaders(opts.headers);
  const timeoutMs = Math.min(Math.max(Number(opts.timeout_ms || 10_000), 1_000), 30_000);
  const fetchImpl = dependencies.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('webhook SMS provider requires fetch support');
  return {
    name: 'webhook',
    async send(phone, code, opts2 = {}) {
      const body = JSON.stringify({
        phone,
        code,
        ttl_seconds: opts2.ttl_seconds || 300,
        from: opts2.from,
        template: opts2.template,
      });
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      timeout.unref?.();
      let res;
      try {
        res = await fetchImpl(url, {
          method: 'POST',
          headers,
          body,
          redirect: 'manual',
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }
      if (!res.ok) {
        await res.body?.cancel();
        throw new Error(`webhook SMS send failed: ${res.status} ${res.statusText}`);
      }
      const data = await res.json().catch(() => ({}));
      return {
        message_id: data.message_id || data.id || `wh-${Date.now()}`,
        provider: 'webhook',
        cost: data.cost,
      };
    },
  };
}

/**
 * Registry: resolved at startup from broker.yaml sms.providers block.
 *
 *   sms:
 *     default: aliyun
 *     providers:
 *       aliyun:
 *         type: webhook
 *         url: 'https://mysms.example.com/aliyun'
 *       twilio:
 *         type: webhook
 *         url: 'https://mysms.example.com/twilio'
 *         headers:
 *           authorization: 'Bearer xxx'
 */
export class SmsRegistry {
  /**
   * @param {Record<string, SmsProvider>} providers
   * @param {string} [defaultName]
   */
  constructor(providers = {}, defaultName = null) {
    this.providers = providers;
    this.defaultName = defaultName || Object.keys(providers)[0] || 'stub';
  }

  static fromConfig(cfg) {
    const production = process.env.NODE_ENV === 'production';
    if (!cfg || !cfg.providers || typeof cfg.providers !== 'object') {
      if (production) throw new Error('SMS providers must be configured in production');
      return new SmsRegistry({ stub: stubSmsProvider }, 'stub');
    }
    const out = production ? {} : { stub: stubSmsProvider };
    for (const [name, p] of Object.entries(cfg.providers)) {
      if (!p || typeof p !== 'object') throw new Error(`SMS provider has an invalid configuration: ${name}`);
      if (p.type === 'webhook') {
        out[name] = makeWebhookSmsProvider({
          url: p.url,
          headers: p.headers,
          timeout_ms: p.timeout_ms,
          allow_insecure: p.allow_insecure,
        });
      } else if (p.type === 'stub' && !production) {
        out[name] = stubSmsProvider;
      } else {
        throw new Error(`unsupported SMS provider type: ${name}`);
      }
      // Future: 'aliyun', 'tencent', 'twilio' -- implement as dedicated modules
    }
    const defaultName = cfg.default || Object.keys(out)[0];
    if (!defaultName || !out[defaultName]) {
      if (production) throw new Error('SMS default provider must name a configured production provider');
      return new SmsRegistry({ stub: stubSmsProvider }, 'stub');
    }
    return new SmsRegistry(out, defaultName);
  }

  /**
   * Send a 6-digit code via the default (or named) provider.
   * @returns {Promise<SmsSendResult>}
   */
  send(phone, code, opts) {
    const name = (opts && opts.provider) || this.defaultName;
    const p = this.providers[name];
    if (!p) throw new Error(`SMS provider is not configured: ${name}`);
    return p.send(phone, code, opts || {});
  }
}

/**
 * Convenience: format a 6-digit code (or override).
 * Uses crypto.randomInt for unbiased generation.
 */
export function generateSmsCode(length = 6) {
  const n = length || 6;
  if (n < 4 || n > 10) throw new Error('sms code length must be 4..10');
  const max = 10 ** n;
  const min = 10 ** (n - 1);
  return String(cryptoRandomInt(min, max));
}

// Use Node crypto for unbiased random
import { randomInt as cryptoRandomInt } from 'node:crypto';
