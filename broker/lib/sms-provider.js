// broker/lib/sms-provider.js — V4 pluggable SMS provider interface
// Sends one-time codes for SMS-based second factor.
// Provider implementations are pluggable; default is no-op stub.

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
 * No-op stub used when no provider configured. Logs and returns fake id.
 * Tests and offline dev use this so broker boots without real SMS credentials.
 */
export const stubSmsProvider = {
  name: 'stub',
  async send(phone, code, opts = {}) {
    // eslint-disable-next-line no-console
    console.log(`[sms-stub] would send to ${phone}: code=${code} (set sms.providers in broker.yaml to enable real send)`);
    return { message_id: `stub-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, provider: 'stub' };
  },
};

/**
 * Webhook-based provider. POSTs a JSON payload to the configured URL.
 * Suitable for self-hosted gateways or in-cluster senders.
 */
export function makeWebhookSmsProvider(opts) {
  if (!opts || !opts.url) {
    throw new Error('webhook SMS provider requires { url }');
  }
  const headers = Object.assign({ 'content-type': 'application/json' }, opts.headers || {});
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
      const res = await fetch(opts.url, { method: 'POST', headers, body });
      if (!res.ok) {
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
    if (!cfg || !cfg.providers || typeof cfg.providers !== 'object') {
      return new SmsRegistry({ stub: stubSmsProvider }, 'stub');
    }
    const out = { stub: stubSmsProvider };
    for (const [name, p] of Object.entries(cfg.providers)) {
      if (!p || typeof p !== 'object') continue;
      if (p.type === 'webhook') {
        out[name] = makeWebhookSmsProvider({ url: p.url, headers: p.headers });
      }
      // Future: 'aliyun', 'tencent', 'twilio' -- implement as dedicated modules
    }
    return new SmsRegistry(out, cfg.default);
  }

  /**
   * Send a 6-digit code via the default (or named) provider.
   * @returns {Promise<SmsSendResult>}
   */
  send(phone, code, opts) {
    const name = (opts && opts.provider) || this.defaultName;
    const p = this.providers[name] || stubSmsProvider;
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
