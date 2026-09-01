// broker/lib/risk-score.js — V4 5-dimension risk score
// Pure function over request context, no I/O. Used by mfa-policy.js
// to decide whether to require 0/1/2 factors.

import { isIpAllowed } from './ip-allowlist.js';

/**
 * Actions that always require a second factor, regardless of score.
 * Tracked here so mfa-policy.js and server.js share one source of truth.
 */
export const SENSITIVE_ACTIONS = new Set([
  'rotate-cert',
  'delete-secret',
  'revoke-api-key',
  'admin:reload',
  'change-password',
  'change-phone',
  'disable-totp',
  'add-webauthn',
  'disable-webauthn',
  'rotate-secret',
  'add-ssh-key',
]);

/**
 * Compute a 0-100 risk score with named contributing factors.
 *
 * Dimensions (each contributes additive points):
 *   1. unusual_ip           +30  IP not in client.ip_whitelist
 *   2. stale_account        +20  last login > 30 days, +10 if > 7 days
 *   3. sensitive_action     +25  ctx.action is in SENSITIVE_ACTIONS
 *   4. unusual_hour         +10  current local hour 0-5 or 23
 *   5. user_agent_changed   +15  ctx.user_agent != ctx.last_user_agent
 *
 * Capped at 100.
 *
 * @param {{
 *   source_ip?: string,
 *   client?: { ip_whitelist?: string[] },
 *   last_login_at?: number|null,
 *   action?: string,
 *   user_agent?: string,
 *   last_user_agent?: string,
 *   now?: Date,
 * }} ctx
 * @returns {{ score: number, factors: string[] }}
 */
export function calcRiskScore(ctx = {}) {
  let score = 0;
  const factors = [];

  // 1. IP not in whitelist
  if (ctx.source_ip && ctx.client) {
    if (!isIpAllowed(ctx.client.ip_whitelist, ctx.source_ip)) {
      score += 30;
      factors.push('unusual_ip');
    }
  }

  // 2. Account staleness
  if (typeof ctx.last_login_at === 'number' && ctx.last_login_at > 0) {
    const now = ctx.now ? ctx.now.getTime() : Date.now();
    const days = (now - ctx.last_login_at) / 86_400_000;
    if (days > 30) {
      score += 20;
      factors.push('stale_account');
    } else if (days > 7) {
      score += 10;
      factors.push('stale_account_minor');
    }
  }

  // 3. Sensitive action
  if (ctx.action && SENSITIVE_ACTIONS.has(ctx.action)) {
    score += 25;
    factors.push('sensitive_action');
  }

  // 4. Unusual hour (local)
  const now = ctx.now instanceof Date ? ctx.now : new Date(ctx.now || Date.now());
  const hour = now.getHours();
  if (hour < 6 || hour >= 23) {
    score += 10;
    factors.push('unusual_hour');
  }

  // 5. User-Agent change
  if (ctx.user_agent && ctx.last_user_agent && ctx.user_agent !== ctx.last_user_agent) {
    score += 15;
    factors.push('user_agent_changed');
  }

  if (score > 100) score = 100;
  return { score, factors };
}
