// broker/lib/mfa-policy.js — V4 MFA policy engine
// Decides whether a request needs 0/1/2 second-factor credentials
// based on role, risk score, action, and configuration.
//
// Pure functions. Caller (auth-flow.js / routes/auth.js) loads
// the active policy and feeds it the per-request context.

import { calcRiskScore, SENSITIVE_ACTIONS } from './risk-score.js';

/**
 * Default policy (used when broker.yaml has no mfa_policy block).
 * Safe-by-default: developers get 1 factor on sensitive or unusual,
 * admins always need 1, ci never.
 */
export const DEFAULT_POLICY = {
  default_policy: {
    developer: {
      primary: ['mtls', 'password'],
      secondary_required_when: ['unusual_ip', 'no_mtls', 'sensitive_action'],
      secondary_options: ['totp', 'webauthn', 'sms', 'recovery'],
      secondary_min_count: 1,
    },
    admin: {
      primary: ['mtls', 'password'],
      secondary_required_when: ['always'],
      secondary_options: ['totp', 'webauthn'],
      secondary_min_count: 1,
    },
    ci: {
      primary: ['mtls'],
      secondary_required_when: [],
      secondary_options: [],
      secondary_min_count: 0,
    },
  },
  risk_score_thresholds: {
    no_mfa: 20,
    require_one: 60,
    require_two: 100,
  },
  sensitive_actions: [...SENSITIVE_ACTIONS],
};

/**
 * Load the policy from broker config. Falls back to DEFAULT_POLICY
 * when the block is absent.
 */
export function loadMfaPolicy(config) {
  if (!config || typeof config !== 'object') return DEFAULT_POLICY;
  const p = config.mfa_policy;
  if (!p || typeof p !== 'object') return DEFAULT_POLICY;
  return {
    default_policy: { ...DEFAULT_POLICY.default_policy, ...(p.default_policy || {}) },
    risk_score_thresholds: {
      ...DEFAULT_POLICY.risk_score_thresholds,
      ...(p.risk_score_thresholds || {}),
    },
    sensitive_actions: p.sensitive_actions || DEFAULT_POLICY.sensitive_actions,
  };
}

/**
 * Pick the policy block for a given role, defaulting to 'developer'.
 */
function policyForRole(policy, role) {
  return policy.default_policy[role] || policy.default_policy.developer || DEFAULT_POLICY.default_policy.developer;
}

/**
 * Decide what (if any) second factor is required.
 *
 * Returns:
 *   {
 *     mfa_required: boolean,
 *     min_count: 0 | 1 | 2,
 *     options: string[],          // allowed factor types in priority order
 *     reason: string,             // 'low_risk' | 'medium_risk' | 'high_risk' |
 *                                 // 'role_always' | 'sensitive_action' | 'no_client'
 *     factors: string[],          // from calcRiskScore
 *     score: number,
 *   }
 *
 * @param {{
 *   client?: { role?: string, allow_password_login?: boolean, factors?: object, ip_whitelist?: string[] } | null,
 *   action?: string,
 *   source_ip?: string,
 *   last_login_at?: number|null,
 *   user_agent?: string,
 *   last_user_agent?: string,
 *   now?: Date,
 * }} ctx
 * @param {object} [config] broker config (for mfa_policy block)
 */
export function decideMfaRequirement(ctx, config) {
  if (!ctx || !ctx.client) {
    // No identity -> force full second factor (caller should reject anyway)
    return {
      mfa_required: true,
      min_count: 1,
      options: ['totp', 'webauthn', 'sms', 'recovery'],
      reason: 'no_client',
      factors: [],
      score: 0,
    };
  }
  const policy = loadMfaPolicy(config);
  const cp = policyForRole(policy, ctx.client.role);

  const riskCtx = {
    source_ip: ctx.source_ip,
    client: ctx.client,
    last_login_at: ctx.last_login_at,
    action: ctx.action,
    user_agent: ctx.user_agent,
    last_user_agent: ctx.last_user_agent,
    now: ctx.now,
  };
  const { score, factors } = calcRiskScore(riskCtx);

  // 1. Sensitive action always requires at least 1 factor (early-out, fixed min 1)
  const action = ctx.action || '';
  if (SENSITIVE_ACTIONS.has(action)) {
    return {
      mfa_required: true,
      min_count: Math.max(1, cp.secondary_min_count || 1),
      options: cp.secondary_options,
      reason: 'sensitive_action',
      factors,
      score,
    };
  }

  // Determine if MFA is required (three reasons: always / trigger_match / risk)
  const triggers = cp.secondary_required_when || [];
  let mfa_required = false;
  let base_reason = 'low_risk';

  if (triggers.includes('always')) {
    mfa_required = true;
    base_reason = 'role_always';
  } else if (factors.length > 0 && factors.some(f => triggers.includes(f))) {
    mfa_required = true;
    base_reason = 'trigger_match';
  }

  // Risk score may independently require MFA (e.g. multiple minor factors add up)
  const t = policy.risk_score_thresholds;
  if (score > t.no_mfa) mfa_required = true;
  if (score > t.require_one) base_reason = 'high_risk';
  else if (score > t.no_mfa) base_reason = base_reason === 'low_risk' ? 'medium_risk' : base_reason;

  if (!mfa_required) {
    return { mfa_required: false, min_count: 0, options: [], reason: 'low_risk', factors, score };
  }

  // Determine min_count: high risk = 2, otherwise 1 (or policy override)
  let min_count;
  if (score > t.require_one) {
    min_count = 2;
  } else {
    min_count = Math.max(1, cp.secondary_min_count || 1);
  }

  return {
    mfa_required: true,
    min_count,
    options: cp.secondary_options,
    reason: base_reason,
    factors,
    score,
  };
}

/**
 * Given a partially-completed MFA session (with verified_factors), decide
 * whether the user must keep submitting factors or whether the session
 * is now fully authenticated.
 *
 * @param {string[]} verifiedFactors   e.g. ['totp']
 * @param {{min_count:number, options:string[]}} decision
 * @returns {{ satisfied: boolean, remaining: number, next_options: string[] }}
 */
export function checkMfaProgress(verifiedFactors, decision) {
  if (!decision || !decision.mfa_required) {
    return { satisfied: true, remaining: 0, next_options: [] };
  }
  // Compute remaining distinct options that haven't been verified
  const verifiedSet = new Set(verifiedFactors || []);
  const remainingOptions = (decision.options || []).filter(o => !verifiedSet.has(o));
  const need = Math.max(0, (decision.min_count || 1) - (verifiedFactors || []).length);
  return {
    satisfied: need === 0,
    remaining: need,
    next_options: remainingOptions,
  };
}
