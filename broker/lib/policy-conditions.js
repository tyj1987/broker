import { BlockList, isIP } from 'node:net';

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

function timestamp(value) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string' || !RFC3339.test(value)) return Number.NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function address(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  const mapped = trimmed.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  const normalized = mapped && isIP(mapped[1]) === 4 ? mapped[1] : trimmed;
  const family = isIP(normalized);
  return family ? { value: normalized, family: family === 4 ? 'ipv4' : 'ipv6' } : null;
}

function sourceMatcher(cidrs) {
  if (cidrs == null) return { ok: true, blockList: null };
  if (!Array.isArray(cidrs) || cidrs.length === 0) return { ok: false };
  const blockList = new BlockList();
  try {
    for (const raw of cidrs) {
      if (typeof raw !== 'string') return { ok: false };
      const separator = raw.lastIndexOf('/');
      if (separator <= 0) return { ok: false };
      const network = address(raw.slice(0, separator));
      const prefix = Number(raw.slice(separator + 1));
      const maximum = network?.family === 'ipv4' ? 32 : 128;
      if (!network || !Number.isInteger(prefix) || prefix < 0 || prefix > maximum)
        return { ok: false };
      blockList.addSubnet(network.value, prefix, network.family);
    }
  } catch {
    return { ok: false };
  }
  return { ok: true, blockList };
}

export function validatePolicyConditions(policy = {}) {
  const notBefore = timestamp(policy.not_before);
  const notAfter = timestamp(policy.not_after);
  if (Number.isNaN(notBefore) || Number.isNaN(notAfter))
    return { ok: false, reason: 'invalid_policy_time' };
  if (notBefore != null && notAfter != null && notBefore >= notAfter) {
    return { ok: false, reason: 'invalid_policy_time_window' };
  }
  const matcher = sourceMatcher(policy.source_cidrs);
  if (!matcher.ok) return { ok: false, reason: 'invalid_source_cidrs' };
  return { ok: true, notBefore, notAfter, sourceBlockList: matcher.blockList };
}

export function evaluatePolicyConditions(policy, sourceIP, now = Date.now()) {
  const compiled = validatePolicyConditions(policy);
  if (!compiled.ok || !Number.isFinite(now))
    return { ok: false, reason: compiled.reason || 'invalid_policy_time' };
  if (compiled.notBefore != null && now < compiled.notBefore)
    return { ok: false, reason: 'outside_time_window' };
  if (compiled.notAfter != null && now >= compiled.notAfter)
    return { ok: false, reason: 'outside_time_window' };
  if (compiled.sourceBlockList) {
    const candidate = address(sourceIP);
    if (!candidate || !compiled.sourceBlockList.check(candidate.value, candidate.family)) {
      return { ok: false, reason: 'source_ip_denied' };
    }
  }
  return { ok: true };
}
