# V4.2.0 Design Spec (2026-09-06)

> **Status**: P3 #12 partial — design spec, no code yet
> **ROADMAP**: target 2027-06-30
> **Source**: [ROADMAP-post-1.0.md §12](../ROADMAP-post-1.0.md#12-v42.0-q2-2027)
> **Baseline**: broker V4.1.x (V4.1.0 GA + V4.1.1 patch in flight)

---

## 1. Goals

V4.2.0 extends the V4.1 foundation with **4 enterprise-grade features**:

1. **Per-tenant rate limiting** — multi-tenant deployments
2. **Attribute-based access control (ABAC)** — fine-grained, dynamic authorization
3. **Secret versioning with diff UI** — track + audit secret value changes
4. **Approval workflow for high-risk secret access** — formal gate for high-risk operations

V4.2.0 is a **minor version** (backward-compatible); no breaking changes to
existing V4.1.x deployments. All new features are opt-in via configuration.

## 2. Why these 4 features

### 2.1 Per-tenant rate limiting

V4.1.x has **per-client rate limiting** (minute/hour/day + IP allowlist +
hierarchical API keys). Multi-tenant deployments (e.g. broker as SaaS
for multiple companies) need **per-tenant** (not per-client) limits:

- Tenant A (small company) can have 100 req/min
- Tenant B (large company) can have 10000 req/min
- Tenant C (premium) can have unlimited

Limits enforced at edge (nginx ingress) + broker core.

### 2.2 ABAC (Attribute-based access control)

V4.1.x uses **RBAC** (role-based: admin/operator/developer/viewer) +
**resource grants** (API-key allowed_secrets + allowed_services +
allowed_operations). For enterprise scale, ABAC adds:

- **Time-of-day** policies (e.g. "this developer can only access
  production secrets between 9am-6pm Mon-Fri")
- **Geo-location** policies (e.g. "this client can only access from US")
- **Action context** (e.g. "this token can only decrypt, not re-encrypt")
- **Risk score** (V4.1.x already computes risk; ABAC uses it as attribute)

ABAC builds on RBAC, doesn't replace it.

### 2.3 Secret versioning with diff UI

V4.1.x has `auto-rotate` (advance warning + auto-rotation + git rollback)
but **no version history**. V4.2.0 adds:

- Every secret value change creates a new version (immutable)
- Diff UI shows: "v3 → v4: value changed by maintainer Y at time Z"
- Time-travel debug: "what was the GitHub PAT at 3pm yesterday?"
- Audit trail: who / when / why for each version

V4.1.x already stores `updated_at`; V4.2.0 adds `version_count` +
`version_history` (encrypted SOPS).

### 2.4 Approval workflow for high-risk access

V4.1.x has WebAuthn 2-person approval for **mutations** (client/secret/
service create/update/delete). V4.2.0 extends to **high-risk access**:

- "View GitHub PAT" → no approval (low risk)
- "Decrypt AWS access_key" → no approval (low risk, it's just a string)
- "Use AWS access_key to make a sensitive API call" (e.g. delete
  production S3 bucket) → **approval required** (high risk)
- "Bulk export 1000 secrets" → **approval required** (high risk)

Approval workflow: requester submits → 2nd admin approves with WebAuthn
reauth → broker executes the operation → audit logged.

## 3. Per-tenant rate limiting

### 3.1 Current state (V4.1.x)

- **Per-client rate limit**: `broker/api-keys.js` (27 tests)
  - `rate_limit: { minute: 60, hour: 1000, day: 10000 }`
  - Default deny if rate limit exceeded
- **Per-IP allowlist**: `broker/lib/ip-allowlist.js` (21 tests)
  - CIDR-based, per-client
- **Hierarchical API keys**: parent + child grants (intersection)

### 3.2 V4.2.0 design

#### 3.2.1 Multi-tenant config

```yaml
# secrets/broker.yaml (excerpt)
tenants:
  - id: tenant-a
    name: "Acme Corp"
    plan: "small"
    rate_limit: { minute: 100, hour: 5000, day: 50000 }
    monthly_quota: 100000  # calls
    geographic_restrictions: ["US", "CA"]
  - id: tenant-b
    name: "BigCo"
    plan: "large"
    rate_limit: { minute: 10000, hour: 200000, day: 2000000 }
    monthly_quota: 5000000
  - id: tenant-c
    name: "PremiumCo"
    plan: "premium"
    rate_limit: null  # unlimited
    monthly_quota: null
```

#### 3.2.2 Tenant resolution

Each client (mTLS cert fingerprint) maps to exactly 1 tenant:

```yaml
# secrets/clients.json (excerpt)
{
  "client.dashboard-admin-acme": {
    "tenant": "tenant-a",
    "role": "admin",
    "mfa_policy": "strict"
  },
  "client.dashboard-admin-bigco": {
    "tenant": "tenant-b",
    "role": "admin"
  }
}
```

Tenant lookup: O(1) hash by client name. Cached in `BrokerCache` (in-memory, 5-min TTL).

#### 3.2.3 Rate limit enforcement

```typescript
// broker/lib/tenant-rate-limit.ts (new in V4.2.0)
function checkRateLimit(tenant: Tenant, client: Client): boolean {
  const now = Date.now();
  const minuteKey = `${tenant.id}:${Math.floor(now / 60000)}`;
  const hourKey = `${tenant.id}:${Math.floor(now / 3600000)}`;
  const dayKey = `${tenant.id}:${Math.floor(now / 86400000)}`;

  const minuteCount = redis.get(minuteKey) || 0;
  const hourCount = redis.get(hourKey) || 0;
  const dayCount = redis.get(dayKey) || 0;

  if (tenant.rate_limit?.minute && minuteCount >= tenant.rate_limit.minute) return false;
  if (tenant.rate_limit?.hour && hourCount >= tenant.rate_limit.hour) return false;
  if (tenant.rate_limit?.day && dayCount >= tenant.rate_limit.day) return false;

  redis.incr(minuteKey); redis.expire(minuteKey, 60);
  redis.incr(hourKey); redis.expire(hourKey, 3600);
  redis.incr(dayKey); redis.expire(dayKey, 86400);
  return true;
}
```

**Counter store**: Redis (new dependency — see §3.2.4) or in-memory
`BrokerCache` (loses state on restart).

#### 3.2.4 Redis dependency (new in V4.2.0)

V4.1.x has **0 hard deps** in Node SDK. V4.2.0 server adds **Redis**
(`ioredis` package) as an **optional** dependency:

- If `REDIS_URL` env set → use Redis (multi-instance rate limit)
- If not set → fall back to in-memory (single-instance only)

This is the **first** new broker hard dep. Documented in
[SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md) — supply chain
risk: Redis has 0 known CVEs but is C codebase; monitor for updates.

#### 3.2.5 Quota enforcement (monthly)

```typescript
// broker/lib/tenant-quota.ts (new in V4.2.0)
function checkQuota(tenant: Tenant): boolean {
  if (!tenant.monthly_quota) return true;  // unlimited
  const monthKey = `${tenant.id}:${new Date().toISOString().slice(0, 7)}`;  // "2026-09"
  const usage = redis.get(monthKey) || 0;
  return usage < tenant.monthly_quota;
}
```

When quota exceeded: HTTP 429 + `Retry-After: <days-until-month-end>`.

#### 3.2.6 Edge enforcement (nginx)

```nginx
# /etc/nginx/nginx.conf (excerpt)
limit_req_zone $arg_tenant zone=tenants:10m rate=100r/s;
limit_req zone=tenants burst=200 nodelay;
limit_req_status 429;
```

Tenant ID passed as query param (`?tenant=tenant-a`) or
`X-Tenant-ID` header (forwarded by broker to nginx).

### 3.3 Tests

`broker-test/test-tenant-rate-limit.js` (target 30 tests):
- Per-tenant minute/hour/day enforcement
- Burst tolerance
- Quota exceeded returns 429
- Tenant lookup O(1)
- Multi-tenant isolation (Tenant A usage doesn't count against Tenant B)
- Redis fallback to in-memory

### 3.4 Migration from V4.1.x

- Default tenant created for backward compat: `default` (id="default")
- Existing clients → `default` tenant
- `broker.yaml` schema: add `tenants: [Tenant]` (optional, defaults to `[{ id: "default", name: "Default", plan: "small", rate_limit: { minute: 60, hour: 1000, day: 10000 } }]`)

## 4. ABAC (Attribute-based access control)

### 4.1 Current state (V4.1.x)

- **RBAC**: 4 roles (admin / operator / developer / viewer)
- **Resource grants**: API-key `allowed_secrets` + `allowed_services` + `allowed_operations`
- **Typed operation policy decision point**: per-operation ACL
- **Risk score**: 5 dimensions (role / source_ip / last_login / sensitive_action / unusual_hour)

### 4.2 V4.2.0 design

#### 4.2.1 ABAC attribute set

```yaml
# secrets/broker.yaml (excerpt)
abac:
  enabled: true
  attributes:
    - name: "request.time_of_day"
      type: time
      range: "09:00-18:00"  # 9am-6pm
    - name: "request.day_of_week"
      type: enum
      values: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    - name: "request.geo_country"
      type: enum
      values: ["US", "CA", "MX"]
    - name: "client.mfa_level"
      type: enum
      values: ["AAL1", "AAL2", "AAL3"]
    - name: "action.risk_score"
      type: number
      range: [0, 100]
    - name: "action.sensitive"
      type: boolean
    - name: "secret.classification"
      type: enum
      values: ["public", "internal", "confidential", "secret"]
  policies:
    - name: "developer-mfa-strict-prod"
      effect: "allow"
      when: >
        client.role == "developer" AND
        action.sensitive == true AND
        request.time_of_day in 09:00-18:00 AND
        request.day_of_week in [Monday, Tuesday, Wednesday, Thursday, Friday] AND
        request.geo_country in [US, CA, MX] AND
        client.mfa_level == "AAL3"
      actions: ["secret.decrypt"]
      resources: ["secrets:prod-*"]
    - name: "viewer-no-sensitive"
      effect: "deny"
      when: >
        client.role == "viewer" AND
        action.sensitive == true
      actions: ["*"]
      resources: ["*"]
```

#### 4.2.2 ABAC engine

```typescript
// broker/lib/abac.ts (new in V4.2.0)
function evaluate(request: ABACRequest, policies: ABACPolicy[]): ABACDecision {
  // Attribute resolution
  const attrs = resolveAttributes(request);

  // Policy evaluation: first match wins
  for (const policy of policies) {
    if (matchesExpression(policy.when, attrs)) {
      return {
        effect: policy.effect,
        matchedPolicy: policy.name,
        audit: { ...attrs, timestamp: Date.now() }
      };
    }
  }

  // Default deny
  return { effect: "deny", matchedPolicy: null, reason: "no_policy_matched" };
}
```

Expression language: subset of [Common Expression Language (CEL)](https://github.com/google/cel-spec)
— well-tested, fast parser, supports attribute lookups + comparisons.

#### 4.2.3 Audit integration

Every ABAC decision logged in audit log:

```json
{
  "timestamp": "2026-09-06T15:30:00Z",
  "client": "client.dashboard-admin-acme",
  "action": "secret.decrypt",
  "resource": "secrets:prod-aws-key",
  "decision": "allow",
  "matched_policy": "developer-mfa-strict-prod",
  "attributes": {
    "request.geo_country": "US",
    "client.mfa_level": "AAL3",
    "action.risk_score": 35
  }
}
```

#### 4.2.4 Tests

`broker-test/test-abac.js` (target 50 tests):
- Policy expression evaluation
- Attribute resolution (request/client/action/secret)
- Default deny
- First-match-wins
- Audit integration
- Geo-IP resolution
- Time-of-day resolution
- Risk score threshold

### 4.3 Migration from V4.1.x

- ABAC is **opt-in** (default off); existing RBAC + resource grants continue
- When `abac.enabled: true`, ABAC engine runs **before** RBAC
- Default policy: allow (passes through to RBAC)

## 5. Secret versioning + diff UI

### 5.1 Current state (V4.1.x)

- `secrets/secrets-detail.json` stores: `value`, `updated_at`, `last_rotated_at`
- `auto-rotate` (advance warning + rotation) updates `value` + `updated_at`
- **No version history** — old values are lost on rotation

### 5.2 V4.2.0 design

#### 5.2.1 Versioned storage schema

```json
{
  "secrets": {
    "github-pat": {
      "value": "ghp_NEW",                // current value
      "current_version": 4,
      "version_history": [
        { "v": 1, "value": "ghp_v1", "updated_at": "2026-01-01T00:00:00Z", "updated_by": "admin@acme", "reason": "initial" },
        { "v": 2, "value": "ghp_v2", "updated_at": "2026-04-01T00:00:00Z", "updated_by": "rotate-svc", "reason": "scheduled 90-day rotation" },
        { "v": 3, "value": "ghp_v3", "updated_at": "2026-07-01T00:00:00Z", "updated_by": "admin@acme", "reason": "leaked in 1Password breach" },
        { "v": 4, "value": "ghp_v4", "updated_at": "2026-09-06T00:00:00Z", "updated_by": "rotate-svc", "reason": "scheduled 90-day rotation" }
      ]
    }
  }
}
```

All values SOPS-encrypted. Version history = immutable chain (no deletions).

#### 5.2.2 Version endpoints

```
GET    /api/v1/secrets/{name}                     # current value
GET    /api/v1/secrets/{name}/versions            # list all versions (metadata only, no values)
GET    /api/v1/secrets/{name}/versions/{v}        # specific version (value included, requires 2-person approval)
GET    /api/v1/secrets/{name}/diff?from=2&to=4    # diff between versions
POST   /api/v1/secrets/{name}/rollback/{v}        # rollback to specific version (requires 2-person approval)
```

`GET versions/{v}` requires same WebAuthn 2-person approval as V4.1.x
mutations (read of historical secret value = sensitive).

#### 5.2.3 Diff UI (new)

`broker/dashboard/secrets-diff.html` (new in V4.2.0):
- Side-by-side view of 2 versions
- Highlight: added chars (green), removed chars (red)
- Show: who / when / why for each version
- Rollback button (triggers 2-person approval)

#### 5.2.4 Storage growth

Each version = ~100 bytes (encrypted value + metadata). For 1000 secrets
× 10 versions = 1 MB. Acceptable.

V4.1.x `secrets/secrets-detail.json` is ~10 KB for 100 secrets → V4.2.0
~100 KB for 1000 versions. SOPS encryption + git tracking still works.

#### 5.2.5 Tests

`broker-test/test-secret-versioning.js` (target 25 tests):
- Version creation on rotation
- Version history ordering
- Diff endpoint
- Rollback (with 2-person approval)
- Audit integration

### 5.3 Migration from V4.1.x

- On V4.2.0 startup, existing `value` becomes `version 1`
- `updated_at` → `v1.updated_at`
- New rotations create v2, v3, etc.
- Backward compat: `GET /api/v1/secrets/{name}` returns current value (same as V4.1.x)

## 6. Approval workflow for high-risk access

### 6.1 Current state (V4.1.x)

- WebAuthn 2-person approval for **mutations** (create/update/delete)
- Approvers: 2 different physical WebAuthn key IDs (no shared key)
- Payload-bound: requester cannot modify payload after approval
- Session-bound: 5-min one-use reauth grants
- Approval enforcement: client/secret/service create/update/delete + certificate rotation/revoke

### 6.2 V4.2.0 design

#### 6.2.1 High-risk access classification

```yaml
# secrets/broker.yaml (excerpt)
high_risk_access:
  enabled: true
  patterns:
    - name: "sensitive-mutation"
      when: action in [secret.update, secret.delete, service.delete, client.delete]
      require_approval: true
      min_approvers: 2
    - name: "bulk-export"
      when: action == "secret.list" AND request.query.limit > 100
      require_approval: true
      min_approvers: 1
    - name: "production-secret-decrypt"
      when: action == "secret.decrypt" AND secret.classification == "secret" AND resource matches "secrets:prod-*"
      require_approval: true
      min_approvers: 2
    - name: "aws-iam-passrole"
      when: action == "provider.invoke" AND provider == "aws" AND operation == "iam:PassRole"
      require_approval: true
      min_approvers: 2
```

#### 6.2.2 Approval flow

```
1. Requester: POST /api/v1/secrets/prod-aws-key/decrypt
   - Request payload: { client: "client.dashboard-dev", reason: "deploy to prod" }
   - Server: high_risk pattern matched → requires approval
   - Server: returns 202 Accepted with approval_request_id

2. Approver 1: POST /api/v1/approvals/{approval_request_id}/approve
   - Auth: mTLS + WebAuthn reauth (5-min one-use grant)
   - Audit: approver = admin@acme, time = now

3. Approver 2: POST /api/v1/approvals/{approval_request_id}/approve
   - Auth: different physical WebAuthn key (CC1.5)
   - Audit: approver = admin2@acme (different from requester), time = now

4. Server: 2/2 approvals received → execute the operation
   - GET /api/v1/secrets/prod-aws-key → return decrypted value
   - Audit: operation executed, all 3 parties logged

5. If 2/2 not received within 15 min → auto-deny + audit
```

#### 6.2.3 UI

`broker/dashboard/approvals.html` (new in V4.2.0):
- Pending approvals list (current approver)
- Approval history (with diff + reason)
- Requestor view: see "your pending requests" + cancel
- Admin view: approve/deny with comment

#### 6.2.4 Tests

`broker-test/test-approval-workflow.js` (target 40 tests):
- High-risk pattern matching
- 2/2 approval required (not 1/2 or 3/2)
- Different physical WebAuthn key IDs
- Payload-binding (modified payload invalidates approval)
- Session-binding (5-min one-use)
- Auto-deny timeout
- Audit trail (3 parties)

### 6.3 Migration from V4.1.x

- `high_risk_access` config: opt-in (default off, fall back to V4.1.x 2-person approval for mutations)
- Same WebAuthn 2-person approval engine (V4.1.x)
- New: pattern-based classification of high-risk access

## 7. Phased rollout (V4.2.0)

| Phase | What | When | Status |
|-------|------|------|--------|
| 7.1 | Per-tenant rate limiting | 2027-04-15 | ⏳ |
| 7.2 | ABAC engine | 2027-05-15 | ⏳ |
| 7.3 | Secret versioning | 2027-06-01 | ⏳ |
| 7.4 | Approval workflow | 2027-06-15 | ⏳ |
| 7.5 | Dashboard diff UI + approvals page | 2027-06-25 | ⏳ |
| 7.6 | V4.2.0 GA release | **2027-06-30** | ⏳ |

**Total estimate**: 12-15 weeks full-time, ~5,000 LOC.

## 8. Backward compatibility

- All V4.1.x endpoints unchanged
- All V4.1.x client SDKs work without changes
- `secrets/broker.yaml` schema: add new sections (`tenants`, `abac`, `high_risk_access`), keep existing
- New Redis dep is **optional** (fall back to in-memory)
- V4.1.x deployments upgrade to V4.2.0 with zero changes

## 9. Tests (V4.2.0 target)

- New: ~150 tests
- Total: 647 (V4.1.0) + 150 (V4.2.0) = **~800/0**

## 10. Refs

- [ROADMAP-post-1.0.md §12](../ROADMAP-post-1.0.md#12-v42.0-q2-2027)
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- [docs/DESIGN-V4-SECURITY-MODEL.md](../docs/DESIGN-V4-SECURITY-MODEL.md)
- [docs/DESIGN-V4-MASTER-PLAN.md](../docs/DESIGN-V4-MASTER-PLAN.md)
- [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md)
- [docs/SECURITY-CONTROLS-ISO27001.md](SECURITY-CONTROLS-ISO27001.md)
- [docs/SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md)
- [Common Expression Language (CEL)](https://github.com/google/cel-spec)

## 11. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
