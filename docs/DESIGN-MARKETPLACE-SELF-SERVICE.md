# Marketplace Self-Service Design Spec (2026-09-06)

> **Status**: P3 #13 partial — design spec, no code yet
> **ROADMAP**: target 2027-06-30
> **Source**: [ROADMAP-post-1.0.md §13](../ROADMAP-post-1.0.md#13-marketplace-self-service-q2-2027)
> **Baseline**: broker V4.1.x + 48 service templates + V4.2.0 design (per-tenant rate limit + ABAC)

---

## 1. Goals

Open the broker template ecosystem to **third-party developers** so
anyone can publish a service template (e.g. "Stripe", "Notion", "Linear",
"Cloudflare R2", "Supabase") without going through tyj1987's manual
review.

**Current state (V4.1.x)**:
- 48 templates (aliyun, tencent, aws, gcp, github, gitlab, gitee,
  openai, anthropic, dockerhub, ghcr, etc.)
- All maintained by tyj1987
- Adding a new template = PR to `broker/service-templates.js` + tests
  + docs = 2-4 weeks maintainer time

**V4.2.0 + V4.3.0 goal**:
- 3rd-party devs publish via `secret-broker marketplace publish`
- Review via GitHub Discussions
- Auto-update via `secret-broker sync` (pull latest templates)
- 100+ templates in 12 months

## 2. Non-goals

- **Not a SaaS marketplace** — templates are static JSON, not executable code
- **Not a paid marketplace** — all templates free + open source (per broker's MIT license)
- **Not a private registry** — public only (no per-tenant template catalog)

## 3. Why a marketplace

**Developer pain today**:
- Want to use broker with a service tyj1987 doesn't have a template for
- Options: (a) PR to broker repo (2-4 weeks), (b) custom code (1-2 days)
- Both are slow / require tyj1987 involvement

**Marketplace value**:
- 3rd-party dev writes template in 1 day
- Broker users get new service support without tyj1987 bottleneck
- Decentralized ecosystem (same model as Terraform providers / GitHub
  Actions / VSCode extensions)

## 4. Stack (no new broker core changes)

| Layer | Tech | Rationale |
|-------|------|-----------|
| Template format | JSON | Same as V4.1.x `service-templates.js` |
| Registry | GitHub repo `tyj1987/broker-marketplace` | Free, public, versioned |
| Review | GitHub Discussions | Already in broker org |
| CLI | `secret-broker marketplace` subcommand | Reuse existing CLI |
| Versioning | Git tags + semver | Standard |
| Auto-update | `secret-broker sync` pulls latest registry index | Same pattern as `apt update` |

**No new broker dependencies**. Marketplace reuses existing infrastructure.

## 5. Template format (3rd-party)

### 5.1 JSON schema (compatible with V4.1.x)

```json
{
  "$schema": "https://broker.tyj1987.com/schemas/marketplace-template-v1.json",
  "name": "stripe",
  "display_name": "Stripe API",
  "version": "1.0.0",
  "author": {
    "github": "stripe-community",
    "email": "support@stripe-community.example"
  },
  "description": "Stripe payment API integration with rotating keys",
  "category": "payment",
  "icon_url": "https://raw.githubusercontent.com/stripe-community/broker-template-stripe/main/icon.png",
  "repository": "https://github.com/stripe-community/broker-template-stripe",
  "license": "MIT",
  "broker_compat": ">=4.1.0",
  "schema": {
    "type": "object",
    "required": ["secret_key"],
    "properties": {
      "secret_key": {
        "type": "string",
        "title": "Secret Key",
        "description": "Stripe secret API key (sk_live_... or sk_test_...)",
        "format": "password",
        "$ref": "secrets-detail.json#/definitions/stripe_secret_key"
      },
      "webhook_secret": {
        "type": "string",
        "title": "Webhook Secret",
        "description": "Stripe webhook signing secret (whsec_...)",
        "format": "password"
      }
    }
  },
  "operations": {
    "create_charge": {
      "method": "POST",
      "path": "/v1/charges",
      "description": "Create a charge",
      "auth": {
        "type": "bearer",
        "field": "secret_key"
      },
      "input": {
        "type": "object",
        "required": ["amount", "currency", "source"],
        "properties": {
          "amount": { "type": "integer", "description": "Amount in cents" },
          "currency": { "type": "string", "description": "3-letter currency code" },
          "source": { "type": "string", "description": "Source token" }
        }
      },
      "output": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "amount": { "type": "integer" },
          "status": { "type": "string" }
        }
      }
    },
    "list_customers": {
      "method": "GET",
      "path": "/v1/customers",
      "auth": { "type": "bearer", "field": "secret_key" }
    }
  },
  "rotation": {
    "interval_days": 90,
    "warning_days": 14,
    "auto_rotate": true
  },
  "tests": {
    "example": {
      "input": { "amount": 2000, "currency": "usd", "source": "tok_visa" },
      "expected_status": 200
    }
  }
}
```

### 5.2 Compatibility with V4.1.x

V4.1.x `service-templates.js` exports an array of templates. Marketplace
templates are converted at `secret-broker sync` time:

```typescript
// broker/lib/marketplace.ts (new in V4.2.0)
async function loadMarketplaceTemplates(): Promise<ServiceTemplate[]> {
  const index = await fetchMarketplaceIndex();  // https://raw.githubusercontent.com/tyj1987/broker-marketplace/main/index.json
  return Promise.all(index.templates.map(async (entry) => {
    const template = await fetchTemplate(entry.url);
    return convertToInternalFormat(template);  // 3rd-party JSON → V4.1.x internal
  }));
}
```

**Backward compat**: V4.1.x `service-templates.js` continues to work;
marketplace templates are **additive** (loaded at runtime via `sync`).

## 6. CLI subcommands

### 6.1 `secret-broker marketplace`

```
secret-broker marketplace <subcommand> [options]

Subcommands:
  list                    List available templates from the registry
  search <query>          Search templates by name / category / description
  info <name>             Show template details
  install <name>          Install a template to local broker
  publish <path>          Publish a template (3rd-party dev workflow)
  validate <path>         Validate template schema + compatibility
  sync                    Update local cache of marketplace templates
  unpublish <name>        Remove a template you published

Options:
  --registry <url>        Custom registry (default: tyj1987/broker-marketplace)
  --output <format>       json / yaml / table (default: table)
```

### 6.2 `secret-broker marketplace publish`

3rd-party dev workflow:

```bash
# 1. Create template repo
gh repo create myorg/broker-template-foo --public
cd myorg/broker-template-foo

# 2. Create template.json (see §5.1)
$EDITOR template.json

# 3. Validate locally
secret-broker marketplace validate ./template.json
# Output: ✓ Schema valid, ✓ Broker compat >=4.1.0, ✓ All operations have auth

# 4. Tag a release
git tag v1.0.0
git push --tags

# 5. Submit to marketplace (via PR to tyj1987/broker-marketplace)
secret-broker marketplace publish ./template.json
# Output: 
#   Creating PR to tyj1987/broker-marketplace...
#   PR URL: https://github.com/tyj1987/broker-marketplace/pull/123
#   Status: awaiting review
#   Estimated review time: 7-14 days

# 6. Wait for review
# Reviewer approves → template available in marketplace
# Reviewer requests changes → fix and re-push
```

### 6.3 `secret-broker marketplace install`

User workflow:

```bash
# 1. Browse marketplace
secret-broker marketplace list
# Name              Version  Author              Category
# stripe            1.0.0    stripe-community    payment
# notion            0.9.0    notion-community    docs
# linear            0.5.0    linear-community   pm
# cloudflare-r2     0.3.0    cf-community        storage
# supabase          0.2.0    supabase-community  db

# 2. Get details
secret-broker marketplace info stripe
# Name: stripe
# Version: 1.0.0
# Author: stripe-community
# Description: Stripe payment API integration with rotating keys
# Category: payment
# Repository: https://github.com/stripe-community/broker-template-stripe
# License: MIT
# Broker compat: >=4.1.0
# Operations: create_charge, list_customers, ...
# Rotation: every 90 days, auto-rotate

# 3. Install to local broker
secret-broker marketplace install stripe
# Output: ✓ Template 'stripe' installed. Restart broker to load.

# 4. Restart broker (or hot-reload)
sudo systemctl restart secret-broker
# OR
secret-broker marketplace reload  # hot-reload without restart

# 5. Use the new service
secret-broker get stripe --field secret_key
# Output: sk_live_*** (or via admin dashboard mTLS enroll)

secret-broker proxy stripe create_charge \
  --body '{"amount": 2000, "currency": "usd", "source": "tok_visa"}'
# Output: {"id": "ch_xxx", "amount": 2000, "status": "succeeded"}
```

### 6.4 `secret-broker marketplace sync`

Auto-update templates:

```bash
# Daily cron (run by maintainer's broker instance)
0 6 * * * secret-broker marketplace sync

# Output:
# Syncing marketplace index...
#   ✓ stripe 1.0.0 → 1.1.0 (auto-update available)
#   ✓ notion 0.9.0 (no update)
#   ✓ linear 0.5.0 → 0.6.0 (auto-update available)
#   ✓ cloudflare-r2 0.3.0 (new template, install?)
#   ✓ supabase 0.2.0 (deprecated, will be removed in 0.4.0)
# 3 templates updated, 1 new, 1 deprecated.
# Run 'secret-broker marketplace reload' to apply.
```

## 7. Registry repo: `tyj1987/broker-marketplace`

GitHub repo structure:

```
broker-marketplace/
├── README.md                        # maintainer guide
├── CONTRIBUTING.md                  # 3rd-party dev guide
├── index.json                       # list of all templates
│
├── templates/
│   ├── stripe/
│   │   ├── template.json
│   │   ├── icon.png
│   │   ├── tests/
│   │   │   ├── create_charge.test.json
│   │   │   └── list_customers.test.json
│   │   └── README.md
│   ├── notion/
│   │   └── ...
│   ├── linear/
│   ├── cloudflare-r2/
│   └── supabase/
│
├── .github/
│   ├── workflows/
│   │   ├── validate.yml              # validate template.json on PR
│   │   └── publish.yml               # auto-update index.json on merge
│   └── ISSUE_TEMPLATE/
│       └── template-submission.md
│
└── scripts/
    ├── validate.py                  # JSON schema + compatibility check
    └── update-index.py              # rebuild index.json from templates/
```

### 7.1 Submission workflow

1. **3rd-party dev**: fork `tyj1987/broker-marketplace`
2. **3rd-party dev**: add `templates/<name>/template.json` + icon + tests + README
3. **3rd-party dev**: open PR
4. **CI**: `validate.yml` runs `scripts/validate.py` (schema + compat + auth)
5. **Reviewer (tyj1987 or delegate)**: reviews PR in 7-14 days
   - Code review: template matches service API
   - Security review: no exfiltration / SSRF / etc.
   - Tests pass: `tests/*.test.json` validate
6. **Approval**: PR merged, `publish.yml` updates `index.json`
7. **3rd-party dev**: tag v1.0.0, mark as GA
8. **Users**: `secret-broker marketplace list` sees new template

### 7.2 Review process

**Tier 1 (tyj1987)**: core maintainer, approves any template
**Tier 2 (delegated maintainers)**: trust list of 3-5 community members
- Stripe / Cloudflare / GitHub employees could be Tier 2 for their own service
- Tier 2 has `triage` permission on broker-marketplace repo (merge PRs, no push)

**Self-service** (future): trusted 3rd-party devs with 5+ published
templates can self-publish (skip review). Bad templates → revert + ban.

## 8. Security considerations

| Concern | Mitigation |
|---------|------------|
| Malicious template exfiltrates secrets | Template runs in **broker process** (Node sandbox). NO shell exec. NO outbound HTTP except to whitelisted providers. V4.1.x outbound policy (HTTPS origin pinning + private IP blocking) applies |
| SSRF via template path / webhook URL | V4.1.x outbound policy enforces HTTPS + private IP block + redirect/header controls |
| Author impersonation | GitHub OAuth (registry maintainer) + signed commits + repo ownership verification |
| Auto-update backdoor | Templates are versioned (Git tags); user opt-in per template (config: `auto_update: true` or `false`) |
| Supply chain attack (3rd-party repo compromised) | Pin to SHA digest (not tag); `secret-broker marketplace install --pin-sha <sha>` |
| Template reuse + name squatting | Namespace convention: `org/service-name` (e.g. `stripe-community/stripe`); no single-name squatting |
| Outdated templates (security issues) | Marketplace shows "last updated" + warns if > 6 months old; auto-deprecate after 12 months no update |

## 9. Phased rollout (P3 #13, target 2027-06-30)

| Phase | What | When | Status |
|-------|------|------|--------|
| 13.1 | Registry repo `tyj1987/broker-marketplace` + schema + CI | 2027-03-31 | ⏳ |
| 13.2 | CLI subcommands (`marketplace list/search/info/install/publish/validate/sync/unpublish`) | 2027-04-30 | ⏳ |
| 13.3 | First 5 community templates (Stripe / Notion / Linear / Cloudflare R2 / Supabase) | 2027-05-15 | ⏳ |
| 13.4 | GitHub Discussions review process | 2027-05-31 | ⏳ |
| 13.5 | Auto-update + digest pinning | 2027-06-15 | ⏳ |
| 13.6 | V4.3.0 GA release with marketplace | **2027-06-30** | ⏳ |

**Total estimate**: 12-15 weeks full-time, ~3,000 LOC.

## 10. Cost estimate (P3 #13)

| Item | Cost |
|------|------|
| GitHub repo (public) | $0 |
| GitHub Actions CI minutes (free tier: 2000 min/month) | $0 |
| Registry maintenance (tyj1987) | volunteer |
| Tier 2 reviewers (5 community members) | volunteer |
| **Total upfront** | **$0** |
| **Total recurring** | **$0** |

## 11. Open questions (for user 决断)

1. **Self-publish privilege**: when does a 3rd-party dev get self-publish? Proposal: 5+ templates + 6 months active + zero security incidents.
2. **Paid templates**: explicitly forbidden? Or allow optional "support the author" links? Proposal: MIT license only, no paid tier.
3. **Template conflicts**: 2 templates with same `name` (e.g. "stripe" by stripe-community vs by another dev)? Proposal: namespace `org/name` mandatory.
4. **Versioning**: tag only, or also branch (like Homebrew)? Proposal: tag only, semver.
5. **Removal policy**: when is a template auto-removed? Proposal: 12 months no update + author opt-out OR security incident OR license violation.

## 12. Estimated effort

| Phase | Weeks | LOC | Risk |
|-------|-------|-----|------|
| 13.1 Registry repo | 4 | ~500 (schema + CI + scripts) | Low |
| 13.2 CLI subcommands | 6 | ~1,500 (TS in CLI) | Low |
| 13.3 First 5 templates | 4 | ~500 (5 × 100) | Low |
| 13.4 Review process | 2 | ~200 (Discussions config) | Low |
| 13.5 Auto-update + pinning | 3 | ~300 (digest check) | Medium |
| **Total** | **19 weeks** | **~3,000** | |

**Calendar**: 4-5 months from Phase 13.1 start (2027-03-01) → 2027-07-31.
ROADMAP target 2027-06-30 is **aggressive** (3-4 months).

## 13. Success criteria

- [ ] `tyj1987/broker-marketplace` repo live
- [ ] `secret-broker marketplace` CLI subcommands work
- [ ] First 5 community templates published + reviewed
- [ ] GitHub Discussions review process documented
- [ ] Auto-update + digest pinning working
- [ ] 50+ templates in marketplace by end of 2027
- [ ] User docs in `docs/MARKETPLACE-SELF-SERVICE.md`

## 14. Refs

- [ROADMAP-post-1.0.md §13](../ROADMAP-post-1.0.md#13-marketplace-self-service-q2-2027)
- [docs/DESIGN-V4.2.0.md](DESIGN-V4.2.0.md) (V4.2.0 design — prerequisite for marketplace)
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) (broker service template architecture)
- [docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) (template execution security)
- [docs/SECURITY-CONTROLS-SOC2.md](SECURITY-CONTROLS-SOC2.md) (SOC 2 considerations)
- [Terraform Provider Registry](https://registry.terraform.io/) (inspiration for ecosystem model)
- [GitHub Actions Marketplace](https://github.com/marketplace?type=actions) (inspiration for review process)

## 15. License

This document is licensed under MIT — see [LICENSE](../LICENSE).
