# Secret Broker V4.1.0 — General Availability

**Released: 2026-09-01**

After 6 months of design + implementation (W1-W24, 23 tasks), Secret Broker V4
reaches **General Availability**. This release delivers on the complete
[DESIGN-V4-MASTER-PLAN.md](docs/DESIGN-V4-MASTER-PLAN.md).

## What's new

### 🎉 P1: V4.0 基础 (W1-W8) — 10 任务

The original V4 spec: AI-first credential management with 6 auth factors,
40+ provider templates, 8 calling surfaces, auto-rotation, and a
zero-credential-leakage design.

| Module | Lines | Tests |
|--------|-------|-------|
| `broker/lib/redact.js` | 165 | 45 |
| `broker/lib/risk-score.js` | 87 | 35 |
| `broker/lib/mfa-policy.js` | 105 | 35 |
| `broker/lib/sms-provider.js` | 90 | 35 |
| `broker/api-keys.js` (enh) | +160 | 27 |
| `broker/lib/template-parser.js` | 200 | – |
| `broker/bin/sync-templates.js` | 130 | – |
| `broker/signing/*.js` (8) | 480 | 42 |
| `broker/webauthn.js` | 300 | 11 |
| `broker/lib/auto-rotate.js` | 260 | – |
| `broker/lib/alerting.js` | 135 | – |
| `broker/lib/openapi-spec.js` | 195 | – |
| `broker/bin/openapi-generate.js` | 60 | – |
| `broker/type-schemas.js` (enh) | +240 | – |
| `broker/service-templates.js` (enh) | +650 | – |

### 🚀 P2: V4.1 增量 (W9-W16) — 6 任务

The new enterprise surface: workload identity, SSH proxy, real-time
WebSocket events, and 3 official client SDKs.

| Module | Description | Tests |
|--------|-------------|-------|
| `broker/lib/workload-identity.js` | K8s/ECS/GKE OIDC → STS | 56 |
| `broker/ssh-proxy.js` | AI never sees private key | 53 |
| `broker/lib/ws.js` | Real-time event stream | 27 |
| `sdk/python/` | Zero-dep Python SDK | 28 |
| `sdk/go/` | Zero-dep Go SDK | 15 |
| `sdk/vscode/` | VS Code/Cursor extension | – |

### 🌍 P3: V4.1.0 生态 (W17-W24) — 5 任务

Production deployment: Helm chart, Terraform module for 3 clouds, Grafana
dashboard + alerts, full documentation site, and a public bug bounty.

| Module | Description |
|--------|-------------|
| `deploy/helm/broker/` | Production-grade Helm chart with 11 templates |
| `deploy/terraform/modules/broker/` | Pure K8s Terraform module |
| `deploy/terraform/examples/{aws,azure,gcp}/` | EKS / AKS / GKE examples |
| `deploy/grafana/dashboard.json` | 14-panel operational dashboard |
| `deploy/grafana/alerts.yml` | 7 alert rule groups (28 rules) |
| `mkdocs.yml` + `docs/index.md` | Material theme documentation site |
| `SECURITY.md` | Bug bounty + threat model |

## Migration from v3.8

```bash
# 1. Backup
cp secrets/broker.yaml secrets/broker.yaml.v3.bak

# 2. (Optional) Migrate YAML in place
secret-broker migrate v3-to-v4 --in-place secrets/broker.yaml

# 3. Upgrade
helm upgrade broker ./deploy/helm/broker \
  --set-file secrets.brokerYaml=secrets/broker.yaml
```

**v3.8 clients continue to work** — V4 is fully backward-compatible at the
API level.

## Test summary

| Suite | Pass | Fail |
|-------|------|------|
| test-v4-modules | 201 | 0 |
| test-workload-identity | 56 | 0 |
| test-ssh-proxy | 53 | 0 |
| test-ws | 27 | 0 |
| test-redact | 45 | 0 |
| test-mfa-policy | 35 | 0 |
| test-sms-provider | 35 | 0 |
| test-api-keys-rate | 27 | 0 |
| test-signing | 42 | 0 |
| test-python-sdk | 28 | 0 |
| v3.8 regression (modular) | 282 | 0 |
| **Total** | **~831** | **0** |

## Statistics

| Metric | Value |
|--------|-------|
| Production code | ~9,500 lines (broker/ + sdk/) |
| Test code | ~3,800 lines |
| Documentation | ~2,500 lines (6 DESIGN docs) |
| Helm chart | 200 lines (11 templates) |
| Terraform | 600 lines (module + 3 examples) |
| Grafana JSON | 1,000 lines (14 panels + 28 alert rules) |
| SDK languages | 3 (Python, Go, TypeScript) |
| Service templates | 48 (from 6 in v3) |
| Type schemas | 59 (from 42 in v3) |
| Calling surfaces | 8 (CLI/SDK/MCP/REST/WS/SSH/OIDC/Skill) |
| Auth factors | 6 (mTLS/Pass/TOTP/WebAuthn/SMS/Recovery) |
| Cloud SDKs | 3 (AWS / Azure / GCP) |
| Git commits in this release | 8 (P1 + P2 + P3) |

## Quick start

```bash
# Install broker
helm repo add tyj1987 https://charts.broker.example.com
helm install broker tyj1987/broker \
  --set-file secrets.brokerYaml=secrets/broker.yaml

# Install Python SDK
pip install secret-broker

# Install Go SDK
go get github.com/tyj1987/broker-sdk-go

# Install VS Code extension
code --install-extension secret-broker-4.1.0.vsix
```

## Acknowledgments

- SOPS / age — secret-at-rest encryption
- Kubernetes — container orchestration
- Helm — package management
- Prometheus + Grafana — observability
- mkdocs-material — documentation
- All early testers who reported issues during the 6-month beta

## What's next

See [DESIGN-V4-ROADMAP.md](docs/DESIGN-V4-ROADMAP.md) for the post-1.0 plan:

- Tauri desktop client
- Homebrew tap
- Cloud marketplace images (AWS / Azure / GCP / 阿里云 / 腾讯云)
- Tailscale-native mTLS
- Compliance certifications (SOC 2, ISO 27001)

## Links

- **Docs**: https://docs.broker.example.com
- **Repository**: https://github.com/tyj1987/broker
- **Issues**: https://github.com/tyj1987/broker/issues
- **Security**: security@broker.example.com (PGP: see SECURITY.md)
- **Discord**: #broker (link in README)
- **Bug Bounty**: see SECURITY.md
