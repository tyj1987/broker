# Secret Broker — Architecture

> One-page overview of the V4.1.1 architecture. For deep dives, see
> `docs/THREAT-MODEL.md` and the linked spec docs. For run-time operations, see `RUNBOOK.md`.


> **Languages**: [English](ARCHITECTURE.md) · [中文](ARCHITECTURE.zh-CN.md)
## Bird's eye view

```
                ┌──────────────────────────────────────────────────────────┐
                │                       AI Client                          │
                │  (Claude / Cursor / VS Code / CLI / mcp-server)         │
                │                                                          │
                │   • uses proxy mode   → never sees the secret value     │
                │   • uses mTLS         → proves its identity             │
                │   • receives WebAuthn → no password storage            │
                └─────────────────┬────────────────────────────────────────┘
                                  │ mTLS (TLS 1.2+)
                                  ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │                          Secret Broker (Node 20)                    │
   │                                                                      │
   │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
   │   │ REST API │  │ WebSocket│  │  MCP stdio│  │   SSH    │            │
   │   │ /api/v1/ │  │   /ws    │  │  /mcp    │  │  /api/v1/│            │
   │   │          │  │ events   │  │   tools  │  │   ssh/*  │            │
   │   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
   │        │             │              │              │                │
   │   ┌────┴─────────────┴──────────────┴──────────────┴─────────────┐  │
   │   │ 8 calling surfaces: get/list/resolve / proxy / exec / ssh  │  │
   │   │ / workload-identity / login / health / audit / ws subscribe│  │
   │   └────┬─────────────────────────────────────────────────────────┘  │
   │        │                                                            │
   │   ┌────┴───────────────────┐    ┌─────────────────────────────┐    │
   │   │  AuthN: mTLS + WebAuthn│    │  AuthZ: clients[cn] + scope │    │
   │   │  + TOTP + SMS + Pass   │    │  + MFA policy (risk-driven)  │    │
   │   └────────────────────────┘    └─────────────────────────────┘    │
   │                                                                      │
   │   ┌──────────────────────────────────────────────────────────┐      │
   │   │  Zero-credential-leakage engine                          │      │
   │   │  (12+ redact patterns, runs on every error + log + ws)  │      │
   │   └──────────────────────────────────────────────────────────┘      │
   │                                                                      │
   │   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐   │
   │   │  Risk   │ │  Auto   │ │ Alerting│ │ Workload │ │ WebSocket│   │
   │   │  Score  │ │ Rotate  │ │ Slack/  │ │ Identity │ │ Subscriptions│
   │   │         │ │         │ │ Feishu/ │ │ (STS)    │ │            │   │
   │   └─────────┘ └─────────┘ └─────────┘ └──────────┘ └──────────┘   │
   │                                                                      │
   └──────────┬─────────────────────┬─────────────────────┬──────────────┘
              │                     │                     │
              ▼                     ▼                     ▼
   ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────────┐
   │ SOPS-encrypted   │  │ Audit log           │  │ Upstream APIs    │
   │ secrets-detail   │  │ audit/YYYY-MM-DD    │  │ GitHub / AWS /   │
   │ .json (age key)  │  │ .jsonl (signed)     │  │ GCP / Slack /    │
   └──────────────────┘  └─────────────────────┘  └──────────────────┘
```

## 8 calling surfaces

| # | Surface | Use case | Endpoint / method |
|---|---------|----------|-------------------|
| 1 | **Secret resolution** | Resolve a single secret by name | `POST /api/v1/secrets/resolve` |
| 1 | **Bulk resolve** | Resolve N secrets in one call | `POST /api/v1/secrets/resolve_bulk` |
| 1 | **List** | List secrets visible to me | `GET /api/v1/secrets` |
| 2 | **Proxy** | Forward request, inject header | `ANY /api/v1/proxy/:service/*` |
| 3 | **Exec** | Spawn subprocess with secrets in env | CLI / Python / Go SDK |
| 4 | **SSH exec** | Run command on remote host, broker holds key | `POST /api/v1/ssh/exec` |
| 4 | **SSH tunnel** | Local port forward to internal DB | `POST /api/v1/ssh/tunnel` |
| 5 | **Workload identity** | K8s/ECS/GKE OIDC → STS | `POST /api/v1/workload-identity/assume` |
| 6 | **Login** | Password + MFA | `POST /api/v1/login` |
| 7 | **Health / Self** | Liveness + my identity | `GET /health` / `GET /api/v1/me` |
| 8 | **WebSocket** | Real-time event stream | `wss://broker:8443/ws` |

## 6 authentication factors

1. **mTLS** — every request is authenticated by client certificate
2. **Password** — for human logins
3. **TOTP** — RFC 6238
4. **WebAuthn** — Passkey / YubiKey
5. **SMS** — one-time code
6. **Recovery code** — backup for when factor 2-5 lost

Risk score (5 dimensions) decides which factors are required per action.

## 4 SDKs

- **Node** (`sdk/node/`) — `npm install @tyj1987/broker-sdk`
- **Python** (`sdk/python/`) — `pip install secret-broker` (zero hard deps)
- **Go** (`sdk/go/`) — `go get github.com/tyj1987/broker-sdk-go` (zero hard deps)
- **VS Code / Cursor** (`sdk/vscode/`) — install `.vsix` from releases

## 4 deployment surfaces

- **Docker** — `Dockerfile` (3-stage: deps/dev/production-distroless) + `docker-compose.yml`
- **Helm** — `deploy/helm/broker/` (11 templates, production-grade hardening)
- **Terraform** — `deploy/terraform/modules/broker/` + `examples/{aws,azure,gcp}/`
- **Bare-metal / systemd** — see `RUNBOOK.md`

## 4 supporting infrastructure pieces

- **Observability**: Prometheus metrics, structured audit logs, OpenAPI 3.1 schema,
  Grafana dashboard (14 panels + 28 alert rules)
- **Documentation site**: MkDocs + Material theme (`docs/`)
- **Bug bounty**: 4 tier rewards up to $5000 (`SECURITY.md`)
- **Project hygiene**: PR template, 3 issue templates, CONTRIBUTING, VERIFY, LICENSE

## Storage layout

```
/var/lib/broker/
├── secrets/                 # SOPS-encrypted YAML
│   ├── broker.yaml          #   operator config
│   └── secrets-detail.json  #   ALL actual secret values
├── audit/                   # append-only JSONL, one file per day
│   └── 2026-09-01.jsonl
└── pki/                     # mTLS material (NOT SOPS — separate trust)
    ├── ca/
    │   ├── ca.crt
    │   └── crl.pem
    ├── server/
    │   ├── server.crt
    │   └── server.key
    └── clients/
        ├── ai-agent-1.crt
        ├── ai-agent-1.key
        ├── admin.crt
        └── admin.key
```

## Key design invariants (NEVER break)

1. **Zero credential leakage** — every code path touching a secret passes
   through `broker/lib/redact.js` before logging, error-reporting, or
   returning to the caller. See the [redact engine](broker/lib/redact.js) and
   the [45 unit tests](broker-test/test-redact.js).
2. **mTLS-only** — no anonymous endpoints (except `GET /health` which returns
   only `{ "status": "ok" }`). Version, SOPS state, service names and uptime
   belong on authenticated `GET /api/v1/health` or the loopback health socket.
3. **No new hard dependencies** for Python/Go SDKs (stdlib only). New deps
   require maintainer approval.
4. **Backward compatibility** with v3.8 clients. Breaking changes bump
   `broker/version.js` and add a `Breaking` section to `CHANGELOG.md`.

## Repository layout

```
broker/                      # Server (Node.js ESM)
  server.js                  #   main entry (~3200 lines)
  version.js                 #   single source of truth for BROKER_VERSION
  lib/                       #   ~30 helper modules
  routes/                    #   ~15 endpoint handlers
  signing/                   #   8 cloud provider signing algorithms
  bin/                       #   CLI helpers (sync-templates, openapi-generate)
  test*/                     #   ~10 unit / integration test files
  package.json

sdk/
  node/                      # Node SDK (existing, in-repo)
  python/                    # Python SDK (zero hard deps)
  go/                        # Go SDK (zero hard deps)
  vscode/                    # VS Code / Cursor extension

deploy/
  helm/broker/               # Helm chart (11 templates)
  terraform/
    modules/broker/          # Pure-Terraform module
    examples/{aws,azure,gcp}/  # 3 cloud examples
  grafana/                   # Dashboard + alerts + provisioning

docs/                        # mkdocs source
  DESIGN-V4-*.md             #   6 architecture documents
  WORKLOAD-IDENTITY.md       #   4 spec docs (P2-17)
  SSH-PROXY.md
  WEBSOCKET.md
  SDK-REFERENCE.md
  index.md                   #   landing page
  requirements.txt           #   pip install mkdocs-material

.github/
  workflows/ci-v4.yml        # Cross-platform CI
  ISSUE_TEMPLATE/            # Bug + Feature + Question
  PULL_REQUEST_TEMPLATE.md   # PR with zero-leakage checklist

CHANGELOG.md                 # Version history
RELEASE-NOTES-v4.1.0.md      # V4.1.0 GA notes
RUNBOOK.md             # Per-task plan vs actual
VERIFY.md                    # 1-line verification recipe
CONTRIBUTING.md              # How to contribute
SECURITY.md                  # Bug bounty + threat model
LICENSE                      # MIT
```

## Reading order

If you are new to the project, read in this order:

1. **README.md** — what it is
2. **QUICKSTART.md** — 5-minute walkthrough
3. **ARCHITECTURE.md** (this file) — high-level overview
4. **docs/THREAT-MODEL.md** — full design
5. **RUNBOOK.md** — what was actually built
6. **Source code** — start with `broker/server.js` + `broker/lib/redact.js`
