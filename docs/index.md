# Secret Broker

> **AI-first mTLS secret broker with zero-credential-leakage.**

A self-hosted secret manager designed for AI agents, Kubernetes workloads,
and developer workstations. Stores credentials encrypted with SOPS, serves
them over mTLS, and never lets AI see raw secrets — only metadata or
redacted placeholders.

[:material-rocket-launch: Quickstart](QUICKSTART.md){ .md-button .md-button--primary }
[:material-github: GitHub](https://github.com/tyj1987/broker){ .md-button }

---

## What is it?

!!! quote "The problem"
    AI agents (LLMs, IDEs, MCP clients) need API tokens, database passwords,
    and SSH keys to do their job — but you can't trust them not to leak
    credentials into logs, conversation history, or model training data.

**Secret Broker** is the answer:

* **mTLS-only** — every request is authenticated with a client certificate.
  No anonymous access, ever.
* **SOPS-encrypted at rest** — secrets live in `secrets/broker.yaml` encrypted
  with age or PGP keys.
* **Zero-credential-leakage** — the broker, SDK, and audit log all
  auto-redact known secret patterns (GitHub PAT, OpenAI `sk-`, AWS `AKIA`,
  JWTs, etc.). Tests assert this on every commit.
* **AI-aware** — built-in support for WebAuthn, TOTP, WebSocket events,
  workload identity (K8s/ECS/GKE), and proxy-mode for 40+ service templates.

## Key features

<div class="grid cards" markdown>

- :material-shield-key:{ .lg .middle } **mTLS + WebAuthn + TOTP**

  ---

  6 authentication factors. No password-only logins. Per-client lockout
  on 5 failed attempts.

- :material-robot:{ .lg .middle } **AI-aware proxy mode**

  ---

  AI calls `GET /api/v1/proxy/github/repos/owner/repo` and the broker
  transparently injects the `Authorization: Bearer` header. The AI never
  sees the PAT.

- :material-cloud-sync:{ .lg .middle } **Workload identity**

  ---

  K8s ServiceAccount tokens, ECS task roles, and GKE Workload Identity
  Federation. Pods 0 AKs.

- :material-rotate-3d:{ .lg .middle } **Auto-rotation**

  ---

  Configurable rotation intervals per secret type. Slack/PagerDuty alerts
  on stale credentials. 1-click rollback via git.

- :material-chart-line:{ .lg .middle } **First-class observability**

  ---

  Prometheus metrics, structured audit logs, OpenTelemetry traces,
  and a pre-built Grafana dashboard.

- :material-package-variant:{ .lg .middle } **8 client SDKs**

  ---

  Node, Python, Go, MCP (stdio/SSE), VS Code/Cursor, and a CLI. Zero
  hard dependencies for Python/Go.

</div>

## 8 ways to call the broker

| Entry | Use case |
|-------|----------|
| `POST /api/v1/secrets/resolve` | Programmatic secret fetch |
| `GET /api/v1/proxy/:service/*` | Transparent header injection |
| `WS /ws` | Real-time audit/alert stream |
| `POST /api/v1/ssh/exec` | SSH without exposing the key |
| `POST /api/v1/ssh/tunnel` | Local port forward to internal DB |
| `POST /api/v1/workload-identity/assume` | Exchange OIDC for STS |
| `GET /api/v1/me` | Self-service: rotate cert, TOTP, audit |
| MCP server | Native integration for Claude Desktop / Cursor |

## Where to go next

- [Quickstart](QUICKSTART.md) — 5-minute walkthrough
- [Master Plan](DESIGN-V4-MASTER-PLAN.md) — architecture overview
- [API Calling Standards](DESIGN-V4-API-CALLING-STANDARDS.md) — how to call
  the broker from AI agents
- [Helm chart](../deploy/helm/broker/) — production deployment
- [Python SDK](../sdk/python/) — zero-dep client
