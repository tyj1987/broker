# Secret Broker

> **AI-first mTLS secret broker with zero credential leakage.**

A self-hosted secret manager and credential proxy designed for AI agents,
Kubernetes workloads, and developer workstations. Stores credentials
encrypted with SOPS, serves them over mTLS, and never lets AI see raw
secrets — only metadata or redacted placeholders.

[![Version](https://img.shields.io/badge/version-v4.1.1-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-1100%2B%20passing-brightgreen)]()

---

## The problem

AI agents (LLMs, IDEs, MCP clients) need API tokens, database passwords,
and SSH keys to do their job — but you can't trust them not to leak
credentials into logs, conversation history, or model training data.

## The solution

**Secret Broker** is the answer:

* **mTLS-only** — every request is authenticated with a client certificate.
  No anonymous access, ever.
* **SOPS-encrypted at rest** — secrets live in `secrets/broker.yaml` encrypted
  with age or PGP keys.
* **Zero-credential-leakage** — the broker, SDK, and audit log all
  auto-redact known secret patterns (GitHub PAT, OpenAI `sk-`, AWS `AKIA`,
  JWTs, etc.). Tests assert this on every commit.
* **Audit log** — append-only JSONL with tamper-evident hash chain. Every
  resolve, proxy, and admin action is recorded.
* **Three usage modes** — pick what fits:
  - **Proxy mode** (recommended for AI) — broker injects secrets into the
    upstream request; AI never sees the raw value.
  - **API key** — short-lived Bearer tokens for AI clients; auto-revoked.
  - **Resolve mode** — names only; values never leave the broker.
* **Three official SDKs** — Python, Go, VSCode extension.
* **Workload identity** — K8s / ECS / GKE pods exchange OIDC for short-lived
  STS credentials; no long-lived keys on disk.

---

## Quickstart

5 minutes to your first broker.

### 1. Install

```bash
# Clone
git clone https://github.com/tyj1987/broker.git
cd broker

# One-time: init SOPS + age key + PKI
iex (Get-Content .\bootstrap.ps1 -Raw)   # Windows
# or
./bootstrap.sh                            # Linux/macOS
```

### 2. Start

```bash
cd broker
node server.js
# Listening on https://127.0.0.1:8443
```

### 3. Issue a client cert

```powershell
# Windows
.\scripts\broker\issue-client-cert.ps1 -CN client.mylaptop -Role developer
```

```bash
# Linux/macOS
./scripts/broker/issue-client-cert.sh client.mylaptop developer
```

The cert is signed by your local CA and printed to stdout (save it!).

### 4. Make your first call

```bash
# mTLS direct (most secure)
curl --cert client.mylaptop.crt --key client.mylaptop.key \
     --cacert pki/ca/ca.crt \
     https://127.0.0.1:8443/api/v1/identity
```

That's it. See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full walkthrough.

---

## Architecture

```
┌─────────────┐  mTLS   ┌─────────────┐  HTTPS   ┌─────────────┐
│ AI / CLI /  │ ──────▶ │   Nginx     │ ───────▶ │   Broker    │
│ K8s / ECS   │         │  (edge)     │          │ (Node.js)   │
└─────────────┘         └─────────────┘          └──────┬──────┘
                                                        │
                                              ┌─────────┴──────────┐
                                              ▼                    ▼
                                       ┌─────────────┐    ┌────────────────┐
                                       │ SOPS+age    │    │ Upstream APIs  │
                                       │ secrets/    │    │ GitHub/Cloud/  │
                                       │ broker.yaml │    │ SSH/etc        │
                                       └─────────────┘    └────────────────┘
```

* **Broker** (Node.js, single binary) holds secrets in memory, never on disk
  unencrypted. Listens on `127.0.0.1:8443` only; nginx fronts public TLS.
* **Nginx** terminates public HTTPS, applies `ssl_verify_client optional`,
  forwards the client cert (if any) to broker as `X-SSL-Client-*` headers.
* **SOPS** encrypts `secrets/broker.yaml` at rest with age (or KMS).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full deep-dive.

---

## Repository layout

```
.
├── broker/                  # Server source (Node.js, ES modules)
│   ├── server.js            # Entry point (~3300 LOC, 100+ routes)
│   ├── lib/                 # Extracted helpers (sops, audit, mtls, …)
│   ├── routes/              # Per-resource HTTP handlers
│   ├── signing/             # Provider request signers (Aliyun, AWS, …)
│   ├── dashboard/           # Static admin UI
│   └── …
├── sdk/                     # Official client SDKs
│   ├── python/              # Python (zero-dep, stdlib only)
│   ├── go/                  # Go (stdlib only)
│   └── vscode/              # VSCode extension (TypeScript)
├── broker-test/             # Server integration tests (43 files, 1100+ tests)
├── docs/                    # Long-form documentation
│   ├── index.md             # MkDocs landing page
│   ├── QUICKSTART.md        # 5-minute walkthrough
│   ├── EXTENDING.md         # Add new secret types / service templates
│   ├── FAQ.md               # Common questions
│   ├── SDK-REFERENCE.md     # All 3 SDKs quick reference
│   ├── THREAT-MODEL.md      # Security model
│   ├── SSH-PROXY.md         # SSH proxy feature
│   ├── WEBSOCKET.md         # WebSocket events feature
│   └── WORKLOAD-IDENTITY.md # K8s/ECS/GKE OIDC → STS
├── scripts/                 # Setup / deploy / maintenance scripts
│   └── broker/              # Core operations scripts
├── deploy/                  # Deployment assets (helm, terraform, etc.)
├── infra/                   # Terraform modules (Aliyun + Tencent)
├── pki/                     # PKI root CA (public cert only; private keys gitignored)
│   └── ca/ca.crt            # Local CA cert (committed for dev)
├── audit/                   # Runtime audit log (JSONL, gitignored)
├── secrets/                 # Runtime secrets (gitignored except broker.yaml)
├── age/                     # age key (gitignored)
├── .github/                 # GitHub config: workflows, issue/PR templates
├── Dockerfile               # Container image
└── docker-compose.yml       # Local dev stack
```

---

## API at a glance

All paths require mTLS (or Bearer API key for AI clients).

| Method | Path | Purpose |
|---|---|---|
| GET    | `/health` | Liveness (no auth) |
| GET    | `/api/v1/identity` | "Who am I, what role" |
| GET    | `/api/v1/services` | Available upstream services |
| GET    | `/api/v1/secrets` | Secret names only (never values) |
| POST   | `/api/v1/secrets/resolve` | Get one secret value (admin/scoped) |
| POST   | `/api/v1/proxy/<service>` | Make upstream API call as that service |
| GET    | `/api/v1/admin/clients` | List clients (admin) |
| POST   | `/api/v1/admin/secrets` | CRUD secrets (admin) |
| GET    | `/api/v1/admin/audit/verify` | Verify audit log hash chain |
| GET    | `/api/v1/healthcheck/status` | Last credential health check |
| WS     | `/api/v1/ws` | Real-time event stream |

Full reference: [`docs/SDK-REFERENCE.md`](docs/SDK-REFERENCE.md).

---

## SDKs

```python
# Python (zero deps)
from secret_broker import Client
c = Client.from_env()
me = c.identity()
print(me.role, me.client_name)
```

```go
// Go (zero deps)
import "github.com/tyj1987/broker/sdk/go/broker"
c, _ := broker.NewFromEnv()
me, _ := c.Identity()
fmt.Println(me.Role, me.ClientName)
```

```typescript
// VSCode extension
import { SecretBroker } from '@tyj1987/broker-vscode';
const client = SecretBroker.fromEnv();
const me = await client.identity();
```

All three are **zero-dependency** (stdlib only) so they don't pull in
vulnerable transitive dependencies.

---

## Security

* **mTLS only** — anonymous requests are 401 at the TLS layer.
* **No raw secrets leave the broker** — proxy mode returns the upstream
  response with credentials already injected.
* **Audit hash chain** — every event is linked to the previous one via
  SHA-256; tampering is detectable.
* **Auto-redaction** — known token patterns (GitHub PAT, OpenAI `sk-`,
  AWS `AKIA`, etc.) are replaced with `ghp_***` etc. before they reach
  audit logs, error responses, or the dashboard.
* **TOTP + recovery codes** for human admins.
* **Bounty**: see [`SECURITY.md`](SECURITY.md) — $5,000 for critical vulns.

Threat model: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Development

```bash
# Install
cd broker && npm install

# Run all tests (1100+ across server + 3 SDKs)
cd broker && npm run test:verify-all

# Format
cd broker && npm run format
cd broker && npm run format:check

# Lint
cd broker && npm run lint
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Deployment

* **Docker** — `docker build -t secret-broker . && docker run -p 8443:8443 ...`
* **Docker Compose** — `docker-compose up`
* **Aliyun / Tencent** — see `infra/` (Terraform modules)
* **Helm** — see `deploy/helm/broker/`
* **Grafana** — see `deploy/grafana/`

Full guide: [`DEPLOY-52TRZ.md`](DEPLOY-52TRZ.md) and [`RUNBOOK.md`](RUNBOOK.md).

---

## License

MIT. See repository root.

## Support

* **Issues** — bug reports, feature requests: [GitHub Issues](../../issues)
* **Discussions** — questions, ideas: [GitHub Discussions](../../discussions)
* **Security** — see [`SECURITY.md`](SECURITY.md)

---

## Acknowledgements

Built with care by the Secret Broker maintainers and contributors. The
SOPS+age stack, nginx mTLS pattern, and zero-credential-leakage principle
draw inspiration from HashiCorp Vault, BoringSSL, and the Mozilla SOPS
project.
