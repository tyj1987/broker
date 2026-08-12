# my-first-app

> First project using the full dev system blueprint.
> System docs: `C:\home\dev-system\README.md`

A production-grade template that proves out the entire workflow:
SOPS + age secret management, direnv auto-load, Docker Compose
local stack, CI/CD, multi-cloud deploy, and a real Node app that
talks to PostgreSQL + Redis with credentials pulled from an
encrypted file at boot.

---

## What you get

- **One-time key generation, permanent reuse.** Encrypt once, decrypt
  anywhere the age key is present. Any machine that can clone this repo
  can decrypt `secrets/common.env`.
- **Zero plaintext secrets on disk or in CI.** Even the production
  deployment decrypts at runtime.
- **`task dev` is the only command you need.** It decrypts secrets and
  starts the full stack (app + database + cache) in one shot.
- **Multi-cloud deploy ready.** GitHub Actions workflows push to both
  Aliyun ACR and Tencent TCR, with OIDC-driven cloud KMS decryption.

---

## 5-minute quick start

### 1. Install tools (one time, on any new machine)

```powershell
# Scoop (skip if already installed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# All required tools in one go
scoop install age sops git go-task direnv gitleaks nodejs
# winget fallback for any package scoop can't find:
#   winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS
```

Restart PowerShell so the new `PATH` takes effect.

### 2. Bootstrap this project (idempotent)

```powershell
cd C:\home\my-first-app
pwsh -File bootstrap.ps1 -Auto
```

What it does:

1. Verifies all required tools are installed.
2. Generates a main age key A at `~/.config/sops/age/key-a.txt`
   (skipped if it already exists).
3. Generates a backup key B and prompts to copy it to a USB drive.
4. Writes the public keys into `.sops.yaml`.
5. Copies `secrets/common.env.example` to `secrets/common.env` and
   SOPS-encrypts it.
6. Initializes git and creates the first commit.

You can run this script on as many machines as you like. After the
first run, your encrypted file decrypts anywhere key A is present.

### 3. Run the local stack

```powershell
task dev
```

This decrypts `secrets/common.env` to `.env`, starts PostgreSQL and
Redis in Docker, and starts the Node app on `http://localhost:3000`.

```powershell
# Smoke test
curl http://localhost:3000/
# -> "Hello from my-first-app! 密钥管理已经生效。"

curl http://localhost:3000/health
# -> {"status":"ok","secrets_loaded":{"database":true,"redis":true},...}
```

`secrets_loaded.database` and `secrets_loaded.redis` must both be
`true`. If either is `false`, the app could not pick up the credentials
and the whole pipeline needs a check.

---

## Project layout

```
my-first-app/
├── .sops.yaml                  # SOPS encryption rules
├── .gitignore                  # strict ignore for keys and .env
├── .envrc                      # direnv auto-load (optional)
├── .pre-commit-config.yaml     # gitleaks + basic checks
├── Taskfile.yml                # task runner
├── Dockerfile                  # multi-stage production image
├── docker-compose.yml          # local dev stack
├── bootstrap.ps1               # one-shot project init
├── README.md                   # you are here
├── RUNBOOK.md                  # incident response & ops
├── secrets/
│   ├── common.env.example      # template
│   └── common.env              # ENCRYPTED — your real secrets
├── app/
│   ├── package.json
│   └── index.js                # Node app: /, /health, /db, /cache
├── scripts/
│   ├── check-tools.ps1         # verify install
│   ├── backup-keys.ps1         # copy keys to backup location
│   └── rotate-keys.ps1         # rotate age keys
├── infra/
│   ├── aliyun/                 # Terraform: Aliyun ACK + RDS + KMS
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── backend.tf
│   └── tencent/                # Terraform: Tencent TKE + TencentDB
│       ├── main.tf
│       ├── variables.tf
│       └── backend.tf
├── monitoring/
│   └── uptime-kuma.yml         # docker-compose for Uptime Kuma
└── .github/
    └── workflows/
        ├── ci.yml              # PR + main: lint, test, gitleaks
        └── deploy.yml          # tag: build, push to both clouds
```

---

## Day-to-day commands

```powershell
# Secrets
task secrets:init         # first-time setup (already done)
task secrets:edit         # open encrypted file in your $EDITOR
task secrets:view         # print decrypted contents
task secrets:export       # write decrypted .env file
task secrets:rotate       # rotate all age keys

# Backup
task backup:keys          # copy age keys to backup location

# Local dev
task dev                  # full stack (app + db + cache)
task dev:secrets          # decrypt secrets to .env
task dev:run              # run app only (assumes stack is up)

# Code quality
task lint                 # code style
task format               # auto-format
task test                 # unit tests
task test:coverage        # tests with coverage

# Build & ship
task build                # docker buildx (multi-arch)
task push                 # push to Aliyun ACR + Tencent TCR
task deploy               # build + push + terraform apply

# Cleanup
task clean                # remove .env, *.dec files
```

---

## CI / CD

`.github/workflows/ci.yml` runs on every push and PR:

- Install sops + age
- `gitleaks detect` — blocks if any plaintext secret sneaks in
- `npm ci && npm run lint && npm test`

`.github/workflows/deploy.yml` runs on every `v*` tag:

- Build multi-arch (amd64 + arm64) image
- Push to Aliyun ACR and Tencent TCR
- For each cloud, decrypt `secrets/prod.env` with the cloud's KMS
  (OIDC, no long-lived keys in GitHub Secrets) and apply Terraform

Required GitHub Secrets per cloud (see `RUNBOOK.md` for full setup):

- `ALIYUN_OIDC_PROVIDER_ARN`, `ALIYUN_OIDC_ROLE_ARN`
- `ALIYUN_ACR_USERNAME`, `ALIYUN_ACR_PASSWORD`
- `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`
- `TENCENT_TCR_USERNAME`, `TENCENT_TCR_PASSWORD`

---

## Multi-cloud

This project ships Terraform modules for both Aliyun and Tencent
Cloud. They provision:

- VPC + subnets
- Managed Kubernetes (ACK / TKE)
- Managed PostgreSQL (RDS / TencentDB)
- KMS keys for production secrets
- Container registry namespaces
- (Optional) Cloud logging and monitoring

See `infra/aliyun/main.tf` and `infra/tencent/main.tf`. Both
read the production secrets at apply time via SOPS, so no plaintext
passwords ever live in Terraform state.

---

## Security model — the 5 non-negotiables

1. **Private keys never enter git.** `.gitignore` blocks `key-*.txt`,
   `*.key`, `*.pem`. The encrypted `secrets/*.env` files are safe to
   commit and SHOULD be committed — that is the whole point.
2. **Multiple keys for redundancy.** Generate key A (everyday) and
   key B (backup). Both can decrypt. Lose one, the other still works.
3. **Offline backups.** The backup key B belongs on a USB drive, a
   safe, or encrypted cloud storage — somewhere NOT on the same disk
   as key A.
4. **Rotate on a schedule.** `task secrets:rotate` regenerates the
   keypair and re-encrypts every file. Do this every 6-12 months, or
   immediately if you suspect compromise.
5. **Production keys are KMS-only.** `secrets/prod.env` should be
   encrypted so that ONLY the cloud KMS can decrypt, not local keys.
   The bootstrap comment in `.sops.yaml` shows the swap.

---

## Monitoring

`monitoring/uptime-kuma.yml` is a docker-compose for Uptime Kuma,
a self-hosted monitoring tool that does:

- HTTP/HTTPS probes
- TCP port checks
- TLS certificate expiry alerts
- Webhook alerts to WeChat, DingTalk, Telegram, Slack, email

After running it (`docker compose -f monitoring/uptime-kuma.yml up -d`),
open `http://localhost:3001`, add your endpoints, and configure a
notification channel.

---

## What's not in scope (yet)

- **Service mesh / mTLS between app and database.** Add Linkerd or
  Istio if you have multiple services.
- **GitOps with ArgoCD.** `infra/*` deploys imperatively today. For
  declarative continuous delivery, layer ArgoCD on top.
- **Database migration tool.** Add `golang-migrate` or `prisma migrate`
  when you have actual schema changes.

See `C:\home\dev-system\02-full-architecture.md` for the full picture.
