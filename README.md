# my-first-app / 我的第一个应用

> First project using the full dev system blueprint.
> 使用完整开发系统蓝图的第一个项目。
>
> System docs / 系统文档: `C:\home\dev-system\README.md`

A production-grade template that proves out the entire workflow:
SOPS + age secret management, direnv auto-load, Docker Compose
local stack, CI/CD, multi-cloud deploy, and a real Node app that
talks to PostgreSQL + Redis with credentials pulled from an
encrypted file at boot.

生产级模板，跑通整个工作流：SOPS + age 密钥管理、direnv 自动加载、
Docker Compose 本地栈、CI/CD、多云部署，以及一个真正连 PostgreSQL +
Redis（凭据从加密文件运行时解密）的 Node 应用。

---

## What you get / 能力清单

- **One-time key generation, permanent reuse.** Encrypt once, decrypt
  anywhere the age key is present. Any machine that can clone this repo
  can decrypt `secrets/common.env`.

  **一次生成钥匙，永久复用。** 在任一台有 age 钥匙的机器上 clone 仓库
  就能解密 `secrets/common.env`。

- **Zero plaintext secrets on disk or in CI.** Even the production
  deployment decrypts at runtime via cloud KMS.

  **磁盘和 CI 中无明文密钥。** 生产部署也通过云 KMS 在运行时解密。

- **`task dev` is the only command you need.** It decrypts secrets and
  starts the full stack (app + database + cache) in one shot.

  **`task dev` 是你唯一需要敲的命令。** 自动解密密钥 + 启动完整栈
  （app + 数据库 + 缓存）。

- **Multi-cloud deploy ready.** GitHub Actions workflows push to both
  Aliyun ACR and Tencent TCR, with OIDC-driven cloud KMS decryption.

  **多云部署就绪。** GitHub Actions 同时推阿里云 ACR 和腾讯云 TCR，
  云 KMS 走 OIDC 鉴权解密。

---

## 5-minute quick start / 5 分钟上手

### 1. Install tools (one time, on any new machine)
### 1. 装工具（一次性，任何新机器都要）

```powershell
# Scoop (skip if already installed) / Scoop（已装则跳过）
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# All required tools in one go / 一次性装齐
scoop install age sops git go-task direnv gitleaks nodejs
# winget fallback for any package scoop can't find:
# winget 后备方案：
#   winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS
```

Restart PowerShell so the new `PATH` takes effect.
重启 PowerShell 让新 `PATH` 生效。

### 2. Bootstrap this project (idempotent)
### 2. 引导本项目（幂等）

```powershell
cd C:\home\my-first-app
pwsh -File bootstrap.ps1
```

What it does / 做的事：

1. Verifies all required tools are installed. / 检查必需工具是否装好。
2. Generates a main age key A at `~/.config/sops/age/key-a.txt`
   (skipped if it already exists). / 在 `~/.config/sops/age/key-a.txt`
   生成主钥匙 A（已存在则跳过）。
3. Generates a backup key B and prompts to copy it to a USB drive.
   / 生成备份钥匙 B 并提示拷到 U 盘。
4. Writes the public keys into `.sops.yaml`. / 把公钥写进 `.sops.yaml`。
5. Copies `secrets/common.env.example` to `secrets/common.env` and
   SOPS-encrypts it. / 复制 example 到 `secrets/common.env` 并 SOPS 加密。
6. Initializes git and creates the first commit. / 初始化 git 并首次提交。

You can run this script on as many machines as you like. After the
first run, your encrypted file decrypts anywhere key A is present.
这个脚本可以在任意多台机器上跑。首次跑完后，只要有钥匙 A 的地方就能解密。

### 3. Run the local stack / 3. 跑本地栈

```powershell
task dev
```

This decrypts `secrets/common.env` to `.env`, starts PostgreSQL and
Redis in Docker, and starts the Node app on `http://localhost:3000`.

这会把 `secrets/common.env` 解密成 `.env`，启动 PostgreSQL + Redis
容器，并在 `http://localhost:3000` 启动 Node 应用。

```powershell
# Smoke test / 冒烟测试
curl http://localhost:3000/
# -> "Hello from my-first-app! 密钥管理已经生效。"

curl http://localhost:3000/health
# -> {"status":"ok","secrets_loaded":{"database":true,"redis":true},...}
```

`secrets_loaded.database` and `secrets_loaded.redis` must both be
`true`. If either is `false`, the app could not pick up the credentials
and the whole pipeline needs a check.

`secrets_loaded.database` 和 `secrets_loaded.redis` 必须都是 `true`。
如果任一是 `false`，说明应用没拿到凭据，整个链路需要排查。

---

## Project layout / 项目结构

```
my-first-app/
├── .sops.yaml                  # SOPS 加密规则 / SOPS encryption rules
├── .gitignore                  # 严格忽略私钥 / strict ignore for keys
├── .envrc                      # direnv 自动加载 / direnv auto-load
├── .pre-commit-config.yaml     # gitleaks + 基础检查 / gitleaks + basic checks
├── Taskfile.yml                # 任务编排 / task runner
├── Dockerfile                  # 多阶段生产镜像 / multi-stage production image
├── docker-compose.yml          # 本地开发栈 / local dev stack
├── bootstrap.ps1               # 一键引导 / one-shot project init
├── README.md                   # 你在这里 / you are here
├── RUNBOOK.md                  # 应急响应与运维 / incident response & ops
├── secrets/
│   ├── common.env.example      # 模板 / template
│   └── common.env              # 加密的（提交进 Git 没问题）/ ENCRYPTED — safe to commit
├── app/
│   ├── package.json
│   └── index.js                # Node 应用：/, /health, /db, /cache
├── scripts/
│   ├── check-tools.ps1         # 工具检查 / verify install
│   ├── backup-keys.ps1         # 备份私钥 / copy keys to backup location
│   ├── rotate-keys.ps1         # 轮转 age 钥匙 / rotate age keys
│   └── install-direnv-hook.ps1 # 装 direnv PowerShell hook
├── infra/
│   ├── aliyun/                 # Terraform: 阿里云 ACK + RDS + KMS
│   └── tencent/                # Terraform: 腾讯云 TKE + TencentDB
├── monitoring/
│   └── uptime-kuma.yml         # docker-compose for Uptime Kuma
└── .github/
    └── workflows/
        ├── ci.yml              # PR + main: lint, test, gitleaks
        └── deploy.yml          # tag: build, push to both clouds
```

---

## Day-to-day commands / 日常命令

```powershell
# Secrets / 密钥管理
task secrets:init         # 首次设置（已完成）/ first-time setup (already done)
task secrets:edit         # 用编辑器打开加密文件 / open encrypted file in $EDITOR
task secrets:view         # 打印解密后内容 / print decrypted contents
task secrets:export       # 写出 .env 文件 / write decrypted .env file
task secrets:rotate       # 轮转所有 age 钥匙 / rotate all age keys

# Backup / 备份
task backup:keys          # 拷贝 age 钥匙到备份位置 / copy age keys to backup location

# Local dev / 本地开发
task dev                  # 完整栈（app + db + cache）/ full stack
task dev:secrets          # 解密到 .env / decrypt secrets to .env
task dev:run              # 只跑应用（假设栈已起）/ run app only

# Code quality / 代码质量
task lint                 # 代码风格 / code style
task format               # 自动格式化 / auto-format
task test                 # 单元测试 / unit tests
task test:coverage        # 测试 + 覆盖率 / tests with coverage

# Build & ship / 构建 & 发布
task build                # docker buildx（多架构）/ multi-arch
task push                 # 推送到阿里云 ACR + 腾讯云 TCR
task deploy               # build + push + terraform apply

# Cleanup / 清理
task clean                # 删 .env 等临时文件 / remove .env, *.dec files
```

---

## CI / CD

`.github/workflows/ci.yml` runs on every push and PR:
每次 push 和 PR 都跑：

- Install sops + age / 装 sops + age
- `gitleaks detect` — blocks if any plaintext secret sneaks in
  拦截任何明文密钥漏出
- `npm ci && npm run lint && npm test`

`.github/workflows/deploy.yml` runs on every `v*` tag:
每个 `v*` tag 触发：

- Build multi-arch (amd64 + arm64) image / 多架构构建
- Push to Aliyun ACR and Tencent TCR / 推送到两家云
- For each cloud, decrypt `secrets/prod.env` with the cloud's KMS
  (OIDC, no long-lived keys in GitHub Secrets) and apply Terraform
  每家云用 KMS 解密 `secrets/prod.env`（OIDC，GitHub Secrets 无长期 key）并 apply Terraform

Required GitHub Secrets per cloud (see `RUNBOOK.md` for full setup):
每家云需要的 GitHub Secrets（完整配置见 `RUNBOOK.md`）：

- `ALIYUN_OIDC_PROVIDER_ARN`, `ALIYUN_OIDC_ROLE_ARN`
- `ALIYUN_ACR_USERNAME`, `ALIYUN_ACR_PASSWORD`
- `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`
- `TENCENT_TCR_USERNAME`, `TENCENT_TCR_PASSWORD`

---

## Multi-cloud / 多云

This project ships Terraform modules for both Aliyun and Tencent
Cloud. They provision:
本项目含阿里云和腾讯云的 Terraform 模块，配置：

- VPC + subnets / VPC + 子网
- Managed Kubernetes (ACK / TKE) / 托管 K8s
- Managed PostgreSQL (RDS / TencentDB) / 托管 PG
- KMS keys for production secrets / 生产密钥的 KMS
- Container registry namespaces / 容器仓库命名空间
- (Optional) Cloud logging and monitoring / （可选）云日志和监控

See `infra/aliyun/main.tf` and `infra/tencent/main.tf`. Both
read the production secrets at apply time via SOPS, so no plaintext
passwords ever live in Terraform state.
详见两个 `main.tf`。两者都在 apply 时通过 SOPS 读生产密钥，Terraform
state 里不会有明文密码。

---

## Security model — the 5 non-negotiables / 5 条铁律

1. **Private keys never enter git.** `.gitignore` blocks `key-*.txt`,
   `*.key`, `*.pem`. The encrypted `secrets/*.env` files are safe to
   commit and SHOULD be committed — that is the whole point.
   **私钥永不入库。** `.gitignore` 屏蔽 `key-*.txt`、`*.key`、`*.pem`。
   加密的 `secrets/*.env` 入库是安全的，而且应该入库——这才是这套系统的意义。

2. **Multiple keys for redundancy.** Generate key A (everyday) and
   key B (backup). Both can decrypt. Lose one, the other still works.
   **多把钥匙兜底。** 生成 A（日常）和 B（备份），任一能解。丢一把还有另一把。

3. **Offline backups.** The backup key B belongs on a USB drive, a
   safe, or encrypted cloud storage — somewhere NOT on the same disk
   as key A.
   **离线备份。** 备份钥匙 B 必须放在与 A **不同**物理位置——U 盘、保险柜、加密云盘。

4. **Rotate on a schedule.** `task secrets:rotate` regenerates the
   keypair and re-encrypts every file. Do this every 6-12 months, or
   immediately if you suspect compromise.
   **定期轮转。** `task secrets:rotate` 重新生成钥匙对并重加密所有文件。
   6-12 个月一次，或怀疑泄露时立即。

5. **Production keys are KMS-only.** `secrets/prod.env` should be
   encrypted so that ONLY the cloud KMS can decrypt, not local keys.
   The bootstrap comment in `.sops.yaml` shows the swap.
   **生产密钥仅 KMS 能解。** `secrets/prod.env` 应该加密成只有云 KMS 能解，
   本地钥匙解不开。`.sops.yaml` 的注释里有切换示例。

---

## Monitoring / 监控

`monitoring/uptime-kuma.yml` is a docker-compose for Uptime Kuma,
a self-hosted monitoring tool that does:
Uptime Kuma 是自托管监控工具，支持：

- HTTP/HTTPS probes / HTTP/HTTPS 拨测
- TCP port checks / TCP 端口检查
- TLS certificate expiry alerts / TLS 证书过期提醒
- Webhook alerts to WeChat, DingTalk, Telegram, Slack, email
  告警推送到微信/钉钉/Telegram/Slack/邮件

After running it (`docker compose -f monitoring/uptime-kuma.yml up -d`),
open `http://localhost:3001`, add your endpoints, and configure a
notification channel.
跑起来后打开 `http://localhost:3001` 加端点、配告警渠道。

---

## What's not in scope (yet) / 暂未涵盖

- **Service mesh / mTLS between app and database.** Add Linkerd or
  Istio if you have multiple services.
  **服务网格 / mTLS。** 多个服务时再加 Linkerd 或 Istio。
- **GitOps with ArgoCD.** `infra/*` deploys imperatively today. For
  declarative continuous delivery, layer ArgoCD on top.
  **GitOps。** 当前是命令式 apply，要声明式持续交付再叠 ArgoCD。
- **Database migration tool.** Add `golang-migrate` or `prisma migrate`
  when you have actual schema changes.
  **数据库迁移工具。** 有 schema 变更时加 `golang-migrate` 或 `prisma migrate`。

See `C:\home\dev-system\02-full-architecture.md` for the full picture.
完整架构见 `C:\home\dev-system\02-full-architecture.md`。
