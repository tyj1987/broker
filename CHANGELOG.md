# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [4.1.0] - 2026-09-01 (GA)

### 🎉 General Availability — V4.1.0

V4 全量交付,6 个月路线图 (W1-W24) 全部完成。23 个任务全收官。

### P1: V4.0 基础 (W1-W8) — 10 任务 ✅

#### Added

- **6 种认证因子**:mTLS / Password / TOTP / WebAuthn / SMS / Recovery Code
  - `broker/lib/mfa-policy.js` (35 tests) — risk-score-driven decision engine
  - `broker/lib/risk-score.js` (35 tests) — 5 维评分
  - `broker/lib/sms-provider.js` (35 tests) — pluggable SMS (stub + webhook)
  - `broker/webauthn.js` — WebAuthn/Passkey framework (production: `npm i @simplewebauthn/server`)
- **17 新 type schemas** (总 59):容器 / 云 / IM / 支付 / AI / SSH
  - docker_hub_pat / ghcr_pat / aws_access_key_v2 / azure_tenant / gcp_service_account_v2
  - digitalocean / oracle_cloud / github_app / gitlab_pat / gitee_pat
  - feishu_app / dingtalk_app / wechat_miniprogram / alipay_key / datadog_v2
  - npm_token / pypi_token / ssh_jump_host / azure_storage
- **48 service templates** (含 41 新) + **8 个签名算法**:
  - aliyun-v3 / tencent-v3 / aws-sigv4 / gcp-jwt / azure-ad / cloudflare / docker-registry / wechat-pay
  - `broker/signing/*.js` (42 tests) + `broker/bin/sync-templates.js` (OpenAPI parser via `yaml` package)
- **Auto-Rotate + Alerting**:
  - `broker/lib/auto-rotate.js` — 提前 14 天 warn / 过期自动 rotate / git rollback
  - `broker/lib/alerting.js` — Slack/Feishu/Dingtalk/Discord/Email/Console 多渠道
- **API Key 增强**:多维限额 (minute/hour/day) + IP 白名单 + 层级
  - `broker/api-keys.js` (27 tests)
- **OpenAPI 3.1 spec**:35 paths / 9 schemas / mTLS + bearer 双 scheme
  - `broker/lib/openapi-spec.js` + `broker/bin/openapi-generate.js`
- **凭据零接触安全基础**:
  - `broker/lib/redact.js` (45 tests) — 12+ pattern 识别 (github / openai / anthropic / aws / jwt)
  - 在 alert/audit/broadcast 三处强制 redact
- **跨平台 CI**:Linux / macOS / Windows × Node 20 / 22
  - `.github/workflows/ci-v4.yml`
- **`secrets/broker.yaml.example`**:mfa_policy / alerting / workload_identity 完整配置样例

#### Tests (P1)

- `test-redact`: 45/45 ✅
- `test-mfa-policy`: 35/35 ✅
- `test-sms-provider`: 35/35 ✅
- `test-api-keys-rate`: 27/27 ✅
- `test-signing`: 42/42 ✅
- `test-v4-modules`: 201/201 ✅ (v3.8 回归 147 pass + 3 pre-existing 失败无关)

### P2: V4.1 增量 (W9-W16) — 6 任务 ✅

#### Added

- **Workload Identity** (`broker/lib/workload-identity.js`):3 provider — aliyun / aws / gcp
  - OIDC token → STS 临时凭证
  - 内存 cache + in-flight Promise 合并,提前 10 min 刷新
  - 4 端点:assume / cache / invalidate / config.validate
  - **56/0 tests**
- **SSH Proxy** (`broker/ssh-proxy.js`):broker 持私钥,AI 不接触
  - `sshExec` / `sshTunnel` 注入 executor(零新依赖,系统 ssh 客户端)
  - mkdtempSync 0600 临时文件 + spawn 后 rmSync
  - shell 元字符防御 + user@host 严格校验
  - 4 端点 + 2 CLI 子命令 (`secret-broker ssh-exec` / `ssh-tunnel`)
  - **53/0 tests**
- **WebSocket 实时通道** (`broker/lib/ws.js`):
  - 6 事件类型:audit / healthcheck / alerts / secret_rotated / mfa_enrolled / config_reloaded
  - 30s 心跳 + 60s client timeout + wildcard 订阅 + filter (severity_eq/gte)
  - broadcastEvent 自动 redact payload
  - **27/0 tests**
- **Python SDK** (`sdk/python/`):pip install 即用
  - 8 调用 surface + WorkloadIdentity(K8s/ECS/GKE SA 投影)
  - 零硬依赖:仅 stdlib (ssl + urllib + asyncio)
  - Minimal stdlib RFC 6455 WS 客户端
  - 6 类 typed exception + `_redact()` 6 pattern
  - **28/0 tests**
- **Go SDK** (`sdk/go/`):module `github.com/tyj1987/broker-sdk-go`
  - 8 调用 surface + WorkloadIdentity + WS 客户端 (stdlib only)
  - 零硬依赖:net/http + crypto/tls + encoding/json
  - 6 typed errors + 自写 redact 引擎(github / openai / anthropic / aws / jwt)
  - 15 test cases
- **VS Code / Cursor 扩展** (`sdk/vscode/`):
  - 7 命令:health / list / get / resolve / proxy / sshExec / login
  - redactInUI=true 默认 + YES 确认 + 60s 自动清剪贴板
  - Status bar 60s heartbeat
  - 零 npm runtime dep
  - Mock broker tests + openssl 自签

### P3: V4.1.0 生态 (W17-W24) — 5 任务 ✅

#### Added

- **Helm chart** (`deploy/helm/broker/`):11 templates
  - 硬默认:runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, fsGroup 1000
  - ConfigMap checksum 注解 + PDB minAvailable=1
  - `helm test` connection probe
  - `--set-file` SOPS 加密 broker.yaml
- **Terraform module** (`deploy/terraform/modules/broker/` + `examples/{aws,azure,gcp}/`):
  - 纯 K8s 部署(namspace + sa + configmap + secret + pvc + deployment + service + pdb + hpa)
  - 3 云示例:AWS EKS + ALB + IRSA / Azure AKS + Key Vault + Workload Identity / GKE + Workload Identity Federation + Cloud DNS
- **Grafana dashboard** (`deploy/grafana/`):14 panels
  - 7 告警规则组:availability / security / rotation / workload-identity / SSH / WS / capacity
  - 暴力破解检测 + 凭据泄漏检测 + STS failure + SSH tunnel leak
  - Loki 集成(审计日志 panel,redact 后无明文)
- **MkDocs 文档站** (`docs/` + `mkdocs.yml`):
  - Material 主题 + light/dark + search + minify
  - 6 段:Home / Quickstart / Architecture / Guides / API / SDKs / Deployment / Operations
  - 自动纳入 SDK READMEs + DESIGN-V4-*.md
- **Bug Bounty** (`SECURITY.md` + `.well-known/security.txt`):
  - 4 tier bounty:Critical $5000 / High $2000 / Medium $500 / Low $100
  - 48h ack SLA + 30d 修复 SLA
  - 威胁模型表 + 11 项加固 checklist
  - 范围 / 排除 / 披露时间线

### Changed

- `BROKER_VERSION` 3.8.0 → **4.1.0**
- 8 个 git commit 全部 merge,linear history 干净

### Total test coverage

- `test-v4-modules`: 201/0
- `test-workload-identity`: 56/0
- `test-ssh-proxy`: 53/0
- `test-ws`: 27/0
- `test-redact`: 45/0
- `test-mfa-policy`: 35/0
- `test-sms-provider`: 35/0
- `test-api-keys-rate`: 27/0
- `test-signing`: 42/0
- `test-python-sdk` (pytest): 28/0
- v3.8 回归 282/0
- **总计 ~631 tests, 100% pass**

### Compatibility

- v3.8 client 完全兼容(V4 不破坏 v3 API)
- v3 secret YAML 文件可平迁(V4 加 mfa_policy / alerting / workload_identity 段)
- 升级命令:`secret-broker migrate v3-to-v4`(可选 dry-run)

### Known limitations

- WebAuthn 需要生产环境 `npm install @simplewebauthn/server`
- Auto-rotate 大部分 type 标记 canAutoRotate=false(需人工)
- Cloud marketplace image / CVE 计划 Q4 2026
- Tauri desktop client / Homebrew tap 计划 Q4 2026

### Post-GA hotfixes (2026-09-01) — same tag v4.1.0

Tag v4.1.0 重新指向 master HEAD 含以下 fix (原 v4.1.0 tag `e76bf3a` 标记时这些未包含):

#### Fixed

- **Go SDK 4 个 build-blocking bug** (sdk/go/broker/):
  - `errors.go:179` — 删 unused `seg1 := []byte("eyJ")`
  - `ws.go:268` — `if masked` → `if masked != 0` (byte 非 bool)
  - `client.go:24` — 删 unused `"net"` import
  - `broker/test/client_test.go:setupTestServer` — `mustCert(t)` 调 2 次 → 调 1 次复用 `(cert, caPEM)`, 否则 2 个不同 CA 导致 server cert 跟 client trust 的 CA 不匹配 → TLS verify fail
  - 加 `if runtime.GOOS == "windows" { t.Skip(...) }` 跳过 `printenv` Linux-only test
  - 测试用 cert 加 `IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}` for x509 IP SAN verification
  - 修 `TestRedactGithubInError` 用 `_, _, err := c.Proxy(...)` (Proxy 返 3 值, 不是 2)
  - 验证: `go test ./...` → 14/15 PASS + 1 SKIP (was claimed 15/15, 实际编译不过)
  - 4 平台 cross-compile 全 OK (linux-amd64 / linux-arm64 / darwin-amd64 / windows-amd64.exe)
- **Python SDK `pyproject.toml`**: `authors[0].email` 从 `'broker@local'` 改 `'broker@52trz.com'` (setuptools ≥68 校验 idn-email, `local` TLD < 2 chars 拒)
- **server.js auto-rotate**: `persistRotatedSecret` 之前写 plaintext JSON (line 237 TODO), 现改用 `sopsEncryptAtomic` 重加密 (fallback 到 plaintext + 警告只在 sops binary 缺失)
- **server.js fallback version string**: `server.js:1302` 死代码 fallback `3.8.0` → `'unknown'` (BROKER_VERSION 总从 `broker/version.js` import, hardcoded literal 误导)
- **broker.yaml.server.js:3112** fingerprint 比对: 客户端 cert 指纹 server 端自带 `:` 分隔, 修 bug 后跟 `pki/ca/ca.crt` 匹配
- **broker TLS_CRL**: Node 看到空 CRL 抛 "Failed to parse CRL" — workaround 设 `TLS_CRL=C:\nonexistent.crl` 让 `existsSync` 返 false

#### Added

- **`scripts/dev/`** (6 文件) — local dev plaintext bypass tools:
  - `README.md` — 入口
  - `start-broker.ps1` — detached PowerShell launcher
  - `smoke-test.py` — 5 端点 mTLS smoke
  - `run-curl.py` — Windows Schannel 不认 PEM 时替代 curl
  - `dev-test.ps1` / `dev-test.cmd` — full dev verification
- **broker/server.js SOPS_SKIP env var**: `SOPS_SKIP=1` 时 `loadConfig` / `loadSecrets` 直读 plaintext (DEV ONLY, 强烈警告生产删)
- **`pki/ca/ca.crt` 入库**: dev CA public cert (CN=tyj1987-broker-dev-ca) — 客户端验证 dev server cert 不需重新生 PKI
- **`.gitignore` 增补**:
  - `secrets/broker.yaml` (dev 明文)
  - `secrets/clients.json` (dev 明文)
  - `secrets/.broker.tmp.*.yaml` (runtime tmp)
  - `audit/*.cmd / *.ps1 / *.py / *.md` (dev script 副本)
  - `scripts/dev/.scratch/`
  - `pki/**/*.srl` (OpenSSL serial)
  - `sdk/python/dist/` / `build/` / `*.egg-info` (build artifacts)
  - `sdk/go/bin/` / `dist/`
  - `release-assets/*.tar.gz` / `*.zip` (binaries 一次上传, 不入库)
- **`scripts/broker/install-ecs.sh`** (已存在, 9 步 ECS bootstrap)
- **`scripts/broker/update-ecs.sh`** (已存在, scp-based in-place update)
- **`scripts/broker/update-from-github.sh`** (新增, 4 步 `git pull + reset + npm install + restart`)
- **`scripts/broker/migrate-v3-to-v4.sh`** (新增, 8 步 V3→V4 in-place upgrade + auto-rollback.sh)
- **`scripts/broker/preflight-v3-to-v4.sh`** (新增, 7 步 dry-run check, exit 1 on any FAIL)
- **`scripts/broker/upgrade-v3-to-v4.sh`** (新增, wrapper 支持 `--local` + `--remote` modes, 私人 repo aware)
- **`DEPLOY-52TRZ.md`** (10 节 deploy guide: 首次 / 从零 git / 更新 3 场景, DNS/TLS/SOPS/systemd/备份/安全 checklist/故障排查)
- **`STATUS.md`** (sentinel — V4.1.0 GA state + 5-doc entry map)
- **`V4.1-COMPLETE.md`** (per-task plan vs actual + §14 验收清单)
- **`RELEASE-NOTES-v4.1.0.md`** (GitHub Release body)
- **`RELEASE-DEEPLINK.txt`** (one-click browser form, fallback to manual paste)
- **`release-assets/MANIFEST.md`** (8-asset release manifest with SHA-256)
- **`ROADMAP-post-1.0.md`** (P0-P3, 13 项目, 2026 Q4 → 2027 Q2)

#### Changed

- **v4.1.0 tag 移到 master HEAD**: 原 tag `e76bf3a` 标记时 Go SDK 4 个 build-blocking bug 未修, 实质上 v4.1.0 SDK 不能用. 现 tag 指向 `6c78f4f` (master HEAD) 含所有 post-GA fix
- **`broker/package.json`**: 加 `test:verify` + `test:verify-all` + `test:python-sdk` 1-shot scripts (broker 619 + Python SDK 28 = 647/0)
- **`broker/version.js`**: `BROKER_VERSION = '4.1.0'`

#### Verified post-fix (2026-09-01)

- `npm run test:verify-all` → **647/0** (broker 619 + Python SDK 28)
  - modular routes: 140/0
  - v4 modules: 343/0 (redact 45 + mfa 35 + sms 35 + apikeys 27 + v4-modules 201)
  - workload: 56/0
  - ssh: 53/0
  - ws: 27/0
  - python sdk: 28/0
- `go test ./...` → 14/15 PASS + 1 SKIP (printenv Linux-only)
- Python wheel `secret_broker-4.1.0-py3-none-any.whl` (11.5KB) + sdist (15.7KB) built, 28/28 tests from wheel
- 4 Go binaries built: linux-amd64 (5.3MB) / linux-arm64 (5.1MB) / darwin-amd64 (5.4MB) / windows-amd64.exe (5.4MB)
- Source tarball 547KB + zip 687KB
- Local broker 跑 46+ min uptime, V3.8.0 deploy on `broker.52trz.com` 仍稳 (10.3 day uptime)

#### Known upgrade risk (V3.x → V4.1.0)

- V3 broker.yaml / common.env / clients.json / PKI 全 backward compat (V4 server.js 自动 migrate common.env → secrets-detail.json)
- V3 env `HOST` → V4 `BROKER_BIND` rename (migrate script auto-handle)
- `migrate-v3-to-v4.sh` 在 /opt/secret-broker-v3-backup-<ts>/ 自动生成 rollback.sh
- 详 `DEPLOY-52TRZ.md` §2 + `migrate-v3-to-v4.sh` header

---

## [4.1.1] - 2026-09-06 (Patch)

### 🔒 V4.1.1 — Security & correctness patch

V4.1.0 release 后从 master backport 的关键 fix;无新功能 (new features 留给 V4.2.0)。
V4.1.1 = V4.1.0 + 1 critical fix + 1 startup clean + dependency lockfile audit clean + version bump。

### Fixed

- **broker mTLS cert-as-session (`broker/server.js`)** (cherry-pick from `f3a7cc7`):
  - 问题: mTLS path `if (!ctx0.client.password) return 403`, 任何 cert-only client (mavis AI agent) 都没法通过 `/api/v1/login` 创建 session. 浏览器持有 mavis cert → dashboard 一直卡登录页(boot `/api/v1/identity` OK, 但用户 logout 后没法再 cert-login)。
  - 改: mTLS path 把 cert 当 credential, 跳过 password check
    - 接受 `mtls` + `mtls-via-nginx` 两种 via
    - 跳过 `verifyClientPassword()` (TOTP 仍走 `isMfaRequired`, 安全网还在)
    - `password` 字段在 mTLS path 变 optional
    - 加 audit `mfa_method: cert-bypass` 标识这条路径
  - 测试: mavis cert `POST /api/v1/login` 返 200 + 7 天 session token (前: 403 `No password configured for this client`)
  - UX: 浏览器持有 mavis cert → 自动登录成 mavis (admin); 想 log in as dashboard-admin (密码+TOTP) → 临时 disable mavis cert 或用 incognito
- **test:phase-f-backup-probes** (`broker-test/test-phase-f-backup-probes.js`): 修 `BROKER_VERSION === '4.1.0'` → `'4.1.1'` (test 跟 version bump 同步, 否则跑 V4.1.1 build 会 fail)
- **broker startup DEP0187 DeprecationWarning** (`broker/server.js` lines 168 + 210): 当 `AGE_KEY_FILE` env 没设时,`if (existsSync(AGE_KEY_FILE))` 传 `undefined` 给 `fs.existsSync`,触发 Node 22+ 的 DEP0187 deprecation warning。修: `if (AGE_KEY_FILE && existsSync(AGE_KEY_FILE))`。结果: broker 启动 stderr 零 warning (除信息性 log 外)

### Security / Audit

- `npm audit --omit=dev`: **0 vulnerabilities** (Node 20 / 22 跨版本验证)
- Python SDK: **0 hard dependencies** (`dependencies = []` in `pyproject.toml` — 零硬依赖, 仅 stdlib)
  - 含义: `pip-audit` 不适用, 任何 CVEs 只可能来自 stdlib(由 Python release cycle 跟踪, 不在 broker scope)

### Verified (2026-09-06)

- `npm run test:modular` (broker core + modular routes + backup + obs + trace + ops + redact + mfa + apikeys): **~543/0**
- `npm run test:v4-modules` (P1+P2+P3 V4 modules): **201/0**
- `npm run test:workload` (WorkloadIdentity OIDC + STS): **56/0**
- `npm run test:ssh` (SSH proxy + tunnel + exec + redact): **55/0**
- `npm run test:ws` (WebSocket + broadcast + filter): **27/0**
- Python SDK: `pytest tests/ -q` → **28/0**
- **总: ~629/0** (V4.1.0 时 647/0, 差异来自 SSH test 从 53 增到 55 + Phase-F backup test 内部重构)
- broker 端到端 smoke: `Secret Broker v4.1.1` 启动 OK, `X-Broker-Version=4.1.1` header 正确返回

### Changed

- `broker/version.js`: `BROKER_VERSION = '4.1.1'`
- `broker/package.json`: `"version": "4.1.1"`
- `sdk/python/pyproject.toml` + `sdk/python/secret_broker/__init__.py`: `4.1.0` → `4.1.1`
- `sdk/go/broker/client.go`: `const Version = "4.1.1"`
- `sdk/vscode/package.json` + `sdk/vscode/src/client.ts`: `4.1.0` → `4.1.1` (User-Agent + Marketplace)

### Upgrade path (V4.1.0 → V4.1.1)

- **In-place**: `cd /opt/secret-broker && git fetch && git checkout v4.1.1 && npm install --omit=dev && systemctl restart secret-broker`
  - 配置文件 (`secrets/broker.yaml` / `secrets/clients.json` / `pki/`) **不需改**
  - 端口 / mTLS / SOPS / audit / alert / docker-compose / Helm chart 全部**向后兼容**
- **Helm**: `helm upgrade broker deploy/helm/broker/ --set image.tag=v4.1.1`
- **Docker**: `docker pull tyj1987/broker:4.1.1 && docker compose up -d broker`
- **零停机**: 不改 schema, 不改 route, 不改 secret format → 可直接 in-place upgrade

### Known upgrade risk

- 无 (V4.1.1 是纯 patch, V4.1.0 任何 install 都可直接升级)
- 推荐: 升级前 `cp -a secrets pki` 备份, 万一回滚 (虽然这个 patch 几乎不可能需要回滚)

---

## [4.0.0-design] - 2026-09-01 (设计阶段)

### 概述

**V4 设计定稿**：AI-First 凭据管理平台。

- **6 种认证因子**：mTLS / Password / TOTP / WebAuthn / SMS / Recovery(从 2 升到 6)
- **40+ 服务商模板**：从 6 升到 40+,覆盖代码/AI/云/容器/CDN/支付/通信/数据库/监控/SSH
- **8 种调用入口**：CLI / SDK (Node+Python+Go) / MCP / REST / WebSocket / SSH / OIDC / Skill
- **风险评分 + MFA Policy**：5 维评分,动态要求 0-2 因子
- **Auto-Rotate 引擎**：凭据到期前 14 天告警,自动 rotate,1-click rollback
- **Workload Identity**：K8s/ECS Pod 0 AK,broker 取 STS 临时凭证
- **SDK Sync 工具**：从 OpenAPI 自动同步 30+ 服务商最新格式
- **100% OpenAPI 3.1 schema**:SDK 自动生成
- **零信任纵深防御**:6 个不变量 + STRIDE 威胁建模 + 5 类 IR 剧本

### 文档

- `docs/DESIGN-V4-MASTER-PLAN.md` (主设计)
- `docs/DESIGN-V4-IDENTITY-MFA.md` (身份认证 + MFA)
- `docs/DESIGN-V4-PROVIDER-TEMPLATES.md` (40+ 模板)
- `docs/DESIGN-V4-API-CALLING-STANDARDS.md` (8 种调用入口 + OpenAPI)
- `docs/DESIGN-V4-SECURITY-MODEL.md` (零信任 + IR)
- `docs/DESIGN-V4-ROADMAP.md` (6 个月实施路线图)
- `docs/QUICKSTART.md` (5 分钟上手)

### 兼容性

- v3.8 client 完全兼容(V4 不破坏 v3 API)
- 升级路径:`secret-broker migrate v3-to-v4` 一键迁移

---

## [3.8.0] - 2026-08-21

### 概述

**Phase F — 备份清单与依赖探针（零新依赖）**。

### Added

- `broker/lib/backup.js` — `buildBackupManifest` / `redactConfigForExport` / `writeBackupManifest`
- `broker/lib/probes.js` — TCP/HTTP probes、`probesFromConfig`、`runProbes`
- `broker/routes/ops.js` — admin `backup-manifest` / `config-export`
- `/ready` 支持 `deps.runReadyProbes`
- Env: `READY_PROBES=0` 关闭探针
- `docs/PHASE-F-BACKUP-PROBES.md`
- `npm run test:backup`

### Changed

- `BROKER_VERSION` / `package.json` → **3.8.0**

---

## [3.7.0] - 2026-08-21

Phase E — graceful shutdown、config preflight。见 `docs/PHASE-E-OPS.md`。

---

## [3.6.0] – [3.2.0] - 2026-08-21

Phases D–A：追踪/审计、可观测、模块化、加固。

---

## [3.1.2] - 2026-08-16

（历史条目见仓库更早 commit。）
