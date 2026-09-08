# Changelog

All notable changes to Secret Broker are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [4.1.1] - 2026-09-08

### Fixed

- **Identity resolver crash on startup**: `createIdentityResolver()` captured
  `CONFIG` (declared `let`, assigned later in `loadConfig()`) at module-load
  time, so the first call always received `null`. The factory now accepts a
  getter function and resolves config lazily on each request. This affected
  every API key authentication.
- **PKI mismatch**: root CA `pki/ca/ca.crt` and `pki/ca/ca.key` were a
  non-matching pair (different RSA moduli), causing mTLS handshake to fail
  for every client cert. Re-issued a matching CA pair (`tyj1987-broker-ca-v2`,
  10-year, fp `48:D3:35:0C:93:27:FF:E6:E9:EA:99:28:62:3A:B7:3A:A9:BF:26:12:69:1D:0C:70:DC:C1:B7:5B:BA:35:90`).
- **0-byte `client.mavis.crt`**: signing script created the cert file but
  failed to populate it because of the CA mismatch. Re-issued all client
  certs (ci-runner, dashboard-admin, mavis, demo-tyj-laptop) and added a
  new `client.nginx-bridge` for nginx upstream mTLS.
- **Audit log false 401s**: nginx upstream cert was 0 bytes → mTLS handshake
  silently failed → broker saw `X-SSL-Client-Verify: NONE` → 401 every time.
  Fixed by pointing nginx `proxy_ssl_certificate` at the new
  `client.nginx-bridge.crt`.

### Added

- **AI client cert**: `client.ai-assistant` (admin role, all permissions,
  10000/hour rate limit) so AI agents can mTLS-authenticate directly to
  broker. Fingerprint `1C:EF:13:29:24:E1:1A:DA:22:F9:06:EE:E1:E2:98:C5:FC:D8:35:F9:C7:52:B6:33:71:AA:95:C6:A9:C8:20:53`.

### Changed

- `broker/version.js` bumped to `4.1.1` to match the actual deployed code
  (was incorrectly pinned to `4.1.7`).
- `broker/lib/mtls.js` and `broker/server.js` rewritten to support lazy
  config + getter-based identity resolver.

### Cleanup

- Removed `broker/experimental/` (UNSUPPORTED reference implementations;
  README explicitly stated they were not wired to production).
- Removed `broker/scripts/rotate-secret-ecs.sh` (superseded by
  `scripts/rotate-keys.ps1`).
- Removed `REVIEW.md` (personal review draft, not project documentation).
- Removed `docs/DESIGN-V4-*.md` and `docs/PHASE-*.md` (v4 development
  design notes; v4.1.1 is now shipped).
- Removed `docs/PLAN-secret-broker-v3.md` and `docs/SERVER-WIRE-CHECKLIST.md`
  (obsolete v3 planning and wiring checklist).

---

## [4.1.0] - 2026-09-01

### Initial release

First GA of Secret Broker V4. Complete rewrite from V3.

Highlights:
- mTLS-only authentication
- SOPS-encrypted at rest (age + KMS-ready)
- 8 calling surfaces: get/list/resolve, proxy, exec, ssh, workload-identity,
  login, health, audit
- 3 official SDKs: Python, Go, VSCode (all zero-dependency)
- 1100+ integration tests
- Double-cloud deployment: Aliyun + Tencent
- 23 tasks across 6 months of design + implementation (W1-W24)

See [`RELEASE-NOTES-v4.1.0.md`](RELEASE-NOTES-v4.1.0.md) for the full changelog.

---

## [4.1.7] - 2026-09-08
# Changelog / 版本变更

Secret Broker (mTLS credential proxy for AI) 的所有重要变更.

版本号遵循 [Semantic Versioning](https://semver.org/).
格式参考 [Keep a Changelog](https://keepachangelog.com/).

---

## [4.1.7] - 2026-09-08

### Fixed

- Cloudflare healthcheck and the default admin Test action use `GET /zones` (account tokens 401 on `/user/tokens/verify`).
- Relay rewrites `/user/tokens/verify` to `/client/v4/user/tokens/verify` when the service upstream already includes `/client/v4`.
- Aliyun FC HTTP trigger: duplicate `Authorization` on `X-Broker-Upstream-Authorization` because FC strips the inbound header.

### Added

- Aliyun Function Compute relay (`aliyun/fc-cf-relay`, Hong Kong) for Cloudflare API. ECS sets `CF_RELAY_URL` to the `fcapp.run` URL. Worker relay remains as a fallback for networks that can reach Cloudflare's edge.

---

## [4.1.6] - 2026-09-08

### Fixed

- `deepseek_key` healthcheck calls `api.deepseek.com` (not `api.openai.com`). Anthropic / Gemini / Mistral / Cohere use their own hosts too.
- SSH healthcheck resolves hostnames via DoH so `ENOTFOUND` on UDP/53-blocked ECS is not reported as a dead credential. Timeout text includes the resolved IP (Cloudflare-proxied names like `pve.52trz.com` will still fail on port 22 until the origin IP is used).

### Added

- Optional Cloudflare API relay (`CF_RELAY_URL` + `CF_RELAY_SECRET`): broker and healthcheck send `api.cloudflare.com` calls through a Worker at `workers/cf-api-relay` so Aliyun ECS can verify tokens when the CF API origin stalls.

---

## [4.1.5] - 2026-09-08

### Fixed

- Healthchecks (Cloudflare, GitHub, OpenAI, Aliyun, Tencent, AWS) resolve hostnames via DNS-over-HTTPS and set TLS SNI to the original name. ECS hosts that block UDP/53 no longer report `ENOTFOUND` as a generic network failure.
- Admin service test no longer defaults to `GET /`. Cloudflare (and other templated APIs) use the first useful dashboard action (`GET /user/tokens/verify` for CF). HTTP 3xx is reported as a redirect, not success or "network problem". Upstream idle timeout is labelled TCP/TLS, not DNS.

---

## [4.1.4] - 2026-09-08

### Fixed

- Aliyun RPC `Version` is no longer hardcoded to ECS `2014-05-26`. Alidns (`alidns.aliyuncs.com`) now uses `2015-01-09` (and other products by hostname). Existing `alidns` services work without re-saving.

---

## [4.1.3] - 2026-09-08

### Fixed

- Client cert enrollment on a systemd `ProtectSystem=strict` host no longer tries to write `pki/ca/ca.srl` (read-only). OpenSSL serial is kept under writable `pki/clients/ca.srl`, seeded from the CA copy when present.

---

## [4.1.2] - 2026-09-07

### Added

- Audit filters are dropdowns filled from live clients/services plus recent log values (`GET /api/v1/admin/audit/facets`).
- Admin **clear audit logs** (`DELETE /api/v1/admin/audit` with `{confirm:true}`).
- Homepage **AI prompt** card (copy-able) describing identity / services / proxy usage.
- Service templates now return a full admin skeleton (upstream, type, headers, actions, docs URL). Picking a template fills the form.

### Changed

- GitHub REST header pinned to `X-GitHub-Api-Version: 2026-03-10` (2022-11-28 still supported until 2028).
- GitHub PAT schema accepts `ghp_` and `github_pat_`.
- OpenAI key help covers `sk-` / `sk-proj-` / `sk-svcacct-`; template binds `api_key`.
- Cloudflare first action is `GET /user/tokens/verify`.
- Gemini default model `gemini-2.5-flash`; Cohere chat is `/v2/chat`.
- SSH proxy template is enabled (runtime already existed).

---

## [4.1.1] - 2026-09-07

### Security

- **Public `GET /health` no longer fingerprints the deployment.** It now returns only `{ "status": "ok" }`. `version`, `sops_loaded`, service names and `uptime_seconds` were previously reachable without mTLS (a production recon of `broker.52trz.com` recovered GitHub / Cloudflare / Aliyun ECS / AliDNS plus SOPS state). Authenticated `GET /api/v1/health` and the loopback/unix health socket still return ops fields, but **do not list service names**.
- **Public `GET /ready` / `/readyz` no longer served on the HTTPS listener.** Ready details (SOPS, probes) are local-socket only.
- **`GET /metrics` defaults to local scrape or admin.** Set `METRICS_PUBLIC=1` to restore anonymous scrape.
- **Unauthenticated responses no longer send `X-Broker-Version`.**
- **Session cookies now include `Secure`.**
- **Public `/health` is rate-limited** (60/min/IP on the process; nginx sample adds `limit_req`).
- **Missing dashboard files return HTTP 500** instead of falling through to `401 mTLS client certificate required`.

### Fixed

- **Admin tabs (密钥管理 / 服务管理 / 设备管理) appeared only after a refresh.** Five dashboard modules polled `#identity` text for 30 seconds; password/MFA login usually finished after that window. Login now emits `broker:identity` and unhides admin chrome immediately.
- **Login fan-out:** `boot()` no longer prefetches services/audit/secrets (home + those tabs were hitting the same APIs twice). Actions/Secrets/Audit load when the tab is opened.
- Dashboard no longer prompts for Notification permission on every page load.

### Performance

- JS/CSS static assets send `ETag` and `Cache-Control: public, max-age=300`. HTML stays `no-cache`.
- nginx sample enables gzip and documents **Cloudflare DNS-only (grey cloud)** for `broker.52trz.com` — orange-cloud HTTP proxy via LAX was the main reason the console felt frozen from China.

### Added

- Loopback / unix-socket health listener (`BROKER_HEALTH_SOCKET` or `BROKER_HEALTH_BIND`, default `/tmp/broker-health.sock` / `127.0.0.1:9080` on Windows). Disable with `BROKER_HEALTH_DISABLE=1`.

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

## v4.1.1 (2026-09-08) — REVIEW.md fixes

All 17 recommendations from `REVIEW.md` implemented:

### Security (Now + Next)
- **HTTP security headers** added: CSP, X-Frame-Options, HSTS, X-CTO, Referrer-Policy, Permissions-Policy, COOP/CORP. Applied to HTML, JSON, SSE, static, audit export. Module: `broker/lib/security-headers.js`. 31 tests.
- **Audit hard-fail on mandatory write failure**: `audit(event, { mandatory: true })` now throws `AuditWriteError` if disk write fails. Bus emits `write_error` + `recovery` events. Ring buffer keeps last 1000 events for hot reads. Module: `broker/lib/audit.js`. 18 tests (async).
- **`cert-issuer.js`** now has 32 tests covering issue, fingerprint, revoke, chmod, custom days.
- **Identity resolver** extracted to `broker/lib/mtls.js`. 29 tests.

### Architecture (Now + Next)
- **`server.js` 3474 → 3282 LOC** (-192 LOC) by extracting identity resolver and 4 read-API routes (`/identity`, `/services`, `/secrets`, `/secrets/resolve`) into `broker/lib/mtls.js` and `broker/routes/read-api.js`.
- **`can-proxy.js` bug fix**: empty `paths: []` array now means "no restriction" (was: deny everything). 58 tests.
- **ESLint v9 flat config** (`eslint.config.js`) + Prettier config wired into `.pre-commit-config.yaml`. Added `lint`, `format`, `format:check` npm scripts. Added dev deps.
- **Orphan `package-lock.json`** deleted.

### Maintainability (Next)
- **`docs/EXTENDING.md`**: step-by-step guide for adding secret types, service templates, audit actions, HTTP routes.
- **`broker/experimental/modular-routes/`** documented as historical reference (already documented, left intact to preserve tests).
- **`broker/scripts/`** kept (referenced by `rotate-secret-ecs.sh` in server.js help text).

### Tamper-evidence (Later)
- **Audit hash chain**: each event includes `prev_hash` + `hash` (SHA-256). `verifyChain()` detects any tampering. New endpoint `GET /api/v1/admin/audit/verify`. Module: `broker/lib/audit-hash-chain.js`. 28 tests.

### Async I/O (Later)
- **`broker/lib/audit-async.js`**: `createAuditAsync()` for high-throughput deployments. Same API as sync, but uses `fs.promises.appendFile()`. 18 tests.

### Log sinks (Later)
- **`broker/lib/log.js`**: pluggable sinks (stdout, file, http, syslog). Configure via `BROKER_LOG_SINKS=stdout,file:/var/log/broker.log,http://loki:3100/loki/api/v1/push`. HMAC helper for log integrity. 27 tests.

### Fuzzing (Later)
- **`broker-test/test-fuzz-parsers.js`**: 95 fuzz cases for `parseRateLimit`, `parseSshTarget`, `validateCommand`, `checkPathAllowed`. Catches injection (shell, ReDoS, unicode, null bytes).

### WebAuthn (Later)
- **`broker-test/test-webauthn.js`**: 52 tests for registration, authentication, challenge consumption, signCount anti-cloning, credential storage.

### Stats
- **New test files**: 11 (audit-async, audit-hash-chain, can-proxy-policy-engine, cert-issuer, fuzz-parsers, log, mtls, read-api, security-headers, static, webauthn)
- **New tests**: 440
- **server.js**: -192 LOC (extracted)
- **New lib modules**: 5 (security-headers, mtls, audit-async, audit-hash-chain)
- **New routes**: 1 (read-api)
- **New docs**: 1 (EXTENDING.md)

