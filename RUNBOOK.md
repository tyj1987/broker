# RUNBOOK / 运维手册

> Operational procedures for **Secret Broker** (mTLS HTTPS credential proxy).
> Secret Broker 的运维操作手册。
> Read this when something is on fire, before you rotate keys,
> or when you set up the project on a new machine.
> 出事时、轮转钥匙前、在新机器上搭项目时读这个。

---

## 0. Quick start on a new machine / 新机器快速搭建

```powershell
# 1. Install all required tools / 装所有必需工具
scoop install age sops git go-task gitleaks nodejs direnv
# winget fallback: winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS

# 2. Add direnv to your PowerShell profile / 给 PowerShell profile 加 direnv hook
pwsh -File scripts/install-direnv-hook.ps1
# Restart PowerShell. / 重启 PowerShell。

# 3. Clone the repo and bootstrap / 克隆仓库并引导
git clone https://github.com/tyj1987/sops-age-template.git
cd sops-age-template
pwsh -File bootstrap.ps1
# bootstrap: install sops/age + generate age key + encrypt secrets/broker.yaml.example -> secrets/broker.yaml
```

---

## 1. Secret Broker operations / 1. Secret Broker 运维

The Secret Broker lives on the ECS at `/opt/secret-broker/`.
Secret Broker 在 ECS 上的位置是 `/opt/secret-broker/`。

### 5.1 Layout / 5.1 目录结构

| Path / 路径 | Purpose / 用途 |
|---|---|
| `/opt/secret-broker/broker/server.js` | mTLS HTTP server (Node, ESM) / mTLS HTTP 服务（Node ESM） |
| `/opt/secret-broker/broker/dashboard/{index.html,app.js,style.css,admin/*.js}` | Vanilla-JS admin UI / 管理 UI（无框架） |
| `/opt/secret-broker/secrets/broker.yaml` | SOPS-encrypted config: services + clients / SOPS 加密配置 |
| `/opt/secret-broker/secrets/secrets-detail.json` | SOPS-encrypted structured secret store / SOPS 加密结构化密钥库 |
| `/opt/secret-broker/pki/{ca,server,clients}/` | mTLS material (CA + server cert + per-client certs) / mTLS 材质 |
| `/opt/secret-broker/age/key.txt` | age private key (mode 600) / age 私钥（600 权限） |
| `/opt/secret-broker/audit/<date>.jsonl` | append-only audit log / 追加式审计日志 |
| `/opt/secret-broker/scripts/` | helper scripts (issue-client-cert.sh, backup-keys.ps1, etc.) / 辅助脚本 |
| `/etc/systemd/system/secret-broker.service` | systemd unit (ReadOnlyPaths=/opt/secret-broker, ReadWritePaths=audit,secrets) / systemd 单元（加固） |

### 5.2 Day-to-day ops / 5.2 日常运维

```bash
ssh user@broker-host
systemctl status secret-broker                      # status / 状态
systemctl restart secret-broker                     # restart (after config edit) / 改配置后重启
journalctl -u secret-broker -f                      # follow logs / 跟踪日志
journalctl -u secret-broker --since "10 min ago"    # recent events / 最近事件
# Get current reload token (for hot config reload via API) / 拿 reload token（热加载）
journalctl -u secret-broker | grep "reload token" | tail -1
```

`systemctl restart secret-broker` is the only reload mechanism that is
guaranteed to pick up code changes; for `broker.yaml` / secrets changes
only, the API also supports hot reload via the reload token (see below).
`systemctl restart` 是唯一能加载代码改动的；只改 `broker.yaml`/密钥时，
可走 API 热加载（见下）。

### 5.3 Hot reload broker.yaml / 5.3 热加载 broker.yaml

For adding/changing services or clients without restarting the broker:
加/改 services 或 clients 时，不重启 broker：

```bash
ssh user@broker-host
TOKEN=$(journalctl -u secret-broker | grep "reload token" | tail -1 | grep -oE '[0-9a-f-]{36}')
curl -sk -X POST -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/api/v1/admin/reload
# Returns the new audit log + token; broker keeps running.
# 返回新的 audit log + token；broker 继续跑。
```

Or use the out-of-band scripts to also re-encrypt broker.yaml via SOPS:
或用 out-of-band 脚本调 SOPS 重加密 broker.yaml：

```bash
ssh user@broker-host
/opt/secret-broker/scripts/issue-client-cert.sh <client-name>      # issue / 签发
# Internally: decrypt → mutate → re-encrypt → call broker reload API
# 内部：解密 → 修改 → 重加密 → 调 broker reload API
```

### 5.4 Issuing client certificates / 5.4 签发客户端证书

The dashboard UI has a `💻 设备管理 / Devices` tab that lets admin
issue / rotate / revoke client certs. **However, on production ECS
the PKI directory is read-only by design** (systemd hardening):
dashboard UI enrollment returns HTTP 503 + a yellow banner pointing
to the script. Use the script for production client certs:
管理 UI 有「💻 设备管理」tab 可以签发/轮换/撤销客户端证书。
生产 unit 把 `pki/ca`（含 CA 私钥）保持只读；签发序号写在可写的
`pki/clients/ca.srl`（v4.1.3+）。若 UI 仍报 Read-only file system，
确认 `ReadWritePaths` 含 `/opt/secret-broker/pki/clients`。
离线签发仍可用脚本：

```bash
ssh user@broker-host
/opt/secret-broker/scripts/issue-client-cert.sh my-laptop
# Generates: pki/clients/client.my-laptop.{crt,key}
# Updates broker.yaml with new fingerprint + adds to clients
# Re-encrypts broker.yaml via SOPS, calls broker reload API.
# 生成证书，更新 broker.yaml 客户端指纹，SOPS 重加密，broker 热加载。
```

For other PKI management tasks (rotate, revoke, list), use the same
script with `--rotate` / `--revoke` / `--list` (see `--help`).
轮换/撤销/列表见脚本 `--help`。

To get a client bundle (ca.crt + client.crt + client.key + install.sh)
as a zip — usually a one-off for the production UI which doesn't
have write access — the script also supports `--bundle <name>`.
要拿 zip bundle（ca.crt + client.crt + client.key + install.sh）通常
生产 UI 写不了时用一次，脚本也支持 `--bundle <name>`。

### 5.5 Local dev / test broker (broker-test) / 5.5 本地测试 broker

A throwaway local broker lives at `C:\Users\User\broker-test\` for
running end-to-end tests without touching production:
本地有一个一次性 broker 在 `C:\Users\User\broker-test\`，跑端到端
测试用，不碰生产：

```powershell
# Start broker on 127.0.0.1:18443 (PKI from broker-test/pki, not prod)
/ 用 broker-test/pki，不碰生产 PKI
Start-Process node -ArgumentList "C:\Users\User\broker-test\mock-upstream.js" `
  -RedirectStandardOutput C:\Users\User\broker-test\logs\mock-upstream.out `
  -RedirectStandardError C:\Users\User\broker-test\logs\mock-upstream.err `
  -WindowStyle Hidden -PassThru
Start-Process powershell -ArgumentList "-NoProfile","-Command","cd C:\Users\User\broker-test; `$env:PORT='18443'; `$env:HOST='127.0.0.1'; `$env:CONFIG_PATH='C:\Users\User\broker-test\secrets\broker.yaml'; `$env:SECRETS_DETAIL_PATH='C:\Users\User\broker-test\secrets\secrets-detail.json'; `$env:PKI_DIR='C:\Users\User\broker-test\pki'; `$env:COMMON_ENV_PATH='C:\Users\User\broker-test\secrets\common.env'; `$env:AGE_KEY_FILE='C:\Users\User\broker-test\age\key.txt'; `$env:TLS_CA='C:\Users\User\broker-test\pki\ca.crt'; `$env:TLS_CERT='C:\Users\User\broker-test\pki\server\server.crt'; `$env:TLS_KEY='C:\Users\User\broker-test\pki\server\server.key'; `$env:OPENSSL_BIN='C:\Program Files\Git\usr\bin\openssl.exe'; node C:\home\my-first-app\broker\server.js" `
  -RedirectStandardOutput C:\Users\User\broker-test\logs\broker.out `
  -RedirectStandardError C:\Users\User\broker-test\logs\broker.err `
  -WindowStyle Hidden -PassThru

# Run the test suites / 跑测试套件
cd C:\Users\User\broker-test
node test-thorough.js       # 40 tests (secrets CRUD + bulk + file upload + eye toggle)
node test-services-crud.js  # 17 tests (services CRUD + templates + test connection)
node test-clients-crud.js   # 16 tests (clients CRUD + cert enroll/rotate/bundle)
node test-audit.js          # 11 tests (filters + SSE stream + JSON/CSV export)

# Login: client `client.dashboard-admin`, password `a203df55219b804edb4b8a0f`
# 登录：client 名称 `client.dashboard-admin`，密码 `a203df55219b804edb4b8a0f`
```

**Hard rule / 硬规则**:
- All tests in broker-test point at `https://127.0.0.1:18443` — NEVER
  at `https://broker.example.com` (production). A pre-cleanup hook deletes
  any secret whose name starts with the test prefix; it does **not**
  delete hard-coded production keys like `GITHUB_PAT`. Adding a new
  test? `grep -l 'broker.example.com' broker-test/test-*.js` first to
  verify no URLs leak to prod.
  所有 broker-test 测试只打 `https://127.0.0.1:18443` —— **绝对不**
  打 `https://broker.example.com`（生产）。pre-cleanup 钩子只删自己命名前
  缀的测试残留，**不删** `GITHUB_PAT` 这类硬编码生产密钥。写新测试
  前先 `grep -l 'broker.example.com' broker-test/test-*.js` 防止 URL 泄到生产。
- If a test starts failing intermittently, check `logs/broker.err` first
  (lots of `ssl3_read_bytes: certificate unknown` is normal — those are
  password-lock or no-cert probes). Lock out after 5 fails for 15 min.
  如果测试开始间歇性失败，先看 `logs/broker.err`（大量
  `ssl3_read_bytes: certificate unknown` 是正常的——密码锁定或无证书
  探测）。5 次失败锁 15 分钟。

### 5.6 Audit log / 5.6 审计日志

The audit log is append-only JSONL at `/opt/secret-broker/audit/<date>.jsonl`.
It records: `ts, action, status, cn, fp, service, method, path, error, name,
field, reason, latency_ms, upstream_status`. Secrets are NEVER recorded
(masked at the source).
审计日志在 `/opt/secret-broker/audit/<date>.jsonl`，追加式 JSONL。记录：
`ts, action, status, cn, fp, service, method, path, error, name, field, reason,
latency_ms, upstream_status`。**密钥永不记录**（源头 mask）。

Inspect via API (admin only) / 通过 API 看（仅 admin）：

```bash
# Last 20 events / 最近 20 条
curl -sk -b /tmp/cookies.txt 'https://broker.example.com/api/v1/admin/audit?limit=20'
# Filter by client / service / action / status / time range / 按客户端/服务/动作/状态/时间过滤
curl -sk -b /tmp/cookies.txt 'https://broker.example.com/api/v1/admin/audit?client=ci-runner&action=proxy&since=2026-08-15T00:00:00Z'
# Real-time SSE stream (30 min auto-disconnect, 25s heartbeat) / 实时 SSE 流
curl -sk -b /tmp/cookies.txt -H 'Accept: text/event-stream' \
  https://broker.example.com/api/v1/admin/audit/stream
# Export / 导出
curl -sk -b /tmp/cookies.txt 'https://broker.example.com/api/v1/admin/audit/export.csv?limit=1000' -o audit.csv
curl -sk -b /tmp/cookies.txt 'https://broker.example.com/api/v1/admin/audit/export.json?limit=1000' -o audit.json
```

Or use the dashboard `📋 审计 / Audit` tab (filters + live stream +
export buttons + anomaly highlighting).
或用 dashboard `📋 审计 / Audit` tab（过滤 + 实时流 + 导出按钮 +
异常高亮）。

### 5.7 Phase 1+2 feature matrix / 5.7 Phase 1+2 功能矩阵

| Tab / 标签 | Path / 路径 | What it does / 用途 |
|---|---|---|
| `🏠 首页 / Home` | `home.js` | 4 stat cards + quick actions + recent activity + admin TODO / 概览 + 快捷操作 + 最近活动 + 待办（轮换提醒） |
| `⚡ 动作 / Actions` | `app.js` | Browse services → call upstream via broker / 浏览服务 → 走 broker 调上游 |
| `📋 审计 / Audit` | `admin/audit.js` | Filter, SSE live stream, JSON/CSV export, anomaly highlight / 过滤 + 实时流 + 导出 + 异常高亮 |
| `🔑 可见密钥 / Secrets` | `admin/secrets.js` | Read-only view of secrets the current client can see / 当前客户端可见密钥只读视图 |
| `🗝️ 密钥管理 / Manage` | `admin/secrets.js` | CRUD structured secrets (multi-field), bulk delete, file upload, eye toggle / 结构化密钥 CRUD + 批量删除 + 文件上传 + 眼睛 |
| `🔌 服务管理 / Services` | `admin/services.js` | CRUD services from 6 templates, test connection, permissions matrix / 6 模板服务 CRUD + 连通测试 + 权限矩阵 |
| `💻 设备管理 / Devices` | `admin/clients.js` | CRUD clients, enroll/rotate/revoke (UI; 503 on prod due to PKI read-only) / 客户端 CRUD + 签发/轮换/撤销（生产 UI 返 503） |
| `📖 文档 / Docs` | `app.js` | API reference, examples / API 参考 + 示例 |

### 5.8 Keyboard shortcuts / 5.8 键盘快捷键

Press `?` (Shift+/) anywhere outside an input to see the help modal. Style:
Gmail-like two-key sequences. / 在 input/textarea 之外的任意位置按 `?`
（Shift+/）可看帮助。Gmail 风格两键序列。

| Sequence | Action / 行为 |
|---|---|
| `g h` | 跳到首页 / Go to Home |
| `g a` | 跳到动作 / Go to Actions |
| `g s` | 跳到密钥 / Go to Secrets (visible) |
| `g u` | 跳到审计 / Go to aUdit |
| `g d` | 跳到文档 / Go to Docs |
| `g k` | 跳到密钥管理 / Go to Keys management (admin) |
| `g p` | 跳到服务管理 / Go to services (admin) |
| `g c` | 跳到设备管理 / Go to Clients (admin) |
| `?` | 显示帮助 / Show help |
| `Esc` | 关闭弹窗 / Close modal |

### 5.9 Secret rotation policy / 5.9 密钥轮换策略

`secrets-detail.json` supports per-secret rotation metadata. UI (home tab
admin TODO list) warns when secrets need rotation.
`secrets-detail.json` 支持每个密钥的轮换元数据。Home tab 的 admin TODO
列表会在密钥需要轮换时显示提醒。

Set rotation policy in admin UI: open 密钥管理 / Manage → edit secret → set
`rotation_policy_days` (e.g. 90). On next load, `last_rotated_at` defaults
to the secret's `updated_at`. The home TODO list shows:
管理 UI 设置：打开密钥管理 → 编辑密钥 → 设 `rotation_policy_days`（如 90）。
下次加载时 `last_rotated_at` 默认用 `updated_at`。Home TODO 列表显示：

- 🟡 还剩 N 天到轮换期 (>= 80% of policy)
- 🔴 已 N 天未轮换 (>= 100% of policy)
- 🟡 无轮换时间戳 (no `last_rotated_at`)

When you rotate a secret (sops edit, then `updated_at` is freshened by the
admin UI), the warning clears automatically.
轮换密钥（sops 编辑后 admin UI 自动更新 `updated_at`）后，提醒会自动消失。

### 5.10 ECS daily snapshot policy / 5.10 ECS 每日快照策略

```bash
ssh user@broker-host
/opt/secret-broker/scripts/ecs-snapshot-policy.sh install   # enable
/opt/secret-broker/scripts/ecs-snapshot-policy.sh status    # check
/opt/secret-broker/scripts/ecs-snapshot-policy.sh uninstall
```

Creates `/etc/systemd/system/ecs-snapshot.{service,timer}`. Timer fires
daily at 03:00 (with ±10min randomize). The script calls ECS OpenAPI
through the broker (no direct ALIYUN_ACCESS_KEY in the script — all
calls audited at /opt/secret-broker/audit/).
创建 systemd unit。每日 03:00 触发，调用走 broker 转发（脚本里没 AK，
全部 audit 记录）。

Snapshots older than `RETENTION_DAYS=7` (default) are auto-deleted; only
snapshots whose name starts with `auto-` are considered for cleanup, so
manual snapshots you create are safe.
超过 7 天的快照自动清理；只清理 `auto-` 前缀的，手动快照不受影响。

Test count (local broker-test, 2-round stable) / 测试数（本地 broker-test，2 轮稳定）:
test-thorough.js 40 + test-services-crud.js 17 + test-clients-crud.js 16 +
test-audit.js 11 + test-home.js 8 + test-shortcuts.js 6 =
**98/98 × 2 = 196/196 stable**.

---

## 2. Production deployment / 2. 生产部署

### Prerequisites (one-time, per cloud) / 前置条件（一次性，每家云）

#### Aliyun / 阿里云
1. Create a RAM role with OIDC trust for GitHub Actions.
   / 创建一个 OIDC 信任 GitHub Actions 的 RAM 角色。
2. Grant the role permission to: `kms:Decrypt`, `acr:*`, `cs:*`,
   `vpc:*`, `rds:*`, `oss:*`. / 授权：kms、acr、cs、vpc、rds、oss。
3. Create a Container Registry namespace. / 创建容器仓库命名空间。
4. Create a Terraform state OSS bucket (encrypted with KMS).
   / 创建一个加密的 OSS 桶给 Terraform state。
5. Add to GitHub repository secrets: / 加到 GitHub Secrets：
   - `ALIYUN_OIDC_PROVIDER_ARN`
   - `ALIYUN_OIDC_ROLE_ARN`
   - `ALIYUN_ACR_USERNAME`
   - `ALIYUN_ACR_PASSWORD`

#### Tencent / 腾讯云
1. Create a CAM role / sub-account. / 创建 CAM 角色或子账号。
2. Grant permissions: `kms`, `tcr`, `tke`, `vpc`, `postgres`,
   `cos`, `cvm`. / 授权同上。
3. Create a TCR instance and namespace. / 创建 TCR 实例和命名空间。
4. Create a Terraform state COS bucket. / 创建 Terraform state COS 桶。
5. Add to GitHub repository secrets: / 加到 GitHub Secrets：
   - `TENCENTCLOUD_SECRET_ID`
   - `TENCENTCLOUD_SECRET_KEY`
   - `TENCENT_TCR_USERNAME`
   - `TENCENT_TCR_PASSWORD`

### Deploy / 部署

```powershell
git tag v1.0.0
git push --tags
# GitHub Actions automatically: / 自动：
#   1. Builds the image / 构建镜像
#   2. Pushes to both Aliyun ACR and Tencent TCR / 推两家云
#   3. Decrypts secrets/prod.env using the cloud's KMS / 云 KMS 解密
#   4. Applies Terraform in both regions / 两家云 apply Terraform
```

### Manual deploy (without CI) / 手动部署（无 CI）

```powershell
# Set up cloud credentials / 配云凭证
$env:ALIBABA_CLOUD_ACCESS_KEY_ID = "..."
$env:ALIBABA_CLOUD_ACCESS_KEY_SECRET = "..."
# (Or for Tencent / 或腾讯云)
$env:TENCENTCLOUD_SECRET_ID = "..."
$env:TENCENTCLOUD_SECRET_KEY = "..."

# Build + push + deploy / 构建 + 推送 + 部署
task deploy TAG=v1.0.0
```

### Secret Broker: public access via Cloudflare Tunnel
### Secret Broker：Cloudflare Tunnel 公网暴露

Public entry: `https://broker.example.com` → Cloudflare edge → tunnel →
ECS `127.0.0.1:8443`. Secrets never leave the broker; TLS terminates
at the CF edge, so browsers see a trusted cert without installing the
self-signed CA.
公网入口：`https://broker.example.com` → Cloudflare 边缘 → 隧道 → ECS
`127.0.0.1:8443`。明文密钥永不离开发送端；TLS 在 CF 边缘终结，浏览器看到的是
受信证书，不需要安装自签 CA。

Key files on the ECS / ECS 上关键文件：

| Path / 路径 | Purpose / 用途 |
|---|---|
| `/etc/cloudflared/config.yml` | tunnel ingress: `broker.example.com -> https://127.0.0.1:8443`（`noTLSVerify: true`，自签 origin） |
| `/etc/systemd/system/cloudflared-secret-broker.service` | systemd unit, auto-start on boot |
| `/root/.cloudflared/e26e5c58-….json` | tunnel credentials (keep secret) |
| `/root/.cloudflared/cert.pem` | zone-level origin cert (from `cloudflared tunnel login`) |

Day-to-day ops / 日常操作：

```bash
ssh user@broker-host
systemctl status cloudflared-secret-broker     # status
journalctl -u cloudflared-secret-broker -f     # follow logs
systemctl restart cloudflared-secret-broker    # restart
```

Add another hostname / 增加新的域名入口：
`cloudflared tunnel route dns secret-broker other.example.com`，再往
`/etc/cloudflared/config.yml` 的 `ingress` 加一条，然后
`systemctl restart cloudflared-secret-broker`。

Local-machine note (China network) / 本机注意（国内网络）：
`broker.example.com` **must be Cloudflare DNS-only (grey cloud)** in front of
the origin nginx. Orange-cloud HTTP proxy via LAX made the dashboard take
many seconds to open and broke client-certificate passthrough. Do not pin
random CF anycast IPs in `hosts` as a workaround.

公开 `GET /health` 只应返回 `{"status":"ok"}`。运维指纹走已认证
`GET /api/v1/health` 或本机 health socket（默认 `127.0.0.1:9080` /
`/tmp/broker-health.sock`）。

无证书打开首页必须是 200 HTML：
`curl -sk -o /dev/null -w "%{http_code}" https://broker.example.com/`

Security notes / 安全提示：
- Password login is protected by a 5-fail → 15-min lockout; sessions are
  30-min sliding. / 密码登录有 5 次失败锁 15 分钟；会话 30 分钟滑动过期。
- All requests arrive via the tunnel as `127.0.0.1`; real client IP is
  in the `cf-connecting-ip` header (not yet surfaced in the audit log).
  / 所有请求经隧道到达，显示为 127.0.0.1；真实客户端 IP 在
  `cf-connecting-ip` 头里（暂未写进审计日志）。
- Optional hardening: wrap the hostname in Cloudflare Access (Zero Trust)
  for a second factor before the password. / 可选加固：用 Cloudflare
  Access（Zero Trust）给域名套第二层认证。

---

## 3. Incident response / 3. 应急响应

### Secret accidentally committed in plaintext / 明文密钥误提交

1. **Rotate the secret immediately.** Treat it as compromised.
   / **立即轮转密钥。** 当成已泄露处理。
2. Remove the file from git history / 从 git 历史删除：
   ```powershell
   git filter-repo --path secrets/secret-leaked.txt --invert-paths
   git push --force
   ```
3. Update `.sops.yaml` and re-encrypt with a new key if the leaked
   value was an age key. / 如果泄露的是 age 私钥，更新 `.sops.yaml` 并用新钥匙重加密。
4. Notify the team. / 通知团队。

### Age key stolen or lost / age 钥匙被偷或丢失

- **Stolen / 被偷**: Treat all secrets as compromised. Rotate every
  secret in `secrets/`. Generate a new key, update `.sops.yaml`,
  re-encrypt everything.
  / 视为所有密钥泄露。轮转 `secrets/` 里每个密钥。生成新钥匙、更新 `.sops.yaml`、全部重加密。
- **Lost but not stolen / 丢了但没被偷**: You can still decrypt with
  the backup key B. Generate a new key A to replace the lost one.
  `task secrets:rotate`.
  / 备份钥匙 B 还能解。生成新 A 替代丢的 A。`task secrets:rotate`。

### Cloud KMS accidentally deleted / 云 KMS 误删

If the cloud KMS key that decrypts `secrets/prod.env` is deleted,
**all production secrets are unrecoverable**. This is why
`.sops.yaml` always includes a local fallback key — production
should be the only place where KMS is the sole key.
如果解密 `secrets/prod.env` 的云 KMS 密钥被删，**所有生产密钥不可恢复**。
这就是为什么 `.sops.yaml` 永远有本地兜底——生产应该是唯一只有 KMS 能解的。

If this happens, you must: / 万一发生了，你必须：
1. Generate new strong random values for every secret. / 给每个密钥生成新的强随机值。
2. Update `secrets/prod.env` with the new values. / 用新值更新 `secrets/prod.env`。
3. Re-apply Terraform with the new values. / 用新值重新 apply Terraform。

### Both private keys lost / 两把私钥都丢了

This is unrecoverable. Generate new strong random values for every
secret and start over. The encrypted files are still in git
history, but they are now permanent ciphertext.
**不可恢复。** 给每个密钥生成新强随机值，从头开始。加密文件还在 git
历史里，但现在它们就是永久密文。

**This is why the USB backup is non-negotiable.**
**这就是为什么 U 盘备份不可妥协。**

---

## 4. Monitoring / 4. 监控

> broker 自带 healthcheck 引擎 (M4) + 5 维 status 告警 (M5.3) + SSE 实时推送 (M5.6).
> dashboard home tab 看凭据自检状态; 异常 secret 立即有 audit + alert history + 浏览器通知.
> / broker 自带 healthcheck, 不需要外部监控启动.

### 4.1 Uptime Kuma (可选) / Optional Uptime Kuma

```powershell
# 用任意 docker host 起 Uptime Kuma (跟 broker 不一定要同机)
docker run -d --restart=always -p 127.0.0.1:3001:3001 \
  -v uptime-kuma-data:/app/data \
  louislam/uptime-kuma:1
# Open http://localhost:3001 / 打开 http://localhost:3001
```

Add monitors for: / 添加监控：
- `https://<broker-domain>/api/v1/health` (HTTP probe, returns 401 = broker alive / HTTP 拨测, 401 表示 broker 活着)
- `<broker-domain>` (TLS cert expiry / TLS 证书过期)
- SSH TCP probe to broker ECS (22)

Configure a notification channel: WeChat, DingTalk, Telegram, Slack,
or email. / 配告警渠道：微信/钉钉/Telegram/Slack/邮件。

### 4.2 broker healthcheck 自身 (built-in) / broker 自带健康度检查

- **Dashboard home tab** → 凭据自检 card: 5 维 status pill (ok/expired/unreachable/misconfigured/fail) + Run Now 按钮
- **每 4:00 cron** (broker 端): 自动跑 healthcheck, 5 secrets 5 维状态
- **SSE 实时推送** (admin only): `/api/v1/admin/healthcheck/stream` → dashboard 状态变化时红点 + 浏览器通知
- **alert_history** 持久化: `/api/v1/admin/alerts/history` → 状态变化 timeline

详见 git history。

---

## 5. Disaster recovery checklist / 5. 灾难恢复清单

Run this checklist every quarter to make sure the system still
recovers from a fresh machine.
每季度跑一遍这个清单，确保从零机器能恢复。

- [ ] Plug in USB with backup key. / 插上带备份钥匙的 U 盘。
- [ ] On a different machine (or VM): / 在另一台机器（或 VM）上：
  - [ ] `scoop install age sops git go-task direnv nodejs`
  - [ ] Copy `key-b-backup.txt` from USB to `~/.config/sops/age/`.
        / 把 U 盘上的 key-b-backup.txt 拷到 `~/.config/sops/age/`。
  - [ ] Clone the repo. / 克隆仓库。
  - [ ] `sops --decrypt secrets\common.env` succeeds. / 能解密。
  - [ ] `task dev` starts the stack. / task dev 能起栈。
  - [ ] `curl http://localhost:3000/health` shows
        `secrets_loaded: { database: true, redis: true, jwt: true }`.
        / 看到 secrets_loaded 全 true。
- [ ] If any step fails, the system is not actually recoverable. Fix
  the gap before going back to normal work.
  / 任何一步失败都说明系统不可恢复，先修好再回到正常工作。

---

## 6. Reference / 6. 参考

- SOPS docs / 文档: https://github.com/getsops/sops
- age docs / 文档: https://age-encryption.org
- Taskfile / 任务: https://taskfile.dev
- Terraform: https://developer.hashicorp.com/terraform
- Aliyun KMS: https://www.alibabacloud.com/help/en/kms
- Tencent KMS: https://www.tencentcloud.com/document/product/573
