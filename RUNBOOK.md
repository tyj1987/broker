# RUNBOOK / 运维手册

> Operational procedures for my-first-app.
> my-first-app 的运维操作手册。
> Read this when something is on fire, before you rotate keys,
> or when you set up the project on a new machine.
> 出事时、轮转钥匙前、在新机器上搭项目时读这个。

---

## 1. First-time setup on a new machine / 1. 新机器首次搭建

```powershell
# 1. Install all required tools / 装所有必需工具
scoop install age sops git go-task direnv gitleaks nodejs
# winget fallback: winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS

# 2. Add direnv to your PowerShell profile / 给 PowerShell profile 加 direnv hook
pwsh -File scripts/install-direnv-hook.ps1
# Restart PowerShell. / 重启 PowerShell。

# 3. Clone the repo and bootstrap / 克隆仓库并引导
git clone https://github.com/<you>/my-first-app.git
cd my-first-app
pwsh -File bootstrap.ps1
# (It will skip age key generation if a USB drive with key-b-backup.txt
#  is plugged in and copied to ~/.config/sops/age/key-b-backup.txt.)
# （如果 U 盘里插着 key-b-backup.txt 并拷到 ~/.config/sops/age/ 下，
#  bootstrap 会跳过重新生成 age 钥匙。）
```

The bootstrap script is idempotent. Run it on every new dev box.
bootstrap 脚本是幂等的。每台新机器都跑一次。

---

## 2. Day-to-day ops / 2. 日常运维

### View the current decrypted secrets / 查看当前解密的密钥

```powershell
task secrets:view
```

### Edit a secret / 编辑密钥

```powershell
task secrets:edit
# Opens secrets\common.env in $EDITOR. SOPS handles decrypt/edit/encrypt.
# 用 $EDITOR 打开 secrets\common.env。SOPS 自动解密 → 编辑 → 加密。
# Add a new key=value, save, commit, push.
# 加新 key=value，保存，提交，推送。
git add secrets\common.env
git commit -m "rotate OpenAI key / 轮转 OpenAI key"
git push
```

### Decrypt to .env (for tools that don't understand SOPS)
### 解密到 .env（给不认 SOPS 的工具用）

```powershell
task secrets:export
# Writes .env (gitignored). Safe to delete with task clean.
# 写出 .env（已 gitignore）。task clean 可清理。
```

### Run the local stack / 跑本地栈

```powershell
task dev
# Decrypts .env, starts postgres + redis + app.
# 解密 .env，启动 postgres + redis + app。
# Visit http://localhost:3000/health
# 打开 http://localhost:3000/health
```

### Stop the local stack / 停掉本地栈

```powershell
# From the directory task dev is running in: Ctrl-C
# 在跑 task dev 的目录按 Ctrl-C
# Or from another terminal / 或在另一个终端：
docker compose down
```

---

## 3. Backup & restore / 3. 备份与恢复

### Back up age private keys / 备份 age 私钥

```powershell
task backup:keys
# Or with a custom destination / 或指定目标：
pwsh -File scripts/backup-keys.ps1 -Destination E:\keys-backup
```

This copies both `key-a.txt` and `key-b-backup.txt` to the destination
and writes a `README.txt` index with the public keys.
这会把 `key-a.txt` 和 `key-b-backup.txt` 都拷到目标目录，并生成一个
`README.txt` 索引（带公钥）。

### Copy to a USB drive (recommended) / 拷到 U 盘（推荐）

1. Plug in the USB drive (e.g. `E:`). / 插上 U 盘（如 `E:`）。
2. `task backup:keys -Destination E:\keys-backup`
3. Verify the files are on the USB drive. / 检查文件在 U 盘上。
4. Eject the USB drive. / 弹出 U 盘。
5. Store the USB drive somewhere physically safe (safe, deposit box,
   with a trusted family member). / 把 U 盘放在物理安全的地方
   （保险柜、银行保险箱、信任的家人处）。

### Restore from USB on a new machine / 在新机器上从 U 盘恢复

1. Plug in the USB drive. / 插上 U 盘。
2. Copy `key-a.txt` and `key-b-backup.txt` to `~/.config/sops/age/`.
   / 把 `key-a.txt` 和 `key-b-backup.txt` 拷到 `~/.config/sops/age/`。
3. Clone the repo. / 克隆仓库。
4. `sops --decrypt secrets\common.env` should work immediately.
   / 应该能立即解密。

### Disconnected USB = no recovery / 没 U 盘 = 不可恢复

If you lose BOTH your development machine AND the USB drive with the
backup key, **all encrypted secrets are unrecoverable**. There is no
backdoor. The system is designed this way on purpose — the trade-off
is security for recoverability. Keep the USB in a separate physical
location.
如果开发机和 U 盘上的备份钥匙**都**丢了，**所有加密密钥都不可恢复**。
没有后门——这是有意的设计：安全换可恢复性。U 盘必须放在不同的物理位置。

---

## 4. Rotate age keys / 4. 轮转 age 钥匙

Every 6-12 months, or immediately if you suspect a key was leaked.
每 6-12 个月一次，或怀疑泄露时立即。

```powershell
task secrets:rotate
```

What it does / 做的事：
1. Generates a new `key-a.txt` (replaces old). / 生成新 key-a.txt（替换旧）。
2. Archives the old key to `~/.config/sops/age/archive-<timestamp>/`.
   / 把旧钥匙归档到 `~/.config/sops/age/archive-<timestamp>/`。
3. Replaces the old public key in `.sops.yaml` with the new one.
   / 用新公钥替换 `.sops.yaml` 里的旧公钥。
4. Re-encrypts every `secrets/*.env` file with the new key.
   / 用新钥匙重加密所有 `secrets/*.env`。
5. Commits the change (you do this). / 提交变更（你来）。

**Manual steps after rotation / 轮转后手动步骤：**

```powershell
git add -A
git commit -m "rotate age key / 轮转 age 钥匙"
git push
# Re-copy the new key-a.txt to your USB drive.
# 把新的 key-a.txt 重新拷到 U 盘。
```

**Important / 重要**: the OLD key file is still in `archive-<timestamp>/`.
Keep it until you have verified that:
旧钥匙还在 `archive-<timestamp>/`。在确认下面这些之前别删：

- The new encrypted files decrypt with the new key on a second machine.
  / 在第二台机器上用新钥匙能解开新加密文件。
- All services that consume those secrets (CI, local dev, production)
  have picked up the new key.
  / 所有消费这些密钥的服务（CI、本地、生产）都用了新钥匙。

Then delete the archive. / 然后删归档。

---

## 5. Secret Broker operations / 5. Secret Broker 运维

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
ssh 52trz
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
ssh 52trz
TOKEN=$(journalctl -u secret-broker | grep "reload token" | tail -1 | grep -oE '[0-9a-f-]{36}')
curl -sk -X POST -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8443/api/v1/admin/reload
# Returns the new audit log + token; broker keeps running.
# 返回新的 audit log + token；broker 继续跑。
```

Or use the out-of-band scripts to also re-encrypt broker.yaml via SOPS:
或用 out-of-band 脚本调 SOPS 重加密 broker.yaml：

```bash
ssh 52trz
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
管理 UI 有"💻 设备管理"tab 可以签发/轮换/撤销客户端证书。**但生产 ECS
的 PKI 目录默认只读**（systemd 加固），dashboard 签发会返 503 + 黄色
banner 提示走脚本。生产用脚本签发：

```bash
ssh 52trz
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
  at `https://broker.52trz.com` (production). A pre-cleanup hook deletes
  any secret whose name starts with the test prefix; it does **not**
  delete hard-coded production keys like `GITHUB_PAT`. Adding a new
  test? `grep -l 'broker.52trz.com' broker-test/test-*.js` first to
  verify no URLs leak to prod.
  所有 broker-test 测试只打 `https://127.0.0.1:18443` —— **绝对不**
  打 `https://broker.52trz.com`（生产）。pre-cleanup 钩子只删自己命名前
  缀的测试残留，**不删** `GITHUB_PAT` 这类硬编码生产密钥。写新测试
  前先 `grep -l 'broker.52trz.com' broker-test/test-*.js` 防止 URL 泄到生产。
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
curl -sk -b /tmp/cookies.txt 'https://broker.52trz.com/api/v1/admin/audit?limit=20'
# Filter by client / service / action / status / time range / 按客户端/服务/动作/状态/时间过滤
curl -sk -b /tmp/cookies.txt 'https://broker.52trz.com/api/v1/admin/audit?client=ci-runner&action=proxy&since=2026-08-15T00:00:00Z'
# Real-time SSE stream (30 min auto-disconnect, 25s heartbeat) / 实时 SSE 流
curl -sk -b /tmp/cookies.txt -H 'Accept: text/event-stream' \
  https://broker.52trz.com/api/v1/admin/audit/stream
# Export / 导出
curl -sk -b /tmp/cookies.txt 'https://broker.52trz.com/api/v1/admin/audit/export.csv?limit=1000' -o audit.csv
curl -sk -b /tmp/cookies.txt 'https://broker.52trz.com/api/v1/admin/audit/export.json?limit=1000' -o audit.json
```

Or use the dashboard `📋 审计 / Audit` tab (filters + live stream +
export buttons + anomaly highlighting).
或用 dashboard `📋 审计 / Audit` tab（过滤 + 实时流 + 导出按钮 +
异常高亮）。

### 5.7 Phase 1 feature matrix / 5.7 Phase 1 功能矩阵

| Tab / 标签 | Path / 路径 | What it does / 用途 |
|---|---|---|
| `⚡ 动作 / Actions` | `app.js` | Browse services → call upstream via broker / 浏览服务 → 走 broker 调上游 |
| `🔑 可见密钥 / Secrets` | `admin/secrets.js` | Read-only view of secrets the current client can see / 当前客户端可见密钥只读视图 |
| `🗝️ 密钥管理 / Manage` | `admin/secrets.js` | CRUD structured secrets (multi-field), bulk delete, file upload, eye toggle / 结构化密钥 CRUD + 批量删除 + 文件上传 + 眼睛 |
| `🔌 服务管理 / Services` | `admin/services.js` | CRUD services from 6 templates, test connection, permissions matrix / 6 模板服务 CRUD + 连通测试 + 权限矩阵 |
| `💻 设备管理 / Devices` | `admin/clients.js` | CRUD clients, enroll/rotate/revoke (UI; 503 on prod due to PKI read-only) / 客户端 CRUD + 签发/轮换/撤销（生产 UI 返 503） |
| `📋 审计 / Audit` | `admin/audit.js` | Filter, SSE live stream, JSON/CSV export, anomaly highlight / 过滤 + 实时流 + 导出 + 异常高亮 |

Test count (local broker-test, 3-round stable) / 测试数（本地 broker-test，3 轮稳定）:
test-thorough.js 40 + test-services-crud.js 17 + test-clients-crud.js 16 +
test-audit.js 11 = **84/84 × 3 = 252/252 stable**.

---

## 6. Production deployment / 6. 生产部署

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

Public entry: `https://broker.52trz.com` → Cloudflare edge → tunnel →
ECS `127.0.0.1:8443`. Secrets never leave the broker; TLS terminates
at the CF edge, so browsers see a trusted cert without installing the
self-signed CA.
公网入口：`https://broker.52trz.com` → Cloudflare 边缘 → 隧道 → ECS
`127.0.0.1:8443`。明文密钥永不离开发送端；TLS 在 CF 边缘终结，浏览器看到的是
受信证书，不需要安装自签 CA。

Key files on the ECS / ECS 上关键文件：

| Path / 路径 | Purpose / 用途 |
|---|---|
| `/etc/cloudflared/config.yml` | tunnel ingress: `broker.52trz.com -> https://127.0.0.1:8443`（`noTLSVerify: true`，自签 origin） |
| `/etc/systemd/system/cloudflared-secret-broker.service` | systemd unit, auto-start on boot |
| `/root/.cloudflared/e26e5c58-….json` | tunnel credentials (keep secret) |
| `/root/.cloudflared/cert.pem` | zone-level origin cert (from `cloudflared tunnel login`) |

Day-to-day ops / 日常操作：

```bash
ssh 52trz
systemctl status cloudflared-secret-broker     # status
journalctl -u cloudflared-secret-broker -f     # follow logs
systemctl restart cloudflared-secret-broker    # restart
```

Add another hostname / 增加新的域名入口：
`cloudflared tunnel route dns secret-broker other.52trz.com`，再往
`/etc/cloudflared/config.yml` 的 `ingress` 加一条，然后
`systemctl restart cloudflared-secret-broker`。

Local-machine note (China network) / 本机注意（国内网络）：
Some Cloudflare anycast IP ranges (`104.21.x` / `172.67.x`) are
interfered with on this machine — requests got hijacked to a wrong
certificate. Fix: pin a working IP in `C:\Windows\System32\drivers\etc\hosts`:
`104.16.132.229 broker.52trz.com`. Re-verify the IP with
`curl -sk --resolve broker.52trz.com:443:<ip> https://broker.52trz.com/health`
before relying on it (CF IPs can change).
本机访问 broker.52trz.com 时，部分 Cloudflare anycast 段（`104.21.x`/`172.67.x`）
会被中间层劫持（返回错误证书）。已在 hosts 固定可用 IP：
`104.16.132.229 broker.52trz.com`。换 IP 前先按上面命令验证。

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

## 7. Incident response / 7. 应急响应

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

## 8. Monitoring / 8. 监控

### Start Uptime Kuma / 启动 Uptime Kuma

```powershell
docker compose -f monitoring/uptime-kuma.yml up -d
# Open http://localhost:3001 / 打开 http://localhost:3001
```

Add monitors for: / 添加监控：
- `https://<your-domain>/health` (HTTP probe / HTTP 拨测)
- `<db-host>:5432` (TCP probe / TCP 拨测)
- `<cache-host>:6379` (TCP probe / TCP 拨测)
- `<your-domain>` (TLS cert expiry / TLS 证书过期)

Configure a notification channel: WeChat, DingTalk, Telegram, Slack,
or email. / 配告警渠道：微信/钉钉/Telegram/Slack/邮件。

### Start Prometheus + Grafana (optional) / 可选启动

```powershell
docker compose -f monitoring/uptime-kuma.yml --profile metrics up -d
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000 (admin / change-me-on-first-login)
```

---

## 9. Disaster recovery checklist / 9. 灾难恢复清单

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

## 10. Reference / 10. 参考

- SOPS docs / 文档: https://github.com/getsops/sops
- age docs / 文档: https://age-encryption.org
- Taskfile / 任务: https://taskfile.dev
- Terraform: https://developer.hashicorp.com/terraform
- Aliyun KMS: https://www.alibabacloud.com/help/en/kms
- Tencent KMS: https://www.tencentcloud.com/document/product/573
