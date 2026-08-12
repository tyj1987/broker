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

## 5. Production deployment / 5. 生产部署

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

## 6. Incident response / 6. 应急响应

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

## 7. Monitoring / 7. 监控

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

## 8. Disaster recovery checklist / 8. 灾难恢复清单

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

## 9. Reference / 9. 参考

- SOPS docs / 文档: https://github.com/getsops/sops
- age docs / 文档: https://age-encryption.org
- Taskfile / 任务: https://taskfile.dev
- Terraform: https://developer.hashicorp.com/terraform
- Aliyun KMS: https://www.alibabacloud.com/help/en/kms
- Tencent KMS: https://www.tencentcloud.com/document/product/573
