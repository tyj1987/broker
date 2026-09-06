# Secret Broker — Homebrew 安装指南

在 macOS / Linux 上用 Homebrew 装 Secret Broker CLI 和 server。

---

## 前提

- macOS 12+ / Linux x86_64 / arm64
- Homebrew 4.0+ (`brew --version`)
- Node.js 20+ (formula 自动装 `node@20`)

## 安装

### 1. tap 仓库 (一次性)

> **user action**: `tyj1987/homebrew-broker` tap 仓库需要在 GitHub 上先建好,首次发布由 maintainer 推 formula。
> 本文档假设 tap 已存在。

```bash
brew tap tyj1987/broker https://github.com/tyj1987/homebrew-broker
```

### 2. 装 broker

```bash
brew install tyj1987/broker/broker
# 或: brew install broker  (如果 tap 在 default 列表里)
```

输出示例:

```
==> Installing broker from tyj1987/broker
==> Installing dependencies for tyj1987/broker: node@20
==> Installing tyj1987/broker/broker dependency: node@20
==> Pouring node@20--20.18.1.arm64_sonoma.bottle.tar.gz
==> Pouring broker--4.1.1.arm64_sonoma.bottle.tar.gz
🍺  /opt/homebrew/Cellar/broker/4.1.1: 42 files, 1.2M
==> Caveats
Secret Broker 4.1.1 has been installed.
... (CLI / server 配置提示)
```

### 3. 验证

```bash
which secret-broker
# /opt/homebrew/bin/secret-broker (或 /usr/local/bin/secret-broker)

secret-broker --help
# Secret Broker 客户端 CLI
# Usage:
#   secret-broker health
#   secret-broker identity
#   secret-broker list
#   secret-broker get <secret-name>
#   secret-broker proxy <service> <method> <path> [--body <json>] [--query k=v]...
#   secret-broker exec --env "VAR1,VAR2" -- <command> [args...]
#   secret-broker pki issue-client --cn <name> [--role <r>] [--register]
#   secret-broker pki revoke --fingerprint <sha256>
#   secret-broker pki list
```

---

## CLI 配置

CLI 不需要 broker server 跑着就能用,但需要知道 server 在哪 + 客户端 mTLS 证书。

### ~/.broker/config.json

```json
{
  "endpoint":    "https://broker.example.com:8443",
  "client_cert": "/Users/you/.broker/client.laptop.crt",
  "client_key":  "/Users/you/.broker/client.laptop.key",
  "ca_cert":     "/Users/you/.broker/ca.crt"
}
```

### 第一次: 拿客户端证书

```bash
# 假设 broker admin 已经给你签了 client.laptop.crt/.key
# 放在 ~/.broker/ 即可
mkdir -p ~/.broker
cp /path/to/client.laptop.crt ~/.broker/
cp /path/to/client.laptop.key ~/.broker/
chmod 600 ~/.broker/client.laptop.key
# ca.crt 从 broker 那边拿
curl -k https://broker.example.com:8443/api/v1/ca/pem > ~/.broker/ca.crt
```

### 试一下

```bash
secret-broker health
# {"status":"ok","version":"4.1.1",...}

secret-broker identity
# {"client":"client.laptop","role":"developer","mfa_enrolled":false}

secret-broker list
# {"services":["github","openai"]}
```

---

## Server 配置 (生产用)

Homebrew formula 同时装 `secret-broker-server` 二进制,但 server 需要 PKI + config + secrets。

### 目录布局 (推荐)

```bash
BREW_PREFIX=$(brew --prefix)
SECRET_BROKER_ETC="$BREW_PREFIX/etc/secret-broker"

mkdir -p "$SECRET_BROKER_ETC"/{secrets,pki/ca,pki/server,pki/clients,audit,log}

# 1. CA
openssl genrsa -out "$SECRET_BROKER_ETC/pki/ca/ca.key" 4096
openssl req -x509 -new -nodes -key "$SECRET_BROKER_ETC/pki/ca/ca.key" \
  -sha256 -days 3650 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=YourOrg/CN=secret-broker-ca" \
  -out "$SECRET_BROKER_ETC/pki/ca/ca.crt"

# 2. Server cert (CN=broker.example.com, SAN=broker.example.com + 127.0.0.1)
# ... 用 broker CLI 生成 或参考 broker/RUNBOOK.md

# 3. SOPS age key
age-keygen -o "$SECRET_BROKER_ETC/pki/age.key"
chmod 600 "$SECRET_BROKER_ETC/pki/age.key"

# 4. Config — 复制 broker repo 的 example
cp "$BREW_PREFIX/Cellar/broker/4.1.1/broker.yaml.example" \
   "$SECRET_BROKER_ETC/broker.yaml"
$EDITOR "$SECRET_BROKER_ETC/broker.yaml"   # 填你的 services / clients

# 5. Secrets — 用 sops 加密
$EDITOR "$SECRET_BROKER_ETC/secrets/secrets-detail.json"   # plaintext
SOPS_AGE_KEY_FILE="$SECRET_BROKER_ETC/pki/age.key" \
  sops --encrypt --in-place "$SECRET_BROKER_ETC/secrets/secrets-detail.json"
```

### 启动 (前台 debug)

```bash
export SOPS_AGE_KEY_FILE="$BREW_PREFIX/etc/secret-broker/pki/age.key"
export CONFIG_PATH="$BREW_PREFIX/etc/secret-broker/broker.yaml"
export SECRETS_DETAIL_PATH="$BREW_PREFIX/etc/secret-broker/secrets/secrets-detail.json"
export CA_CERT_PATH="$BREW_PREFIX/etc/secret-broker/pki/ca/ca.crt"
export TLS_CERT="$BREW_PREFIX/etc/secret-broker/pki/server/server.crt"
export TLS_KEY="$BREW_PREFIX/etc/secret-broker/pki/server/server.key"
export TLS_CRL=""  # 没 CRL 就留空
export BROKER_BIND="0.0.0.0"
export BROKER_PORT="8443"

secret-broker-server
# 看到: Secret Broker v4.1.1 listening on https://0.0.0.0:8443
```

### 启动 (后台 + systemd / launchd)

参考 [RUNBOOK.md](../RUNBOOK.md) §5 — `systemd` / `launchd` / `docker compose` 任意一种。

---

## 升级

```bash
brew update
brew upgrade tyj1987/broker/broker
# 自动保留 $(brew --prefix)/etc/secret-broker/ 下的 PKI / config / secrets
```

升级后:
- 如果新版本改了 `broker.yaml` schema,看 release notes
- 重启 server: `systemctl restart secret-broker` (Linux) 或 `brew services restart broker` (macOS)

## 卸载

```bash
brew uninstall tyj1987/broker/broker
brew untap tyj1987/broker

# (可选) 删除 config + data
rm -rf $(brew --prefix)/etc/secret-broker/
```

---

## 已知问题

### M1/M2 Mac (Apple Silicon)

formula 用 `node@20` bottle 跨平台,无需源码编译。首次安装会下载约 30 MB,后续升级增量小。

### Linux ARM64 (Raspberry Pi 4/5)

`node@20` 在 Linux ARM64 也有 bottle。broker server 本身 Node.js,ARM64 上零问题。

### macOS Gatekeeper

Homebrew 装在 `/opt/homebrew` (Apple Silicon) 或 `/usr/local` (Intel),本身在 Gatekeeper 白名单。不需要 `xattr -d com.apple.quarantine`。

---

## 跟其他部署方式对比

| 方式 | 优点 | 缺点 |
|------|------|------|
| **Homebrew (本指南)** | 一行装, 自动升级, 跟 macOS 生态一致 | macOS/Linux 才有 |
| Docker | 跨平台, 隔离干净 | 多一层 container, 性能小损失 |
| Systemd (裸跑) | 性能最好, 跟 OS 集成 | 配置稍多 |
| Helm (Kubernetes) | 适合 k8s 部署 | 需要 k8s 集群 |

推荐:
- **macOS 开发机**: Homebrew
- **Linux 服务器**: Systemd (参考 RUNBOOK.md)
- **云**: Docker / Helm (参考 DEPLOY-52TRZ.md)

---

## 故障排查

### `secret-broker: command not found`

确认 `brew install` 成功:
```bash
brew list | grep broker
ls -la $(brew --prefix)/bin/secret-broker*
```

### `Error: Cannot find module '...'`

CLI 是零硬依赖,但 Node 必须是 20+:
```bash
node --version
brew install node@20
brew link node@20 --force
```

### `Error: ENOENT: no such file or directory, open '~/.broker/config.json'`

第一次跑 CLI 之前先建 config:
```bash
mkdir -p ~/.broker
cat > ~/.broker/config.json <<'EOF'
{
  "endpoint":    "https://broker.example.com:8443",
  "client_cert": "/path/to/client.crt",
  "client_key":  "/path/to/client.key",
  "ca_cert":     "/path/to/ca.crt"
}
EOF
chmod 600 ~/.broker/config.json
```

### `Error: unable to verify the first certificate`

CA cert 路径错 / broker server 用了自签证书但你的 ca.crt 不匹配。从 broker admin 拿正确的 ca.crt:
```bash
secret-broker health --insecure  # 临时跳过 verify
# 或: 重新下载 ca.crt
curl -k https://broker.example.com:8443/api/v1/ca/pem > ~/.broker/ca.crt
```

---

## 反馈

- Bug: https://github.com/tyj1987/broker/issues
- Homebrew formula bug: 也在上面 repo (formula 在 `deploy/homebrew/broker.rb`)
- Slack: 不适用 (项目没用 Slack)
