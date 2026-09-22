# Secret Broker v4.9.0 快速上手

> 目标：启动一个本地 Broker，完成 mTLS 健康检查，并让客户端通过 Broker 调用外部服务而不接触明文凭据。

## 1. 前置条件

必需：

- Windows 10/11、Linux 或 macOS
- Node.js **22+**（推荐 Node.js 24）
- Python 3.9+
- Git
- SOPS、age、OpenSSL

生产发布还需要 Docker/BuildKit。不要使用 Node.js 20 作为当前构建基线。

```powershell
node --version
python --version
git --version
sops --version
age --version
openssl version
```

## 2. 克隆并初始化

```powershell
git clone https://github.com/tyj1987/broker.git
cd broker

# 交互式引导；非交互环境可加 -Auto
pwsh -File .\bootstrap.ps1

# 使用锁文件进行可复现安装
npm --prefix .\broker ci
```

严禁把 age 私钥、客户端私钥、解密后的 `.env`、`broker.yaml` 或真实 API Key 提交到 Git。

## 3. 初始化本地 PKI

```powershell
pwsh -File .\scripts\broker\init-ca.ps1
pwsh -File .\scripts\broker\issue-server-cert.ps1 `
  -Domain localhost `
  -AltNames "localhost,127.0.0.1"

# 初始管理员设备证书；后续客户端建议从 Dashboard 一次性签发
pwsh -File .\scripts\broker\issue-client-cert.ps1 `
  -CN client.local-admin `
  -Role admin
```

CA 私钥只能留在受控 Broker 主机。不要通过聊天、邮件或普通文件共享发送客户端私钥。

## 4. 配置 SOPS 加密数据

使用引导生成的 age key，并确保：

```powershell
$env:SOPS_AGE_KEY_FILE = "$HOME\.config\sops\age\keys.txt"
```

编辑运行时配置后立即加密：

```powershell
sops .\secrets\broker.yaml
sops .\secrets\common.env
```

不要先把真实凭据写进受版本控制的脚本。阿里云 AccessKey 轮转使用：

```bash
sudo bash scripts/broker/inject-aliyun-ak.sh
```

脚本会隐藏输入、使用 0600 临时文件、原子替换密文，并且不会打印解密后的凭据值。

## 5. 启动 Broker

直接运行：

```powershell
npm --prefix .\broker start
```

或在已经配置好运行时挂载的 Docker 环境中：

```powershell
docker compose up -d broker
```

生产镜像使用仓库根目录的 `Dockerfile`，不要再使用已经移除的 `broker/Dockerfile`。

## 6. 验证 TLS 健康状态

本地自建 CA 必须显式传入 CA，禁止用 `-k/--insecure` 掩盖证书问题：

```powershell
curl.exe --fail --show-error `
  --cacert .\pki\ca\ca.crt `
  https://localhost:8443/health
```

预期：

```json
{"status":"ok"}
```

验证认证接口：

```powershell
curl.exe --fail --show-error `
  --cacert .\pki\ca\ca.crt `
  --cert .\pki\clients\client.local-admin.crt `
  --key .\pki\clients\client.local-admin.key `
  https://localhost:8443/api/v1/identity
```

## 7. 一次性签发客户端证书

登录 Dashboard 后，从“客户端管理”创建客户端并执行签发：

1. 输入 TOTP、恢复码或管理员密码完成二次验证；
2. 下载一次性 ZIP，或立即保存返回的 `cert_pem/key_pem`；
3. 关闭结果窗口后，页面会清除私钥内容；
4. 安全默认下，Broker 会删除服务器上的客户端私钥文件；
5. 丢失一次性私钥时必须重新签发或轮换，不能重复下载。

仅迁移旧系统时才允许显式设置：

```text
BROKER_RETAIN_CLIENT_PRIVATE_KEYS=1
```

迁移完成后应立即关闭该兼容选项。

## 8. 配置客户端 CLI

将一次性 ZIP 解压到用户私有目录，例如 `$HOME/.broker/`，并创建配置：

```json
{
  "endpoint": "https://localhost:8443",
  "client_cert": "C:/Users/User/.broker/client.crt",
  "client_key": "C:/Users/User/.broker/client.key",
  "ca_cert": "C:/Users/User/.broker/ca.crt"
}
```

私钥文件权限应仅允许当前用户读取。

健康检查与代理调用：

```powershell
node .\cli\secret-broker.js health
node .\cli\secret-broker.js proxy github GET /user
```

AI/Agent 只接收上游响应，不应接收 GitHub PAT、AccessKey Secret 或客户端私钥。

## 9. 开发和提交前检查

```powershell
npm --prefix .\broker run quality:gate
npm --prefix .\broker audit --omit=dev --audit-level=high
git diff --check
```

完整发布验收请执行 [VERIFY.md](../VERIFY.md)。真实发布还必须在有 Docker 的环境构建并检查 `production` 镜像。

## 10. 生产健康检查

生产站点使用公开受信任证书时：

```bash
curl --fail --show-error --silent https://broker.52trz.com/health
```

不要在生产验收命令中添加 `-k`。如果命令因证书错误失败，应修复证书链、SAN、系统时间或反向代理配置，而不是跳过验证。
