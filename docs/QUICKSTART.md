# Secret Broker — V4 快速上手 (5 分钟)

> **目标**:5 分钟内跑通"AI 通过 broker 调 GitHub API,AI 永远不接触明文 PAT"。
> **前置**:Windows 10+ / macOS / Linux,Node 20+ 已装

---

## 步骤 1:安装工具(单次,2 分钟)

```powershell
# Windows (PowerShell 7+ 推荐)
scoop install age sops git go-task gitleaks nodejs direnv
# 或 winget:
winget install FiloSottile.age Mozilla.SOPS OpenJS.NodeJS.LTS
```

```bash
# macOS
brew install age sops git go-task gitleaks nodejs direnv

# Ubuntu/Debian
sudo apt install -y age sops git
# nodejs / go-task / gitleaks 见各自官网
```

## 步骤 2:克隆 + 引导(1 分钟)

```powershell
git clone https://github.com/tyj1987/broker.git
cd broker
pwsh -File bootstrap.ps1 -Auto
```

引导会:
- ✅ 检查工具
- ✅ 生成主 age 私钥 A
- ✅ 配置 `.sops.yaml`
- ✅ 创建 `secrets/common.env`(加密)
- ✅ 初始化 git

## 步骤 3:启动 broker(1 分钟)

```powershell
# 初始化 PKI(单次)
.\scripts\broker\init-ca.ps1
.\scripts\broker\issue-server-cert.ps1 -Domain localhost -AltNames "localhost,127.0.0.1"
.\scripts\broker\issue-client-cert.ps1 -CN client.laptop -Role developer

# 启动 broker
docker compose up -d broker

# 检查
curl -k https://localhost:8443/health
# → {"status":"ok","version":"4.0.0","uptime":...}
```

## 步骤 4:配置 GitHub PAT(1 分钟)

```powershell
# 1. 浏览器去 https://github.com/settings/tokens 生成 fine-grained PAT
#    (勾选 repo,90 天)

# 2. 编辑 secrets/common.env,加:
"GITHUB_PAT=github_pat_xxxxxxxxxxxxxxxxxxxx" | Out-File -Append secrets\common.env
sops --encrypt --in-place secrets\common.env

# 3. 编辑 secrets/broker.yaml,加服务:
@"
services:
  github:
    type: bearer
    token_secret: github.pat
    upstream: https://api.github.com
    inject_headers:
      Accept: application/vnd.github+json
      X-GitHub-Api-Version: "2022-11-28"
"@ | Out-File -Append secrets\broker.yaml -Encoding UTF8
sops --encrypt --in-place secrets\broker.yaml

# 4. Reload broker
$token = (Get-Content audit\*.jsonl | Select-Object -Last 1 | ConvertFrom-Json).id  # 实际从 audit log 拿
curl -k -X POST -H "Authorization: Bearer $RELOAD_TOKEN" https://localhost:8443/api/v1/admin/reload
```

## 步骤 5:AI 调用(30 秒)

```powershell
# AI 看不见 PAT,只看到响应
node cli\secret-broker.js proxy github GET /user
# → {"login":"tyj1987","id":12345,...}

# 或 exec 模式(注入子进程)
node cli\secret-broker.js exec --env "GH_TOKEN" -- git push origin main
# → 子进程拿到 GH_TOKEN,结束即丢
```

---

## 验证清单

- [x] broker 跑起来
- [x] health 端点 200
- [x] 客户端 cert 签发
- [x] GitHub PAT 注入到 secret
- [x] AI 调 GitHub API 成功,**没看到 PAT**
- [x] audit log 记录调用

---

## 下一步

- [多因子认证](DESIGN-V4-IDENTITY-MFA.md) — 加 TOTP / WebAuthn
- [服务商模板](DESIGN-V4-PROVIDER-TEMPLATES.md) — 看 40+ 模板
- [API 调用规范](DESIGN-V4-API-CALLING-STANDARDS.md) — 看 8 种入口
- [安全模型](DESIGN-V4-SECURITY-MODEL.md) — 看零信任 + 应急
- [实施路线图](DESIGN-V4-ROADMAP.md) — 看 6 个月计划

---

## 常见问题

**Q: 怎么用 OpenAI 而不是 GitHub?**
A: 同上,改 `secrets/common.env` 加 `OPENAI_API_KEY`,改 `secrets/broker.yaml` 加 `openai` service。详见 [PROVIDER-TEMPLATES.md](./DESIGN-V4-PROVIDER-TEMPLATES.md#openai)

**Q: AI 怎么连 broker?**
A: 用 CLI(`secret-broker`),或 MCP(AI agent 自动),或 SDK(Node/Python/Go),或 REST(任何 HTTP client)。详见 [API-CALLING-STANDARDS.md](./DESIGN-V4-API-CALLING-STANDARDS.md)

**Q: 忘记密码?**
A: 走 `recovery` 流程,或 admin 帮你重置。详见 [IDENTITY-MFA.md](./DESIGN-V4-IDENTITY-MFA.md)

**Q: 证书丢了?**
A: 立即 `scripts\broker\revoke-cert.ps1`,然后签新 cert。详见 [SECURITY-MODEL.md §9 IR-1](./DESIGN-V4-SECURITY-MODEL.md#ir-1-client-cert-丢失)

---

**作者**:Mavis + 脱永军
**最后更新**:2026-09-01
**版本**:V4.0-QUICKSTART
