# my-first-app

> 第一个用全套开发系统模板启动的项目
> 配套方案文档：`C:\home\dev-system\README.md`

## 🎯 这个项目能给你什么

跑完下面的 3 步，你就有了：

- ✅ **永远可复用的密钥管理** —— 任何机器 clone 仓库后能解密
- ✅ **自动化任务编排** —— `task dev` 一键启动、`task deploy` 一键部署
- ✅ **进项目自动加载密钥** —— direnv + SOPS 联动
- ✅ **CI/CD 流水线** —— PR 自动 lint+test，tag 自动部署
- ✅ **密钥泄露防护** —— gitleaks 拦截误提交

---

## 🚀 3 步上手

### 第 1 步：装工具（一次性）

```powershell
# 装 scoop（如果还没装）
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# 一键装齐
scoop install age sops git go-task direnv gitleaks nodejs
```

可选（用到再装）：`scoop install docker terraform`

### 第 2 步：跑引导脚本（生成密钥 + 加密文件）

```powershell
cd C:\home\my-first-app
pwsh -File bootstrap.ps1
```

脚本会自动：
- 检查工具是否装好
- 生成主钥匙 A（日常用）
- 提示生成备份钥匙 B（强烈建议）
- 把公钥填到 `.sops.yaml`
- 加密第一个密钥文件
- 初始化 git 提交

### 第 3 步：进项目 + 启动

```powershell
cd C:\home\my-first-app

# 首次进入提示 direnv allow
direnv allow

# 验证密钥自动加载
$env:DATABASE_URL   # 应该能看到明文值

# 启动开发服务器
task dev
```

打开 http://localhost:3000 看到 "密钥管理已经生效" 就成功了。

---

## 📁 目录结构

```
my-first-app/
├── .sops.yaml                    # SOPS 加密规则（自动填充）
├── .gitignore                    # 严格忽略私钥
├── .envrc                        # direnv 自动加载
├── .pre-commit-config.yaml       # gitleaks + 基础检查
├── Taskfile.yml                  # 任务编排
├── bootstrap.ps1                 # ⭐ 一键引导脚本
├── README.md                     # 你在这里
├── secrets/
│   ├── .gitkeep
│   ├── common.yaml.example       # 密钥模板
│   └── common.yaml               # 🔒 加密后（自动生成）
├── scripts/
│   ├── check-tools.ps1           # 工具检查
│   ├── backup-keys.ps1           # 备份私钥
│   └── rotate-keys.ps1           # 轮转私钥
├── app/
│   ├── package.json
│   └── index.js                  # 示例 Node.js 应用
└── .github/
    └── workflows/
        ├── ci.yml                # Lint + Test + gitleaks
        └── deploy.yml            # 构建 + 推送双云 + 部署
```

---

## 🛠 常用命令

```powershell
# 密钥管理
task secrets:init       # 初始化密钥体系（首次）
task secrets:edit       # 编辑加密文件（自动解密 → 编辑 → 加密）
task secrets:view       # 查看解密后内容
task secrets:export     # 解密为 .env 文件
task secrets:rotate     # 轮转所有 age 钥匙

# 备份
task backup:keys        # 备份私钥到指定目录

# 开发
task dev                # 启动开发环境
task lint               # 代码风格
task test               # 运行测试
task build              # 构建 Docker 镜像
task push               # 推送到阿里云 + 腾讯云
task deploy             # 完整部署

# 工具
task check              # 检查工具是否齐全
```

---

## 🔐 密钥管理"5 个不能忘"

1. **私钥永不入库** —— `.gitignore` 已经配好，别动
2. **多把钥匙兜底** —— 至少主 A + 备份 B，丢了不会变孤儿
3. **加密文件可公开** —— 但私钥泄露了 = 一切白搭
4. **进项目就 direnv allow** —— 否则密钥不会自动加载
5. **每 6 个月轮转一次** —— `task secrets:rotate`

---

## 🆘 应急场景

| 场景 | 怎么办 |
|-----|-------|
| 主钥匙 A 丢了 | 用备份钥匙 B 解密 → 跑 `task secrets:rotate` |
| 备份钥匙 B 也丢了 | 用云 KMS 解密（需先配 `.sops.yaml`） |
| direnv 不生效 | 重启 PowerShell，确认 `$PROFILE` 有 hook |
| 误提交了密钥 | `gitleaks` 会拦截；万一漏了，立刻轮转 |
| CI 跑挂 | 看是不是云 KMS OIDC 没配（看 deploy.yml）|

---

## 📚 下一步学习

- **方案详细文档**：`C:\home\dev-system\01-secret-management.md`（密钥管理 13 节）
- **完整架构**：`C:\home\dev-system\02-full-architecture.md`
- **实施路线**：`C:\home\dev-system\03-implementation-roadmap.md`

跑通这个项目后，按 `03-implementation-roadmap.md` 走 4 个阶段，把整套体系铺开。
