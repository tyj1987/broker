# Secret Broker v3 规划 / Plan

> 目标：把所有"需要安全保管的凭据"（GitHub / AI 厂商 / 阿里云 / 腾讯云 / SSH / 数据库 / 任意自定义），
> 通过一个 Web 控制台集中管理，让"AI / 脚本 / 任何设备"在**不接触明文**的前提下调用。
> **简单、可靠、安全**——按这个优先级做。

---

## 0. 现状 / What's there today

**已工作的基础设施**（不要重做）：
- ✅ Broker 后端：`broker/server.js`，mTLS + 密码双认证、SOPS+age 静态加密、JSON Lines 审计、proxy/resolve 双模式、限流、登录锁
- ✅ ECS 公网入口：`https://broker.52trz.com` → nginx 443 → broker 8443（TLSv1.3），LE 证书自动续期
- ✅ 客户端证书 PKI：`scripts/broker/init-ca.ps1 / issue-client-cert.ps1 / revoke-cert.ps1`
- ✅ CLI 工具：`cli/secret-broker.js`（proxy / exec / get 三个子命令）
- ✅ 部署脚本：`infra/aliyun`、`infra/tencent` Terraform，`scripts/broker/install-ecs.sh / update-ecs.sh / connect-client.sh`
- ✅ 文档：`RUNBOOK.md`、`README.md`、`docs/04-secret-broker.md`

**Dashboard 现状**（`broker/dashboard/`）：
- 5 个 Tab：动作 / 审计 / 密钥 / 文档
- 可以"调外部 API + 看审计 + 拉明文"——但**全是只读 + 调用**，**不能"加 / 改 / 删"任何东西**
- 任何变更（加密钥、新增服务、签新证书）都得 SSH 到 ECS 改 yaml / 跑脚本

**关键痛点**（用户原话）：
> 我需要在 WEB 端可以**明文填入**这些信息，然后**安全的保存和使用**。
> 功能极其完善，极其可靠，极其易用。
> 不要把简单的东西复杂化，而是既要简单，还要可靠，还要安全。

---

## 1. 核心设计原则 / Principles

按这个优先级，遇冲突时**前面的赢**：

1. **简单 > 强大**：少一个功能 = 少一个 bug。默认开箱即用，能不加就不加。
2. **可靠 > 漂亮**：所有写操作要 SOPS 落盘 + 审计 + 健康检查。UI 丑一点没关系，逻辑不能错。
3. **安全 > 便利**：明文只在用户输入那一刻存在浏览器内存；服务端只存 SOPS 密文；审计 100% 覆盖。
4. **复用 > 重写**：后端已经设计好了（mTLS、SOPS、proxy/resolve、审计、限流），**只补管理 API，不动核心**。
5. **一份代码 > 多套环境**：所有配置、所有 secrets、所有设备信息都用同一份 SOPS 文件，**别分散在 yaml/env/db 里**。

---

## 2. 架构总览 / Target architecture

```
                ┌──────────────────────────────────────────────┐
                │   Web Dashboard (admin)                      │
   用户浏览器 ──▶│  /dashboard                                 │
                │    ├─ 密钥管理 (CRUD + 模板)                  │
                │    ├─ 服务管理 (CRUD + 模板)                  │
                │    ├─ 设备/客户端管理 (CRUD + 证书签发)        │
                │    ├─ 审计 (实时 + 过滤 + 导出)                │
                │    └─ 动作 (调用外部 API，proxy 模式)         │
                └──────────────┬───────────────────────────────┘
                               │  HTTPS / 密码或 mTLS
                               ▼
                ┌──────────────────────────────────────────────┐
                │   nginx 443 (TLSv1.3, LE cert)               │
                │   ─── proxy_pass ───▶ broker 8443 (mTLS)     │
                └──────────────┬───────────────────────────────┘
                               │
                ┌──────────────▼───────────────────────────────┐
                │   broker (Node.js)                           │
                │   - mTLS 认证 (设备证书)                      │
                │   - 密码认证 (Web 登录，限次锁)                │
                │   - session cookie (30min 滑动)              │
                │   - 管理 API: secrets/services/clients CRUD  │
                │   - 业务 API: proxy/resolve/identity         │
                │   - 审计: JSON Lines 落盘 + stream           │
                └──────────────┬───────────────────────────────┘
                               │
                ┌──────────────▼───────────────────────────────┐
                │   /opt/secret-broker/                        │
                │   ├─ secrets/broker.yaml      (SOPS 加密)    │ ◀── 一切配置 + 密钥 + 服务定义
                │   ├─ secrets/common.env       (SOPS 加密)    │ ◀── KV 形式的密钥 (github.pat=xxx)
                │   ├─ pki/ca/, pki/server/, pki/clients/      │ ◀── 证书
                │   ├─ age/key.txt             (broker 解密用)  │
                │   └─ audit/*.jsonl                          │ ◀── 审计日志
                └──────────────────────────────────────────────┘
```

**关键决策**：
- **配置 + 密钥 + 服务定义全部进 broker.yaml**（SOPS 加密），用 sections 区分（`clients:` / `services:` / `secrets:`）。这样一份 yaml 就是一个完整备份。
- **不引入数据库**。SQLite 看着简单，但多一份状态就要多一份备份/迁移/一致性维护。SOPS 文件 + git 已经是最好的"数据库"。
- **不引入 RBAC 框架**。就 admin / user 两级，配合每个 client 的 `allowed_resolve` / `allowed_proxy` 白名单，够用。
- **不引入前端框架**（React/Vue）。Vanilla JS + 一点点 helper 足矣——少 10MB 依赖、少一套构建、少一类兼容问题。

---

## 3. 分阶段实施 / Phased plan

> 顺序按"价值密度"排：先解决"加一个密钥得 SSH 一次"的最大痛点，再做易用性。

### Phase 1 — 管理控制台（**最优先**）

新增 4 个管理 API + 对应 4 个 Dashboard Tab。所有写操作都要求 admin 角色 + 二次确认 + 落审计 + SOPS 重加密。

#### 1.1 密钥管理（Secrets）

**API**：
```
GET    /api/v1/admin/secrets              # 列出所有密钥名（不含值）+ 元数据
POST   /api/v1/admin/secrets              # 新增 {name, value, type, description}
PUT    /api/v1/admin/secrets/:name        # 更新值
DELETE /api/v1/admin/secrets/:name        # 删除
POST   /api/v1/admin/secrets/test/:name  # 用密钥调一次预置的"活性检查"（GitHub /user、Aliyun /ram 等）
```

**UI**：
- 列表：name / type / 上次更新 / 上次访问 / 操作
- 新增：弹出表单 → name (校验唯一) + type 下拉（github_pat / openai_key / aliyun_ak / ssh_key / custom）+ 粘贴 value + 描述
- **模板**：选 type 后自动展开"如何获取这个密钥"的图文步骤 + 一键测试按钮
- 批量导入：粘贴 `.env` 格式（`KEY=value` 一行一个）→ 自动解析 → 预览 → 一次性提交
- 导出：列出所有 name（不导出 value），方便对照填到别处

**存储**：全部进 `secrets/common.env`（SOPS 加密），保持与现有 resolver 兼容。

#### 1.2 服务管理（Services）

**API**：
```
GET    /api/v1/admin/services             # 列出所有服务（不含 secret 引用细节）
POST   /api/v1/admin/services             # 新增
PUT    /api/v1/admin/services/:name       # 更新
DELETE /api/v1/admin/services/:name
POST   /api/v1/admin/services/:name/test # 触发一次测试调用
```

**UI**：
- 模板下拉：GitHub / OpenAI / Aliyun ECS / Aliyun RAM / 通用 HTTPS / SSH 命令代理
- 选模板后，自动填好 upstream / 默认 actions / 默认 headers
- 自定义模式：upstream URL + headers 模板（带 `{{secret.xxx}}` 占位符）+ 一组预置 actions
- 权限矩阵：哪些 client 允许调（多选 / 全部）

**存储**：进 `secrets/broker.yaml` 的 `services:` section。

#### 1.3 设备管理（Clients / Devices）

**API**：
```
GET    /api/v1/admin/clients              # 列出所有 client + 状态
POST   /api/v1/admin/clients              # 新增（只填 name/role/allowed_*），返回 enrollment token
GET    /admin/clients/:name/enrollment    # 查 enrollment token（一次性，签完即失效）
POST   /api/v1/admin/clients/:name/revoke # 吊销（写 CRL + 加拒绝列表）
POST   /api/v1/admin/clients/:name/rotate # 重发证书（保留 client identity，旋转 key）
GET    /api/v1/admin/clients/:name/bundle # 下载 zip（client.crt + client.key + ca.crt + install.sh）
```

**UI**：
- 列表：name / role / 设备类型标签（手填）/ 最后在线时间 / 关联的 cert fingerprint
- 新增：弹窗填 name + role + 允许的 service 白名单 + 允许 resolve 的 secret 白名单 + "设备用途备注"
- 新增成功后显示一次性 enrollment token（带倒计时 5min），用户用 CLI 命令下载：
  ```
  secret-broker enroll --token=xxx
  ```
  → 自动生成 client key + CSR → 提交 broker 签发 → 落盘 + 设置 systemd
- "下载安装包"按钮：直接给 zip（含证书 + `connect-client.sh`），方便丢到没法跑命令的设备（VM 手动部署）
- 吊销：一键，列表立即刷新（broker 端 mTLS 校验读 CRL）

**存储**：进 `secrets/broker.yaml` 的 `clients:` section。

#### 1.4 审计增强

- 实时流：`GET /api/v1/admin/audit/stream` (SSE)，新事件 < 1s 推送到 Dashboard
- 过滤：按 client / service / secret / action / 时间范围
- 导出：JSON / CSV 一键下载
- 异常高亮：连续 5 次 denied / 异地 IP / 深夜访问 自动高亮（仍只记录，不告警推送——v3 不做通知）

---

### Phase 2 — UX 打磨（管理功能跑稳后）

- **首登引导**：第一次登录是空数据时，浮窗提示"加你的第一个密钥 / 服务 / 设备"
- **Dashboard 首页**：健康状态（broker / cert 有效期 / 磁盘 / 30 天事件统计）+ 最近 10 条活动
- **命令片段面板**：每个 service 旁边显示对应的 `secret-broker proxy ...` 命令，可一键复制
- **键盘快捷键**：`/` 聚焦搜索，`g s` 跳 Secrets，`g d` 跳 Devices，`n` 新建当前 Tab 的对象
- **空状态文案**：所有空列表都写"还没有 X，点这里加一个"，而不是冷冰冰的 `(无)`
- **错误信息**：所有 API 错误用中英双语，附带"应该怎么修"的建议链接到 RUNBOOK
- **响应式**：手机也能用（紧急场景下能查密钥 / 吊销设备）

---

### Phase 3 — 进阶（按需，不预先做）

- **密钥轮转**：定时任务（cron）按周期自动 rotate，写新值、保留旧值 24h 过渡期、审计通知
- **临时授权**：给某个 client 临时开一个 secret 的 resolve 权限，2h 后自动失效
- **SSH 代理模式**：broker 同时是 SSH jump host，登录用 mTLS 证书，命令通过 broker 转发到目标机器（适合跳板机场景）
- **Webhook / 通知**：审计事件推到飞书 / 钉钉 / Slack（用现有的 secrets 管理 webhook URL，dogfooding）
- **多 broker 联邦**：两个 broker 之间同步 secrets（异地灾备）

---

## 4. 关键设计决策 / Key decisions

### 4.1 存储：单 yaml + 单 env，不上 DB

**为什么**：SOPS+age 已经把"加密"和"版本控制"两件事做了。SQLite/Mongo 等于再加一个并发控制、备份、迁移、加密的负担。一份 yaml 备份等于整个系统备份。

**写流程**：
1. Web UI 收到变更请求
2. broker 进程修改内存中的 `CONFIG` / `SECRET_CACHE`
3. 同步写回 yaml/env（SOPS re-encrypt）
4. 写一条 audit
5. 返回 200

**读流程**（已存在）：直接读内存中的 `CONFIG`，启动时从 SOPS 解密加载。

### 4.2 模板驱动服务定义

不要让用户手填"GitHub 服务的 upstream 是 `https://api.github.com`，header 模板是 `Authorization: Bearer {{secrets.github.pat}}`"——他们配错就调不通。

**预置模板**（写在 broker 代码里）：
| 模板 | upstream | 默认 actions | 测试调用 |
|---|---|---|---|
| `github` | `https://api.github.com` | `GET /user`、`GET /repos/{owner}/{repo}` | `GET /user` |
| `openai` | `https://api.openai.com/v1` | `GET /models`、`POST /chat/completions` | `GET /models` |
| `aliyun_ecs` | `https://ecs.aliyuncs.com` | `DescribeRegions`、`DescribeInstances` | `DescribeRegions` |
| `aliyun_ram` | `https://ram.aliyuncs.com` | `ListUsers`、`GetUser` | `ListUsers` |
| `tencent_cvm` | `https://cvm.tencentcloudapi.com` | `DescribeRegions`、`DescribeInstances` | `DescribeRegions` |
| `ssh_proxy` | (broker 内置) | `exec <cmd>` | - |
| `custom_https` | 用户填 | - | - |

### 4.3 设备 = client（保留现有概念）

不引入新的"device"实体，client 就是 device。理由：
- 一个 client 证书代表一个身份，可以装在多台机器上（典型的"PC + 笔记本 + VM 各一份"）
- 但 cert fingerprint 一样的话，审计上看不出"是不是同一台机器"——这点 v3 不解决，靠人工备注
- 如果以后真要"每台机器一个指纹"，再加 `client.instance` 概念

### 4.4 enrollment 流程用一次性 token，不用长期 enrollment 服务

**为什么**：长期 enrollment 服务要管状态、要过期清理、要 rate-limit、要审计——多一个攻击面。一次性 token + 5min 过期 + 一次性使用，简单可靠。

**流程**：
1. Web 后台新增 client，生成一个 256-bit 随机 token，5min 过期，存内存
2. 用户在设备上跑：`secret-broker enroll --url=https://broker.52trz.com --token=xxx --name=my-vm`
3. CLI 用 mTLS 匿名连 broker（broker 配 mTLS 但 `requestCert: true, rejectUnauthorized: false`，允许无证书连接）
4. CLI 提交：token + 自己生成的 client key + CSR
5. broker 验证 token + 签发证书 + 返回 zip（crt + ca.crt + install.sh）
6. token 立即作废
7. CLI 落盘 + 提示用户跑 `connect-client.sh` 验证

### 4.5 不做的东西（明确划出去）

| 不做 | 原因 |
|---|---|
| 用户管理（多账号、邀请、注册） | 个人工具，自己用 |
| 多租户隔离 | 同上 |
| RBAC 细粒度（资源/动作级别） | admin/user 两级 + 白名单已经够 |
| 通知系统（邮件/IM/短信） | v3 不接外部系统，等真用到了再加 |
| WebAuthn / TOTP | 密码 + 5 次锁定已经够个人用，攻击面也更小 |
| 主题切换、暗色模式 | 已经有暗色，再做一个亮色是时间黑洞 |
| 国际化（多语言切换） | 中英双语写死在 UI 上够了 |

---

## 5. 文件结构 / File layout

新增 / 修改的文件：

```
broker/
├── server.js                          # 现有：加 12 个新管理 API 端点（不改核心逻辑）
├── dashboard/
│   ├── index.html                     # 现有：加 4 个新 Tab + 改导航
│   ├── app.js                         # 现有：加 4 个 Tab 的 JS（独立 module 风格）
│   ├── style.css                      # 现有：加管理 Tab 用的样式（沿用现有设计 token）
│   └── admin/                         # 新增：管理模块
│       ├── secrets.js                 # 密钥管理 JS
│       ├── services.js                # 服务管理 JS
│       ├── clients.js                 # 设备管理 JS
│       └── audit.js                   # 增强审计
├── service-templates.js               # 新增：服务模板定义（github/openai/aliyun_ecs/...）
└── admin-handlers.js                  # 新增：管理 API handler（拆出来 server.js 太长）

cli/
└── secret-broker.js                   # 现有：加 `enroll` 子命令

scripts/
└── broker/
    └── deploy.sh                      # 新增：一键 deploy（scp + restart，取代手工操作）

docs/
├── PLAN-secret-broker-v3.md           # ← 本文档
├── RUNBOOK-v3.md                      # 新增：v3 运维手册
└── user-guide.md                      # 新增：终端用户怎么用（给非 owner 看）
```

**严格约束**：
- 不引入 npm 依赖（保持 zero-dep 状态）
- 不引入前端框架
- 所有 JS 仍用 vanilla + IIFE module 风格
- 所有 UI 文案中英双语

---

## 6. 验证 / Verification

每个 Phase 结束都做这三件事：

### 6.1 功能验证
- 新增 / 编辑 / 删除一个 secret → broker 重启后值正确加载
- 新增 / 编辑 / 删除一个 service → 客户端拉 `/api/v1/services` 看到新条目 + 能正常调用
- 新增 client → 用 `secret-broker enroll` 跑完 → 新设备能调通 broker
- 吊销 client → 旧证书立即被拒（mTLS 握手失败）
- 审计：新事件 < 1s 出现在 Web 上 + 落盘 jsonl

### 6.2 回归验证
- 现有的 `secret-broker proxy / exec / get` 命令不受影响
- 现有的 mTLS 客户端证书继续能用
- 现有的 `client.dashboard-admin` 密码登录继续能用
- 现有的 nginx + LE cert + acme.sh DNS-01 自动续期不受影响

### 6.3 自动化测试
新增 `tests/e2e/`：
- `secrets-crud.js`：admin 登录 → 加 secret → 重启 broker → 拉值 → 删除
- `service-crud.js`：加 github 服务 → 用 client cert 调 `/user` → 成功
- `client-enroll.js`：生成 token → 模拟设备 enroll → 验证 cert 落盘 → 调一次 API
- `audit-stream.js`：触发 5 个事件 → SSE 流 5 条 + jsonl 落盘 5 条

跑法：`node tests/e2e/<file>.js`（同 `test-login-flow.js` 风格）。

---

## 7. 风险与对策 / Risks

| 风险 | 等级 | 对策 |
|---|---|---|
| SOPS 写回失败 → 配置不一致 | **高** | 写前先写 `.tmp`，atomic rename；失败时回滚内存 + 审计 error |
| 多 admin 同时改同一份 yaml | 中 | broker 进程内串行化（Node 单线程天然 OK）+ 文件锁（flock） |
| 设备 cert 私钥在 Web 端下载时被截获 | **高** | enrollment 流程必须 mTLS + 一次性 token；bundle 下载用 admin 单独接口 + 二次确认 + 30s 过期 |
| 误删 secret / service | 中 | 软删除（标记 `_deleted_at`） + 7 天回收站 + 二次确认弹窗 |
| Dashboard 复杂化后打开慢 | 低 | 每个 Tab 懒加载 JS（`<script type="module">` 动态 import） |
| 浏览器存明文 secret | 中 | 输入后只放内存 state，不写 localStorage；form submit 后立即清空 |
| Web UI 被 CSRF | 低 | 所有 POST 加 CSRF token（从 session cookie 派生）；SameSite=Strict 已有 |

---

## 8. 时间表 / Timeline

| Phase | 内容 | 工作量 | 状态 |
|---|---|---|---|
| **Phase 1.1** | Secrets CRUD UI + API + 模板 | 3 天 | ✅ 完成 |
| **Phase 1.2** | Services CRUD UI + API + 6 个模板 | 4 天 | ✅ 完成 |
| **Phase 1.3** | Clients CRUD + enrollment token + 证书签发 | 3 天 | ✅ 完成 |
| **Phase 1.4** | 审计增强（SSE + 过滤 + 导出） | 2 天 | ✅ 完成 |
| **Phase 2** | UX 打磨（首页/引导/快捷键/响应式） | 3 天 | 部分完成 |
| **Phase 3** | 进阶（按需，估不动） | — | — |

**Phase 1 全部完成**预计 12 个工作日。**Phase 2** 3 天。

---

## 9. 第一步 / Next step

我建议**马上开始 Phase 1.1（Secrets CRUD）**——这是最大的痛点，也是其他 Phase 的基础。

**具体动作**：
1. 确认这个规划 OK（你点头 / 给反馈）
2. 我开始写 `secrets-crud` 部分的 server.js API + dashboard 改 index.html 加 Tab + admin/secrets.js
3. 写完用 playwright 跑 E2E 验证
4. scp 推 ECS + restart + 再跑一次 E2E
5. 给你看效果

**不在这次范围**（明确）：
- 我不会动现有 mTLS / SOPS / 审计 / proxy / resolve 任何核心逻辑
- 我不会引入新依赖
- 我不会做 Phase 3 的任何东西（除非你主动提）

---

**等你的反馈**：
- 这个规划方向对吗？
- Phase 1.1 (Secrets CRUD) 先做？还是你有别的优先级？
- 有没有我漏掉的设备类型 / 密钥类型？
- 模板里 6 个够吗？要不要加（Cloudflare / Stripe / AWS / Supabase / 自定义 SSH ...）？
