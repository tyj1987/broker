# 52TRZ AI Control Plane

## 1. 目标

将 Secret Broker 升级为 52TRZ AI/Agent 的统一安全控制面，承接 ChatGPT Work、Codex、业务 Agent 与基础设施之间的受控工具调用。

第一阶段优先支撑 52TRZ 融资租赁顾问业务闭环：

1. 项目录入
2. 文档解析
3. 智能预审
4. 融资方案测算
5. 资金方匹配
6. 顾问报告生成

Broker 不承载业务数据本身，只负责身份、授权、审批、短期凭据、工具代理、审计和安全边界。

## 2. 安全原则

- AI/Agent 默认不得读取长期真实 Secret。
- 高危操作默认拒绝，必须显式授权。
- 所有工具调用必须绑定调用主体、用途、目标资源和审计记录。
- 生产环境写操作必须支持人工审批。
- 使用最小权限、短期凭据、单用途 token。
- 客户资料与融资项目数据不得进入 Broker secrets 存储。
- Broker 只保存连接业务系统所需的受保护凭据与策略元数据。

## 3. 目标架构

```text
ChatGPT / Work / Codex / 52TRZ Agents
                |
                v
      broker.52trz.com
  +-------------------------+
  | Identity / mTLS / OIDC  |
  | Policy / RBAC / ABAC    |
  | Approval                |
  | Tool Registry           |
  | Proxy / STS             |
  | Audit / Redaction       |
  +-------------------------+
       |       |       |
       v       v       v
    GitHub  Cloudflare  VPS/Docker
       |       |       |
       +--- Google Drive / DB / APIs
```

## 4. Agent 角色

### 4.1 `work-agent`
允许：
- 读取业务资料元数据
- 调用低风险查询工具
- 创建任务
- 请求生成报告
- 请求 staging 部署

禁止：
- 读取原始长期 Secret
- 删除客户资料
- 修改生产 DNS
- 修改 Broker 权限
- 执行生产数据库破坏性操作

### 4.2 `codex-agent`
允许：
- GitHub 仓库读写
- 创建分支/PR
- 触发测试
- 查看 staging 日志
- 部署 staging

生产写操作：必须审批。

### 4.3 `ops-agent`
允许：
- 健康检查
- 日志查询
- 容器状态查询
- 已批准的服务重启

### 4.4 `human-admin`
最终审批者，可管理策略、客户端身份和高风险操作。

## 5. 工具风险等级

### LOW
只读、不可产生外部副作用：
- `github.read`
- `drive.read`
- `db.query_readonly`
- `infra.health`
- `logs.read`

默认策略：满足角色权限即可执行。

### MEDIUM
有可逆写操作：
- `github.create_issue`
- `github.create_pr`
- `staging.deploy`
- `staging.restart_service`
- `crm.update_project`

默认策略：角色授权 + 速率限制 + 完整审计。

### HIGH
生产环境或敏感数据变更：
- `production.deploy`
- `cloudflare.dns.write`
- `db.migration.production`
- `customer.document.delete`
- `broker.policy.write`

默认策略：强制人工审批 + 短期单次授权 + 完整审计。

### CRITICAL
不可逆、高破坏性或根权限：
- `db.drop`
- `production.root_shell`
- `broker.master_key.export`
- `cloudflare.zone.delete`

默认策略：Broker 永久拒绝 Agent 自动执行，只允许人工管理流程。

## 6. Tool Call 统一请求模型

```json
{
  "tool": "staging.deploy",
  "request_id": "uuid",
  "actor": {
    "type": "agent",
    "id": "codex-agent"
  },
  "target": {
    "service": "52trz-api",
    "environment": "staging"
  },
  "reason": "Deploy tested commit abc123",
  "inputs": {
    "commit_sha": "abc123"
  },
  "constraints": {
    "ttl_seconds": 300,
    "single_use": true
  }
}
```

## 7. Broker 返回模型

### 7.1 直接允许

```json
{
  "status": "allowed",
  "execution_id": "uuid",
  "expires_at": "..."
}
```

### 7.2 需要审批

```json
{
  "status": "approval_required",
  "approval_id": "uuid",
  "risk": "high",
  "expires_at": "..."
}
```

### 7.3 拒绝

```json
{
  "status": "denied",
  "reason": "policy_denied"
}
```

## 8. 审批状态机

```text
REQUESTED
   |
   +--> DENIED
   |
   +--> APPROVED
          |
          +--> EXECUTING
                 |
                 +--> SUCCEEDED
                 +--> FAILED
                 +--> EXPIRED
```

每个状态变化必须写入现有防篡改审计链。

## 9. 第一阶段新增 Broker 能力

### P0
- Tool Registry
- Tool Risk Classification
- Agent Identity Mapping
- Policy Evaluation
- Approval Request API
- Approval Decision API
- Single-use Execution Token
- Tool Execution Audit Event

### P1
- GitHub tool adapter
- Cloudflare tool adapter
- VPS/Docker tool adapter
- Google Drive tool adapter
- PostgreSQL read-only tool adapter

### P2
- Webhook/event stream
- Scheduled Agent execution support
- Policy simulation
- Emergency revoke / kill switch

## 10. API 草案

```text
GET  /api/v1/tools
GET  /api/v1/tools/:name
POST /api/v1/tools/:name/invoke

POST /api/v1/approvals
GET  /api/v1/approvals/:id
POST /api/v1/approvals/:id/approve
POST /api/v1/approvals/:id/deny

POST /api/v1/policy/evaluate
POST /api/v1/executions/:id/cancel
GET  /api/v1/executions/:id
```

## 11. 52TRZ 业务系统边界

Broker 与业务系统必须解耦。

业务系统建议独立仓库，例如：

```text
52trz-platform/
  apps/
    web/
    admin/
    api/
  services/
    document-intelligence/
    project-underwriting/
    lease-calculator/
    funder-matching/
    report-generation/
  packages/
    domain/
    db/
    ai/
    broker-client/
```

Broker 仅提供安全工具访问，不承载融资租赁业务逻辑。

## 12. 第一阶段商业闭环

```text
融资需求提交
  -> 上传材料
  -> 文档结构化
  -> 项目预审
  -> 融资结构测算
  -> 资金方匹配
  -> 顾问复核
  -> 生成项目推荐报告
  -> 推进融资
```

优先级原则：先形成可收费、可交付的顾问闭环，再扩展 CRM、自动尽调和全自动运营。

## 13. Definition of Done

Broker 第一阶段完成标准：

- Agent 无需接触真实长期 Secret 即可调用至少 3 类外部工具。
- LOW/MEDIUM/HIGH/CRITICAL 四级策略生效。
- HIGH 操作必须经过审批。
- CRITICAL 操作对 Agent 永久拒绝。
- 每次调用具备 actor、tool、target、decision、result、timestamp 审计链。
- Secret 与敏感字段在日志和错误返回中自动脱敏。
- 单元/集成测试覆盖权限绕过、重放、过期 token、审批绕过、审计篡改。

