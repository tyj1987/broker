# Secret Broker 架构

> V4.2 当前架构总览。设计目标与已取得的证据是两回事；生产验收状态见
> `docs/PRODUCTION-ACCEPTANCE.md`，运维步骤见 `RUNBOOK.md`。

English: [ARCHITECTURE.md](ARCHITECTURE.md)

## 信任边界

```text
客户端 / SDK / 工作负载
        │  mTLS、短期会话或受限工作负载身份
        ▼
nginx 可信边缘代理
        │  清除外来身份头，以独立代理身份连接回环端口
        ▼
Node 过渡层 ── 结构、身份与策略预检 ── Unix socket ── Go 策略核心
        │
        ├─ /api/v2 类型化操作、审批、设备与验证码任务
        ├─ 兼容档 /api/v1；严格档拒绝明文解析、任意代理和自由 SSH
        ├─ 追加式审计与统一脱敏
        └─ 固定目标、方法、路径、Header 和响应大小的服务商适配器
```

生产环境中 Go 决策核心不可用时必须拒绝操作。Node 最终只保留界面、协议兼容
和迁移职责，不能提供绕过 Go 策略的入口。

## `/api/v2` 操作模型

客户端只提交 `provider`、`operation_id`、`account_ref`、`environment` 和
Schema 允许的 `typed_parameters`。权限同时约束主体、角色、安全档、身份方式、
服务商、账户、环境、资源、API Key 子权限、审批与有效期。

审批请求与完整操作参数摘要绑定，申请人与审批人分离。审批必须由带 WebAuthn
复验的短时会话完成，并且只能消费一次。创建审批请求本身也必须先经过同一套
Node 与 Go 策略检查。

验证码属于既有操作，不属于 Broker 登录因素。任务绑定操作、账户、设备、SIM、
服务商、挑战、接收方和过期时间；没有匹配任务的短信不会上传。AI 没有“读取最
新验证码”接口。

## 身份与认证

- 严格档：实体 FIDO2/WebAuthn、mTLS 或绑定受众和工作负载的短期身份。
- 受控档：允许受控 Passkey。
- 兼容档：密码、TOTP、Bearer 与 v1 功能只在隔离入口按显式策略开放。
- SMS 不能替代实体密钥，也不能自动批准付款、恢复或安全设置修改。

浏览器会话为 10 分钟绝对过期，可即时撤销，不在响应体返回 Session。Cookie 使用
`Secure`、`HttpOnly` 和 `SameSite=Strict`。

## 凭据与出站边界

优先使用 OIDC、RAM Role、STS 等短期身份。确需静态凭据时，由 Broker 在受限适配
器内部使用，调用方不能覆盖 `Authorization`、Cookie、Host、签名或转发身份头。
任意 URL、绝对 URL、重定向逃逸、IP literal、私网、回环和 metadata 地址均被拒绝。

仓库不包含生产配置、私钥、日志、备份、设备数据或 Terraform state。当前本地存储
仍是过渡实现；KMS 信封加密、不可篡改远端审计和适配器进程隔离未取得生产证据。

## 客户端

- Windows/Linux：Tauri 2，负责配对、类型化操作与后续审批/审计界面。
- Android：Kotlin/Compose、Keystore、双卡与 SMS 能力探测；真机权限结论待验收。
- iOS：SwiftUI 与 Secure Enclave P-256 初始实现；编译、签名和真机验收未完成。
- 浏览器：Chrome/Edge MV3 与 Native Messaging，仅用于本人参与的一次性填码。
- CLI/SDK：Go CLI 及 Go、Python、VS Code 客户端，不默认导出凭据。

## 部署面

- `Dockerfile`、Compose：Node 与 Go 核心分离、非 root、只读根文件系统。
- `deploy/helm/broker/`：Go 核心通过本地 socket sidecar 提供决策。
- `infra/aliyun/broker/`：阿里云主站基础设施基线。
- `infra/tencent/`：腾讯云灾备基础设施基线。
- `deploy/systemd/` 与 `deploy/nginx/`：版本化发布和可信代理配置。

Terraform 文件目前只通过本地格式和离线验证，不等于已经 plan/apply。生产发布仍
受 `docs/PRODUCTION-ACCEPTANCE.md` 中的 P0/P1、凭据轮换、契约测试、真机测试和灾
备演练门禁约束。

## 仓库布局

```text
broker/               Node 过渡服务和管理界面
core/                 Go 策略核心与 CLI
clients/              desktop、android、ios、browser
sdk/                  Go、Python、VS Code 等客户端
contracts/            OpenAPI 与生成物
providers/            版本化服务商 Manifest
deploy/               容器、Helm、nginx、systemd 与回滚工具
infra/                阿里云主站与腾讯云灾备 Terraform
docs/                 架构、安全、使用和验收文档
```

## 不可破坏的约束

1. AI 不获得长期明文凭据。
2. 所有入口使用同一权限计算，身份来源不能改变权限结果。
3. 严格档禁止明文 resolve、任意 URL 代理和自由命令执行。
4. 敏感状态变更必须先写入强制审计意图；审计不可用时拒绝变更。
5. “代码存在”“自动测试通过”“真机通过”“生产验证通过”分别记录，不能互相替代。
