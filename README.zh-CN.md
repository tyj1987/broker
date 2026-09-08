# Secret Broker

面向自动化、开发工具和云工作负载的策略型凭据代理。严格档调用方只提交类型化
操作并接收允许返回的业务结果，不会获得长期凭据。

[![CI](https://github.com/tyj1987/broker/actions/workflows/ci.yml/badge.svg)](https://github.com/tyj1987/broker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**语言：** [English](README.md) · [中文](README.zh-CN.md)

## 安全模型

- `/api/v2` 是类型化操作、绑定审批、设备和短时验证码任务的严格安全边界。
- Node 负责身份、Schema 与策略预检；生产环境还必须取得本地 socket 上 Go 策略
  核心的允许决定。
- 某项服务商操作只有在隔离账户完成真实契约测试并显式标记后，才允许用于生产。
- 浏览器 Session 为 10 分钟绝对过期。审批必须经过 WebAuthn 复验、职责分离，且
  只能消费一次。
- 出站请求固定 scheme、主机、端口、方法、路径、Header 和响应大小；私网、回环、
  metadata 与重定向逃逸均被拒绝。
- 严格身份不能使用 v1 兼容接口的明文密钥解析、任意代理或自由 SSH 命令。
- v2 状态变更必须先写入强制审计意图；审计存储不可用时拒绝变更。

短信只是一项已经授权操作的输入，不是 Broker 登录因素。Android 客户端只上传与
任务匹配的验证码和绑定信息，不上传短信历史或未匹配短信。短信不能批准付款、
账户恢复或安全设置变更。

详细边界见[威胁模型](docs/THREAT-MODEL.md)与[架构说明](ARCHITECTURE.zh-CN.md)。

## 当前成熟度

仓库包含 Node 过渡服务、Go 策略核心、API 契约、服务商 Manifest、SDK、Windows/
Linux 桌面客户端、Android 客户端、iOS 初始客户端和浏览器辅助扩展。代码存在不等
于生产验收通过。

首批六家服务商仍受真实契约测试门禁约束；Android/iOS 仍需真机验收；制品签名、
来源证明及生产环境发布阻断项仍未全部闭环。最新证据见
[生产验收记录](docs/PRODUCTION-ACCEPTANCE.md)。

## 仓库布局

```text
broker/               Node 过渡服务和管理界面
core/                 Go 策略核心
clients/
  desktop/            Tauri Windows/Linux 客户端
  android/            Kotlin/Compose 验证码设备客户端
  ios/                SwiftUI/Secure Enclave 初始客户端
  browser/            Chrome/Edge MV3 辅助扩展及 Native Host 元数据
sdk/                  Go、Python、VS Code 客户端
contracts/            生成的 OpenAPI 契约
providers/            版本化服务商 Manifest
deploy/               容器、Helm、nginx、systemd 与回滚资产
infra/                阿里云主站与腾讯云灾备 Terraform 基线
docs/                 架构、安全、运维和验收文档
```

生产配置、凭据、PKI 私密材料、审计日志、备份、设备数据、Terraform state 与生成
安装包不得进入 Git。

## 源码验证

Broker 开发环境使用 Node 24。必须从锁文件安装并运行安全覆盖率门禁：

```sh
cd broker
npm ci --ignore-scripts --no-audit --no-fund
npm audit --audit-level=high
npm run lint
npm run test:coverage
npm run openapi:generate
git diff --exit-code -- ../contracts/openapi.yaml
```

Go、Python、Rust、Android、Swift、Terraform、Helm 与容器门禁由
[CI](.github/workflows/ci.yml)执行。本机与 CI 证据的区别见 [VERIFY.md](VERIFY.md)。

## 配置与部署

[`secrets/broker.yaml.example`](secrets/broker.yaml.example) 为无凭据、默认拒绝的结构
示例。没有保留真实契约测试证据时，不得把 `contract_verified` 改为 `true`；当前
Terraform 根目录只用于验证，不得直接用于生产 apply。

- 本地源码验证：[快速开始](docs/QUICKSTART.md)
- 部署与回滚：[deploy/README.md](deploy/README.md)
- 运维手册：[RUNBOOK.md](RUNBOOK.md)
- 生产迁移阻断项：[deploy/PRODUCTION-MIGRATION.md](deploy/PRODUCTION-MIGRATION.md)

## 贡献与安全报告

提交变更前请阅读 [CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)。安全问题按
[SECURITY.zh-CN.md](SECURITY.zh-CN.md)私密报告；Issue 中不得包含真实凭据、验证码、
私钥或生产配置。

本项目采用 [MIT License](LICENSE)。
