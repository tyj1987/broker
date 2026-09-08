# 本地验证快速上手

本指南只建立不含真实凭据的本地验证环境。不要关闭 TLS 校验，不要把密钥、证书私钥或恢复码提交到仓库。

## 前置条件

- Node.js 24.20.x LTS
- SOPS 与 age
- Docker（可选）

## 安装与测试

```powershell
git clone https://github.com/tyj1987/broker.git
cd broker\broker
npm ci --ignore-scripts --no-audit --no-fund
npm run lint
npm run test:verify
npm run openapi:generate
git diff --exit-code -- ..\contracts\openapi.yaml
```

这些命令只验证源码。它们不会创建生产凭据，也不表示生产验收通过。

## 本地 TLS 材料

仓库不再包含会直接生成长期 CA 私钥的一键脚本。运行服务前，应通过组织 PKI 或
隔离的本地测试 CA 签发仅供测试的服务端证书、专用 nginx 工作负载证书和客户端
证书，并把私密材料保存在仓库之外。当前文档不把“源码测试通过”包装成可直接运行
的安全部署。

证书校验失败时停止并修复证书、主机名、用途或 CA；禁止使用 `-k`、`--insecure`
或关闭上游验证绕过。

## 类型化操作

严格档客户端调用 `/api/v2/operations`，只提交 `provider`、`operation_id`、`account_ref`、`environment` 和契约允许的 `typed_parameters`。服务端策略必须显式允许角色、安全档、身份方式、账户、环境、资源和所需审批。

旧 `/api/v1/proxy`、明文 resolve 和自由 SSH 命令仅用于隔离的兼容环境，不属于严格档。

## 下一步

- [安全策略](https://github.com/tyj1987/broker/blob/master/SECURITY.zh-CN.md)
- [威胁模型](THREAT-MODEL.md)
- [生产部署检查](PRODUCTION-ACCEPTANCE.md)
