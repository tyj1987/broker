# 为 Secret Broker 做出贡献

感谢你有兴趣让 Secret Broker 变得更好!本文档介绍如何提交 issue、提交代码以及审查变更。
>
> English version: [CONTRIBUTING.md](CONTRIBUTING.md)

## 行为准则

本项目遵循 [Contributor Covenant](https://www.contributor-covenant.org/)。
参与即表示你同意遵守其条款。

## 提交 issue

### Bug 报告

使用 **Bug Report** issue 模板。包括:

- broker 版本(从 `X-Broker-Version` 响应头获取)
- Node.js / Python / Go 版本(如果使用 SDK)
- 最小复现步骤
- 期望行为 vs 实际行为
- 相关审计日志摘录(已由 broker 自动脱敏,但请再次确认)

### 安全问题

**请勿在公开 GitHub issue 中报告安全漏洞。**

请使用 [GitHub 私密漏洞报告](https://github.com/tyj1987/broker/security/advisories/new)，
并遵循 [`SECURITY.zh-CN.md`](SECURITY.zh-CN.md)。请勿提交真实凭据。

### 功能请求

先开一个 GitHub Discussion(不是 issue)。如果维护者同意该功能在范围内,
再用 **Feature Request** 模板转为 issue。

## 提交代码

1. Fork 仓库并从 `master` 创建功能分支。
2. 做修改。
3. 按 [`VERIFY.md`](VERIFY.md) 运行各模块检查。除非数字来自当前 CI，
   否则不要声称固定测试数量。
4. 在 `CHANGELOG.md` 的下一个未发布版本下更新。
5. 用 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md) 提交 PR。
   确保所有清单项都已勾选。

## 代码风格

- **JavaScript / TypeScript**:2 空格缩进,文件名 `kebab-case`,函数
  `camelCase`,ESM(`"type": "module"`)。
- **Python**:PEP 8,4 空格缩进,`snake_case`。公开 API 必须有类型提示。
- **Go**:`gofmt` + `go vet` 干净。标准 `golangci-lint` 规则。
- **YAML / JSON**:2 空格缩进。无尾随空白。

## 架构原则

这些不可协商:

1. **零凭据泄漏**:每个接触密钥的代码路径在记录日志、报告错误或返回
   给调用者之前,必须通过 `broker/lib/redact.js`(或 SDK 的等价物)处理。
   见 [redact 引擎测试](broker-test/test-redact.js) 当前支持的 12 种模式。
2. **仅 mTLS**:无匿名端点。唯一例外是 `GET /health`,它只返回
   `{ "status": "ok" }`。不要在公网 health 响应中放 `version`、`sops_loaded`、
   服务名或 `uptime_seconds`。
3. **SDK 不增加新硬依赖**:Python 和 Go SDK 必须保持只用 stdlib。Node
   SDK 可以加 `ws`(已经有了)。新依赖需要维护者批准。
4. **向后兼容**:v3.8 客户端必须继续工作。破坏性变更会提升
   `broker/version.js` 并在 `CHANGELOG.md` 添加 `Breaking` 部分。

## 测试

- 单元测试与源代码放在一起(`broker/lib/`、`sdk/python/secret_broker/`、
  `sdk/go/broker/`)。
- 集成测试在 `broker-test/`,使用 stdlib 模拟。
- 性能敏感路径有基准测试(见 `bench/` 如果存在;回归 > 10% 的 PR
  需要说明)。
- 所有 PR 在合并前必须通过 `npm run test:verify-all`。

## 发布流程

1. 维护者切出发布分支 `release/vX.Y.Z`。
2. CI 执行仓库中声明的 Node 24、Go、Python、Android、浏览器、Windows
   桌面、Terraform 与安全检查任务。
3. 打 tag `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`。
4. GitHub Actions 自动构建 Docker 镜像(如果配置了)并发布到
   ghcr.io。
5. 发布说明从 CHANGELOG.md 自动生成。

## 审查 PRs

维护者会在 7 天内审查。重点关注:

- **安全影响**:改动是否触及任何认证路径、密钥值路径或新的外部输入?
- **向后兼容**:v3.8 客户端还能工作吗?
- **测试覆盖率**:新逻辑有单元测试吗?边界情况(空、超大、畸形)覆盖了吗?
- **文档**:`CHANGELOG.md` 更新了吗?新的环境变量或配置旋钮在
  `secrets/broker.yaml.example` 文档化了吗?
- **风格**:diff 符合上面的约定吗?

## 社区

- GitHub Discussions:设计问题、RFC
- Discord `#broker`:实时聊天
- Office hours:预约制(在 Discord 上 DM 维护者)
- 邮件:broker@local (非安全私密事务)

## 许可证

提交贡献即表示你同意贡献按 [MIT 许可证](LICENSE) 授权。
