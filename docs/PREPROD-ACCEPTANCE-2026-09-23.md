# Broker 候选版本：差异审查与预发布验收记录

> 目录日期沿用 2026-09-23 审查批次。执行器原始日志记录为 2026-09-22 UTC；以证据中的实际开始/结束时间为准。
> 本文补充并更新 `REVIEW-PREPROD-2026-09-23.md` 的执行状态，不覆盖此前失败证据。

## 1. 当前判定

**核心预发布链路已实际执行：104 项核心验收及 87 项证书/回滚扩展验收全部通过。完整本地 quality:gate 退出码为 0。生产发布仍为 NO_GO。**

NO_GO 的原因不能用测试全绿消除：真人 Review 尚未签署；扩展审计完整性检查真实失败；本轮镜像回滚不是上一生产版本的数据兼容性验收；未执行 GitHub Release/Cosign 的真实发布作业。

本次没有提交、推送、发布 tag、更新生产服务或修改生产 DNS/TLS。原工作区分支、HEAD 和暂存区保持不变。预发布部署用于验证，不表示已跨过真人批准的生产发布门禁。

## 2. 工作区与不可变标识

| 项目 | 记录 |
|---|---|
| 授权设备 | ROG / Windows |
| 原工作区 | `E:\broker` |
| 分支 | `codex/security-audit-hardening` |
| Git 基准 HEAD | `cee3e4cbea87b6011d61d618309528bdd96bbd33` |
| SSH 预发布目标 | alias / hostname 均为 `docker` |
| 独立目录 | `/tmp/broker-preprod-r2-20260923` |
| Compose 项目 | `broker-preprod-r2` |
| 网络与资源标签 | internal network；`broker.preprod.run=r2-20260923` |
| 源码清单 SHA-256 | `6d4fd4600a50e92d5726c2381a6d92aef52f28d2a1b36a0c16c02131fbaaa452` |
| 构建输入压缩包 SHA-256 | `09b3328c554e01fd9167152cfcca09afcf1577675476d219dff2059a649b2a32` |
| 实际 Docker image ID | `sha256:8f08c0ba851aa16d70cdb74cb87a649edb98568584c783b4810f32803c668056` |
| Nginx 镜像引用 | `nginx@sha256:ef8676b33d681f272ba429b27658bdd7e640963279714c96bddf1dc76307f7b6` |

Docker image ID 是本地镜像配置标识，不等同于发布到 Registry 后的 manifest digest。候选镜像未推送 Registry，RepoDigests 为空；不得将上表 image ID 当成已发布、已签名的远程镜像 digest。

构建清单覆盖 108 个选择的构建输入。所有清单中 `broker/` 下文件均与镜像 `/app/` 内容逐文件比对；最后核对未发现工作区构建输入漂移。CI 和新增测试的后续修改不进入生产镜像，另由最终候选差异清单覆盖。

## 3. 环境隔离与实际配置

三个测试容器为 Broker、Nginx、模拟上游，均运行于独立 internal Docker 网络，**没有发布任何宿主机端口**。非 root、只读根文件系统、删除全部 Linux capabilities、no-new-privileges、有限内存/CPU/PID 及受限 tmpfs 均经实际检查。

只使用本批次生成的 CA、客户端/服务器/代理证书、age 密钥、密码、TOTP 种子、恢复码和 API Key。未读取或复制生产凭据。CA、服务器证书及 age 目录对 Broker 只读；客户端签发目录、SOPS 密文目录和审计目录为隔离可写状态。`SOPS_SKIP` 未启用，实际使用生产镜像内 SOPS 进行加解密。

原始仓库 Nginx vhost 通过真实 `nginx -t`；运行夹具仅改域名、监听端口和源站地址。站点共享扫描 map/blocklist 使用明确的测试替身，**不代表生产共享 include 已验收**。

本轮修复隔离 Nginx 主配置的 FastCGI/uWSGI/SCGI 临时目录，全部放到 `/tmp`，未通过放开只读文件系统规避错误。校验配置、启动 Compose 的实际退出码均为 0。

镜像的 Node、SOPS、OpenSSL、SSH、ssh-keygen、Git 均实际存在；应用目录未检出私钥型文件、未包含 ESLint/Prettier 开发依赖。采集了真实镜像 OS/Node 软件包清单，**该 inventory 不是已签名 SBOM，也不是操作系统 CVE 扫描结果**。

## 4. 失败、修复及复验

### 4.1 预发布首轮：100 通过、4 失败

首个 r3 候选 `sha256:2733b0761c53b73c9d27e50133924b036b38fc3db85902e2f52111744c2f84f4` 出现两类实际失败：

1. Master Key 创建路由没有把 `allowed_services` / `allowed_secrets` 传给签发函数，导致请求声明的委托限制丢失，子 Key 越界服务申请未被拒绝。
2. 服务管理 API 的规范化和返回值遗漏 `allow_methods`，管理员设置的方法限制没有持久化或生效。

修复写入 `broker/server.js`：保留并验证方法数组、在管理返回值呈现策略、Master Key 路由保留两类 allowlist，并在边界拒绝错误数组形状。基于修复后的源码重建镜像，**相同核心套件复验 104/104，退出码 0**。

另外补齐常规回归：`broker-test/test-review-regressions.js` 现在有 35 个通过断言，覆盖纯规范化/校验函数、Master 路由参数传递及子 Key 拒绝路径。此测试不加载会启动服务或读取真实凭据的完整 server 模块。真实 HTTP 行为仍以上述预发布测试为准。

### 4.2 CI 与部署草稿

`ci.yml` 删除依赖仓库私钥文件、失败也可能显示 smoke passed 的旧启动步骤，改为完整 quality:gate（含临时 CA 的实际 Node 启动测试）和生产依赖审计。

`deploy-ecs.yml` 的本地草稿取消自动 master-push 部署，要求显式 workflow_dispatch 及 `preprod_review_approved` 输入，声明 `production-ecs` 环境；SSH 必须使用独立核验的 known_hosts，不再运行时 keyscan 自动信任；健康检查启用 CA/SAN 校验并拒绝 HTTP 失败。

这些是**尚未推送的代码更改**，没有改变已安装的 GitHub workflow。YAML 里的 environment 名称和布尔输入也不等于真实人员批准；required reviewers、保护规则和实际审批记录仍需在 GitHub 侧核验。旧 ECS 脚本是原地复制的 systemd 部署路径，本轮 Docker 镜像回滚证据不能代替该路径的生产回滚验收。

## 5. 真实预发布验收矩阵

| 范围 | 实际覆盖 | 结果 |
|---|---|---|
| 镜像及启动 | 实际构建 production target、非 root/只读/cap-drop、工具存在、源码哈希匹配、真实 SOPS 加载 | 已执行 |
| TLS | 边缘 TLS 1.2/1.3；源站拒绝 TLS 1.2；错误 SAN/CA 拒绝；Nginx 错误上游 SNI/CA 返回 502，不降级 | 通过 |
| mTLS | 直连与边缘正常证书；过期、错 CA、未登记证书拒绝；伪造转发头拒绝；代理身份不变成业务身份 | 通过 |
| MFA/Session | 密码仅产生 challenge；有效/错误 TOTP；一次消费、并发消费、猜测锁定；Cookie Origin；启用 MFA 后不得密码降级；注册/禁用；ACL 变化使挑战和旧会话失效 | 通过 |
| 恢复码事务 | 真 SOPS 持久化、不可重放、写目录不可写时失败并保留原密文、恢复后同挑战只消费一次 | 通过 |
| API Key | 委托权限、Owner ACL、Scope、IP、TTL、计数一次、子 Key 限额/名单/期限、父撤销传导、SOPS 失败不返回未持久化 secret | 通过 |
| Proxy | origin/路径规范化、编码歧义、方法 ACL、认证头覆盖、响应 Cookie/hop-by-hop 过滤、sandbox CSP、请求/响应体上限 | 通过 |
| SSE | Nginx 透传 ready 与实时审计事件；3 流上限、第四流 429 | 通过 |
| 客户端证书 | 签发失败恢复文件/密文/旧身份；一次性 ZIP；服务器不保留私钥；成功旋转立即撤销旧证书及会话；并发旋转仅最后证书有效；显式撤销重启后持续生效 | 通过 |
| 代理证书轮换 | 先添加新信任、切换 Nginx、再移除旧信任；从相同可信 IP 验证旧代理拒绝、新代理成功 | 通过 |
| 服务端证书与密钥恢复 | 更换合法 SAN 证书并恢复旧有效服务端证书；错误 age 密钥启动失败、恢复后可服务 | 通过 |
| 回滚 | 独立故障镜像退出 42，恢复精确候选 image ID；不恢复旧安全状态密文，已撤销 Key/子 Key/证书仍拒绝 | 通过 |
| 日志敏感值 | 测试密码、TOTP 种子、恢复码、已签发 Key/private key 未进入被检查的审计与运行日志；无遗留 SOPS 明文临时文件 | 通过 |
| 审计哈希链完整性 | 额外调用实际 audit verify 接口 | **失败，见下一节** |

核心套件 104 通过 / 0 失败；扩展套件 87 通过 / 0 失败。额外镜像/审计检查套件 6 通过 / 1 失败。不得把三者合并表述为“所有测试通过”。

完整本地 `npm run quality:gate` 退出码 0；Python SDK 28 通过；新增 review regression 35 通过；Node 启动回归 35 通过。部分历史模块测试包含 mock、跳过项或隔离模块服务，不能将其通过数解释为同等数量的生产 HTTP 端到端用例。

生产依赖 `npm audit --omit=dev --audit-level=high --json` 实际退出码 0，返回 total vulnerabilities 为 0。该结论仅限当次 npm 生产依赖检查。

## 6. 未关闭发现与放行边界

### AUDIT-INTEGRATION-01：实际日志未形成可验证哈希链

**状态：OPEN。** 真实请求 `/api/v1/admin/audit/verify` 返回 HTTP 422：`prev_hash mismatch at index 0 ... got undefined`，`broken_at: 0`。

源码证据：`broker/routes/audit.js` 的 `audit()` 直接写 JSONL，没有接入 `sealEvent()`；`broker/lib/audit-hash-chain.js` 的验证器要求每条事件带 `prev_hash/hash`。模块级哈希测试通过不能证明主服务写入路径已使用该机制。

这不是生产已被篡改的结论，而是对当前测试日志“不具备已验证哈希链”这一集成缺口的复现。未重写、补签或删除这些历史日志来让验证变绿。后续修复需要设计并验收重启续链、滚动日志/保留策略、损坏 JSON 拒绝、写入失败处理和旧无链日志迁移；不能为旧记录伪造历史完整性。

### REVIEW-HUMAN-01：真人 Review

**状态：PENDING。** 自动差异归类、格式化/AST 双重等价检查、AI 风险审查和测试记录均不是人工签字。真人需要审阅最终候选哈希绑定的六组补丁、跨组依赖、开放问题及部署迁移步骤。修改任一候选源文件后，签字应失效并重新绑定新清单。

### RELEASE-PROD-01：生产适配与发布

**状态：NOT_EXECUTED。** 本轮没有确认并克隆上一生产 release 的镜像/数据快照，因此不声称完成历史版本回退兼容。没有执行 GitHub Release、远程 registry push、Cosign keyless 签名/attestation 或真实 GitHub 环境审批。

预发布使用独立代理身份；生产迁移须先准备专用 Nginx transport 证书、配置实际代理出口 IP 与指纹，再协调升级 Nginx/应用。禁止继续复用业务客户端证书作为转发信任。保留独立管理通道；撤销记录和恢复码消费状态不得随应用镜像回滚而恢复。

WebSocket 模块测试通过不表示主服务 `/ws` 已接线；当前文档明确该路径仍需单独实现。本轮不把它列为已完成生产 WebSocket 验收。SSE 是本轮实际验证的事件流路径。

## 7. 交付位置与证据

原工作区证据根：`E:\broker\.tmp\acceptance-20260923-r3`。

- `starting-candidate.json` / `starting-tree` / `starting.patch` / `index.backup`：本轮开始时可恢复基线。
- `candidate-source.json` / `image-build-candidate.json` / `.log`：实际镜像与构建输入。
- `image-build-first.json` / `core-acceptance-first.log`：首轮失败证据，未覆盖。
- `core-acceptance-second.log` / `rotation-rollback-first.log`：真实链路验收 stdout 与实际作业退出结果。
- `quality-gate-r3.json` / `.log` / `npm-audit-r3.json`：当前本地门禁与依赖审计。
- `remote-reports`：回收的脱敏预发布报告、哈希、镜像软件包清单及开放审计问题。没有下载 fixture 密钥和 driver credentials。
- `preprod_common.py` / `acceptance-core-r3.py` / `acceptance-rotation-r3.py` / `verify-image-r3.py`：此次实际执行的测试驱动，硬限制到测试 hostname/目录/资源标签。

最终人工评审包位于 `E:\broker\.tmp\review-final-20260923-r3`，包含不可变候选清单、六组可重放原始补丁、格式噪声归一化副本、逐文件分类、重放校验和人工审批模板。混合格式与行为变化的文件保留在功能分组，不误标为纯格式化；六组是评审拆分，不承诺每个中间组可独立编译/测试。

测试驱动含状态变更：证书和 Key 撤销后，不得把旧 core 初始配置直接覆盖到同一已经旋转的 PKI 上。需要重跑完整生命周期时应生成全新隔离夹具，或先按快照清单一致恢复整个测试状态；不得挪用生产密文/密钥。

运行前后已对其他 25 个既有容器核对 ID、镜像和启动时间，未发现变化。测试资源清理的实际状态以单独 `environment-closeout.json` 为准；原始密钥材料不进入评审压缩包。

## 8. 人工放行记录模板

| 审批项 | 状态 | 审查人 | 实际时间 | 绑定的清单/证据 |
|---|---|---|---|---|
| 六组差异及跨组依赖 | PENDING | 未填写 | 未填写 | 最终 manifest SHA-256 |
| 身份、MFA、证书及 Proxy 安全审查 | PENDING | 未填写 | 未填写 | 源码清单及 191 项实际用例 |
| AUDIT-INTEGRATION-01 关闭或明确不予发布 | OPEN | 未填写 | 未填写 | 422 失败证据与后续修复复验 |
| 生产专用代理证书迁移 | NOT_EXECUTED | 未填写 | 未填写 | 实际生产只读基线及迁移计划 |
| 生产前一版本兼容回退 | NOT_EXECUTED | 未填写 | 未填写 | 前一镜像/配置版本的真实演练 |
| GitHub 环境审批及签名发布 | NOT_EXECUTED | 未填写 | 未填写 | 真实 workflow run / attestation |

在上述发布门禁关闭前，不将本候选推广为生产已验收版本。
