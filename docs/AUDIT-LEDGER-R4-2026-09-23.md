# 审计哈希链 R4：初始实施记录（历史快照）

> 本文保留上一轮“代码落盘但未执行”的历史记录。用户批准继续后，已修正一处语法错误，完整质量门禁退出码 0，真实预发布 104+87+33 项检查通过；审计集成缺口已复验关闭。最新状态、证据及末次镜像检查/环境清理阻断见 `PREPROD-ACCEPTANCE-R4-2026-09-23.md`。下文的“当前”“本轮”和旧哈希均指当时状态，不是最新结论。

## 当时状态

**IMPLEMENTED_NOT_VERIFIED / NO_GO。** 审计哈希链修复和回归测试已写入 ROG 的 `E:\broker`。本轮唯一一次格式化/测试执行请求被 OpenAI 平台以“无法确定请求的安全状态”拦截；没有创建作业，没有退出码，格式化、测试和 lint 均没有执行。

这不是 ChatLink 的 pending 本机审批，也没有可查询的审批 request_id。没有通过通用 shell、换一种命令包装或其他运行环境重试该执行操作。本机只登记了 `workspace-shell`，没有专用质量门禁任务。

`AUDIT-INTEGRATION-01` 保持 **OPEN / PATCH_WRITTEN_AWAITING_VALIDATION**。R3 的 104+87 项通过和镜像 `sha256:8f08c0ba851aa16d70cdb74cb87a649edb98568584c783b4810f32803c668056` 只适用于 R3 源码；不能用于证明 R4 正确。R3 的真实审计验证 HTTP 422 尚未在 R4 上复验。

## 已取得的本轮证据

- 目标设备：ROG / Windows，在线；工作区：broker。
- 修改前分支：`codex/security-audit-hardening`。
- 修改前 HEAD：`cee3e4cbea87b6011d61d618309528bdd96bbd33`。
- 本轮修改前的 194 个差异条目已保存至 `E:\broker\.tmp\acceptance-20260923-r4\starting-tree`，另有 `starting-candidate.json`、`starting.patch` 与 `index.backup`。
- 快照作业：`PuZru27WDRt-QmaAWbIv2agaEV4laKR650GOmeE_UUM`，实际退出码 0。
- 快照时原 index SHA-256：`e1fbb8b8a728c9978548d92686246a909af229c775b94e8c8d5f75cf12d7ed7d`。
- 修改前 `git diff --check` 无输出；本轮修改后没有执行它，不沿用之前的结果。
- 本轮没有提交、推送、启动预发布容器、更新镜像、迁移实际日志、修改生产凭据或生产服务。

## 修复内容（代码已落盘，行为待实测）

### 1. 实际写入路径接入哈希链

新增 `broker/lib/audit-ledger.js`，由 `broker/routes/audit.js` 的真实审计写入函数调用。流程为：事件脱敏 → 按持久 JSON 值规范化 → 写入带 `prev_hash/hash`、链 ID 和序号的事件 → flush → 原子替换持久检查点 → 发布到 ring/SSE。

日志分段采用不可覆盖的顺序文件名；检查点保存每段的起止序号、起止哈希、长度、事件数及关闭段校验和。重启时校验现有证据后续链，不重新生成 genesis。未提交尾部、长度不匹配或崩溃遗留锁不自动截断、补签或删除。

### 2. 验证器不再跳过损坏证据

`broker/lib/audit-hash-chain.js` 的哈希基于实际 JSON 序列化结果，避免 undefined、Date、数组空位等在内存与磁盘之间不一致。调用者提供的 hash 不进入计算。

新验证器检查持久检查点、整段长度、事件连续性、序号、末端哈希、旧日志基线和多余文件；旧格式验证也读取编号轮转文件，拒绝损坏 JSON 和不完整尾行。读写竞争返回 retryable 非成功结果；HTTP 路由区分 503（暂不可用）与 422（完成后的完整性失败）。

### 3. 历史无链记录不补造证明

首次启用时对旧 JSONL 做字节级 inventory；不修改原文件，也不为历史事件补 hash。报告分别返回 `legacy_baseline_unchanged`、`legacy_history_verified`、`full_history_verified`。新链通过不等于旧历史通过。

### 4. 保留策略不重置链

仅允许经过校验的、已关闭的连续前缀按保留期处理。先记录保留计划、持久保存段边界和校验和，再移除对应文件；报告明确为 retained-events-with-local-retention-checkpoints，不声称已删除的事件正文仍可验证。已纳入基线的旧无链日志默认保留。

通过 API 清空审计证据改为 HTTP 409，避免删除日志后重启链掩盖历史。`pruneAuditFiles()` 在检查点缺失而管理段仍存在时拒绝降级为旧清理逻辑。

### 5. 写入失败不冒充成功

写入/检查点失败不将事件放入 ring/SSE。配置、会话变更前记录请求意图；Proxy 调用前记录授权后的调用意图。审计存储在操作开始前不可用时，应拒绝继续。

**这不是审计文件与 SOPS/外部上游之间的跨资源原子事务。** 如果意图已持久化、业务操作已发生，而结果日志落盘失败，操作结果可能不确定。必须查询业务状态后对账，不能盲目重试，也不能声明“503 必然意味着无副作用”。此边界尚需真实故障注入验证。

### 6. 回归与门禁

新增 `broker-test/test-audit-ledger.js`，并接入 `test:verify-all`。测试覆盖实际路由写入、JSON round-trip、重启、分段、过滤读取、损坏/截断/缺失文件、缺失检查点、旧日志保留、保留策略、写盘与检查点失败、多进程竞争和遗留锁。

更新旧 clear 测试以验证新契约：明确拒绝清空，且证据不变；没有降低哈希完整性断言。**测试文件已写入不等于已执行；本轮不存在通过数量。**

## 当前源码哈希（格式化尚未运行）

| 文件 | SHA-256 |
|---|---|
| broker/lib/audit-hash-chain.js | d63302ca13d8c3b7c78a35cdf78e05266d6cf1a352ac51306d7465c3c715f0d6 |
| broker/lib/audit-ledger.js | 2d45a3e5f27a423f5731c417a0ec3c3f75a778d022a9e809238694a51e3f574e |
| broker/lib/audit-policy.js | 32ea8f3dc32799afa2927da895f07140b318923c2d8fc41bfe2287370418c071 |
| broker/routes/audit.js | 34dfd298a0d2ac31f07bc5912b87245ed76fc1a67760ebfc90727128fe90103c |
| broker/routes/read-api.js | 2a29125fded434e9fabd39b9afeec5662065348dd2787e2c3e0d1ce165382523 |
| broker/server.js | 6b6843c1524db68c052ed67dc227f80bd2f956a11d804b747f0ed3450bafda26 |
| broker/package.json | 1ef6c6e040c378e1f47ada034085388533e8c2d5b8a15aa38bfa6c0c1d063aee |
| broker-test/test-audit-routes.js | 2718a24c6eb4a713bc802670ce3cf0a94c99e50878f21abe59cf1d61759f576d |
| broker-test/test-audit-ledger.js | 941c358dabe45319d29796c6e406d40792dfe3626bd6480172b2bb53216de9c5 |

这些是读取/写入工具返回的完整文件哈希，不是最终发行 manifest。格式化或后续修复会改变它们；R3 的 review-final manifest 不再覆盖当前工作区。

## 明确的限制与待验收项

本地检查点没有独立签名，也没有外部可信锚定。拥有同时改写日志和检查点权限的攻击者不在本地哈希链单独能证明防御的范围内。需要将检查点同步到独立只读/不可变存储，不能把 `independently_anchored:false` 改成通过。

在线校验设置了单文件 64 MiB、累计 512 MiB 和 4096 段等限制；超限会拒绝，不能称为完成全量验证。大体积日志迁移、性能、崩溃恢复、磁盘满、跨平台目录 fsync 差异及外部 checkpoint 对账尚未实测。Windows 不具备本实现可移植的目录 fsync 路径，不宣称与 Linux 具有完全相同的断电保证。

尚未执行：格式化、lint、专项测试、完整 quality:gate、新镜像构建、Docker/Nginx 191 项复验、真实审计接口正/负验收、新审查包重放。真人 Review、历史生产版本兼容回退和真实签名发布仍待各自独立门禁。

## 本机验证入口（已保存，未执行）

`E:\broker\.tmp\acceptance-20260923-r4\run-local-verification.cjs`

由本机操作者审核后运行：

```powershell
node "E:\broker\.tmp\acceptance-20260923-r4\run-local-verification.cjs"
```

脚本只格式化明确列出的改动 JS 文件，再运行审计专项、read-api、lint 和现有 quality:gate；在独立 local-verification-时间戳目录中保存日志、退出码及源码哈希。任一步失败即停止。现有 quality:gate 包含 Python SDK 开发依赖安装步骤，可能访问软件包仓库；该脚本不部署、不发布镜像、不访问生产 Broker。

脚本运行后的结果需要重新读取才能记入验收。随后必须用新源码清单重建隔离预发布，不复用已轮换且被撤销的旧测试身份来覆盖初始化配置，不覆盖 R3 原始失败证据。

## 规范参考

- Node.js fs API：flush/fsync 的语义及操作系统差异：https://nodejs.org/download/release/v24.1.0/docs/api/fs.html
- OWASP Logging Cheat Sheet：篡改/删除检测、日志故障测试、独立保护与保留边界：https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

上述规范参考不是本实现已通过测试的证据。
