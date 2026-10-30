# Broker R4：审计集成修复与真实预发布复验

## 结论

**功能预发布复验通过；生产发布仍为 NO_GO。** 原 `AUDIT-INTEGRATION-01` 已在本报告绑定的 R4 源码与镜像上完成正向、拒绝路径和重启复验，可以关闭该集成缺口。镜像末次终检与测试环境清理命令被平台拦截，未执行，不能声称环境已收尾。

本记录接续 `AUDIT-LEDGER-R4-2026-09-23.md` 的未验证阶段。批次名称沿用 2026-09-23；原始作业时间为 2026-09-22 UTC，各设备日志原样保存，不改写设备时间。

## 1. 工作区与候选身份

| 项目 | 实际记录 |
|---|---|
| 授权执行设备 | ROG / Windows |
| 原始工作区 | `E:\broker` |
| 分支 | `codex/security-audit-hardening` |
| HEAD | `cee3e4cbea87b6011d61d618309528bdd96bbd33` |
| 原 index SHA-256（门禁和构建后均核对） | `e1fbb8b8a728c9978548d92686246a909af229c775b94e8c8d5f75cf12d7ed7d` |
| SSH 目标 | alias / hostname 均为 `docker` |
| 全新隔离目录 | `/tmp/broker-preprod-r4-20260923` |
| Compose 项目 / 容器前缀 | `broker-preprod-r4` |
| 资源标签 | `broker.preprod.run=r4-20260923` |
| 源码清单 SHA-256 | `abfd142ebdfb8e4b3fea97c94973a32970a37de61deb0a457d71bb22ccb65ad0` |
| 构建输入文件 | 109 |
| Docker image ID | `sha256:e7ee1f5584ac5b47d6f0e69f8032ae39b1588cdbbee4f1ec658612b89d93927a` |
| Nginx 固定引用 | `nginx@sha256:ef8676b33d681f272ba429b27658bdd7e640963279714c96bddf1dc76307f7b6` |

Docker image ID 是本地镜像身份，不是 Registry 发布、Cosign 签名或 attestation 的证明。本次没有推送 Registry。

新环境使用新 CA、TLS/mTLS 证书、age 密钥、密码、TOTP 和 API Key；未复用 R3 已轮换/撤销的测试身份。网络为 internal，未发布宿主机端口；容器使用非 root、只读根文件系统、cap_drop=ALL 和受限 tmpfs。R3 原始成功/失败证据保持原样。

## 2. 实际执行结果

| 验证 | 结果 |
|---|---|
| 第一轮验证入口 | 失败：格式化退出码 2，账本排序表达式缺少右括号；未进入后续测试 |
| 修正语法后第二轮验证入口 | 完整退出码 0 |
| 格式化、专项、read-api、lint | 各步骤退出码 0 |
| 完整 `quality:gate` | 退出码 0 |
| Windows 审计账本专项 | 47 通过 / 0 失败 |
| Docker 镜像构建 | 退出码 0；构建前后源码清单无漂移 |
| Nginx 原始 vhost 的 `nginx -t` | 退出码 0 |
| 原生 Compose config / up | 退出码均为 0 |
| TLS/mTLS/MFA/API Key/Proxy 核心复验 | 104 通过 / 0 失败 |
| 证书轮换、SOPS 故障与镜像回滚复验 | 87 通过 / 0 失败 |
| 真实 HTTP 审计与故障注入专项 | 33 通过 / 0 失败 |
| Linux 生产镜像内审计账本专项 | 47 通过 / 0 失败 |
| 镜像末次七项检查 | 未执行：调用被平台拦截 |
| 测试容器及网络清理 | 未执行：与末次检查同一次被拦截调用 |

预发布三套共 **224 项检查（104+87+33）**。其中审计专项的一条检查是“Linux 回归套件退出码为 0”；Linux 的 47 个断言单列，不重复加入 224。Windows 专项及常规质量门禁包含重复覆盖，也不累加成独立端到端用例数。

本轮仅修正账本排序表达式的语法错误并完成格式化；未弱化完整性断言。原验证入口的执行者字段已改为通用入口标识，实际启动者由 ChatLink 作业证据确认；第一轮历史 JSON 的旧字段原样保留，不将其视为真人执行证明。

## 3. 原审计阻断的真实闭环

R3 的正常审计验证曾返回 HTTP 422：真实写入路径没有 hash/prev_hash。R4 现在由生产路由写入分段哈希链与持久检查点，并完成以下验证：

- 正常日志：HTTP 200，`ok:true`；末次检查覆盖 208 个事件、1 个文件、103544 字节。
- 重启：同一 chain_id 和 head 保持；新审计事件继续序号，不重建 genesis。
- 篡改、完整尾事件删除、追加损坏记录、检查点缺失：真实 HTTP 接口返回 422。
- 独占锁与真实目录不可写：返回 503；锁不被抢占，失败的 Key 创建未改变 SOPS 密文或返回 secret。
- 审计故障期间公共 /health 仍可用；变更请求拒绝。
- 损坏日志下重新启动生产镜像：进程非零退出，没有静默截断或重签日志；恢复测试夹具原字节后恢复服务。
- API 清空审计被拒绝（409），证据保留。
- 并发读取通过；没有遗留事务锁或检查点临时文件。
- Windows 与 Linux 的 47 项文件系统回归覆盖分段、旧无链日志基线、保留策略、写入/检查点失败和多进程竞争。

末次链标识：`d45a19c1-25c3-46c1-9384-6c5700bf8624`。

末次 head：`c73a3e9c37e755790c6a8ea101ab3167917daa4726c2a850df8b86c1d5175dc2`。

该环境没有历史无链记录或已修剪记录，因此本次返回 `full_history_verified:true` 仅指本测试链。`independently_anchored:false` 保持原值；不声称具备外部签名、WORM 存储或对日志与检查点同时重写的独立防护。

## 4. 证据位置与实际作业

本地根：`E:\broker\.tmp\acceptance-20260923-r4`。

| 证据 | 位置 / 作业 |
|---|---|
| 首次语法失败 | `local-verification-2026-09-22T22-18-36-772Z`；作业 `PYx-d5WXGx-7wURd_YUTQLImMxtiax115tzxNB2g2Bg` |
| 全部门禁通过 | `local-verification-2026-09-22T22-19-13-724Z`；作业 `ZF7tzjvJJsDoS-cBh9CU3oxpnWnU0Jvv_dshmLcES4A` |
| 构建、清单、驱动来源 | `live/image-build.json`、`live/candidate-source.json`、`live/driver-provenance.json`；作业 `k1tnO6U_EBXqcm6q3l1iSKLQFfHIPm4-iZTzeB1U13I` |
| 104+87 复验 | 作业 `ZoV7jy1mYhK7Xu_rir83FinhPU9HsguWrB2Ds7vrAQA`，退出码 0 |
| 33 项真实审计复验 | `live/audit-live.log`；作业 `Uq-ipjHAe9pjKxemr7q7P9aVZPLMGmYlRqgiShRhb70`，退出码 0 |
| 回收的脱敏报告 | `live/remote-reports/`；SCP 作业 `Q6ckbjAeB0GZ60lYUGB172ieU6JMmMDFkRaoqBLDnpo`，退出码 0 |

只回收了七个指定的报告/测试日志，没有回收 fixture 私钥、age 密钥、driver-secrets 或 driver-state。完整故障夹具保存在隔离目录内用于复核，不作为可分享验收附件。

## 5. 尚未执行的末次步骤

平台在镜像终检及清理调用时返回“因 OpenAI 无法确定请求的安全状态，已拦截此工具调用”。没有 ChatLink request_id/job_id，也没有执行退出码。没有通过另一终端或包装重试被拦截操作。

最后成功观察到的测试容器：`broker-preprod-r4-broker`、`broker-preprod-r4-edge`、`broker-preprod-r4-upstream`；网络：`broker-preprod-r4-net`。**本轮不能报告它们已停止或删除。** 此前 R3 的清理记录不能替代 R4 清理记录。

环境启动前记录了 25 个既有容器；本轮未对生产服务、DNS、证书、凭据或其他容器发起修改，但末次全体既有容器的身份/镜像/启动时间比对也未执行，不将其写成“已核对未变”。

本机操作者在 ROG 上审核后可执行原有末次入口，并读取真实结果：

```powershell
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes docker "cd /tmp/broker-preprod-r4-20260923 && python3 verify-image-r4.py && python3 close-preprod-r4.py"
```

该入口只针对带 r4 标签的隔离环境；清理脚本会校验容器集合和网络成员，拒绝清理异常集合。不应使用全局 Docker prune，也不应删除测试证据目录。入口失败后应读取其结果，而不是跳过检查继续宣称完成。

## 6. 人工 Review 与发布边界

当前批准是继续执行工程验证的授权，不能替代绑定最终变更清单的逐文件人工 Review。六组候选差异需要按最新 manifest 重放并审查；R3 旧清单不再覆盖 R4。

仍需单独完成：最终候选人工签字、镜像末次校验及 R4 环境收尾、上一实际生产版本的数据兼容回退、真实受保护发布流程与签名。本次“故障镜像回退到已验证 R4 镜像”不能证明历史生产版本兼容性。

实现还保留明确边界：同步审计检查可能影响大日志环境延迟；在线校验有 64 MiB 单文件、512 MiB 总扫描及 4096 段上限；没有真实断电验收或外部可信 checkpoint。审计与 SOPS/外部上游不是跨资源原子事务，结果写入失败可能产生不确定业务结果，需要对账。此处不声明不存在其他漏洞，也不因有限测试通过而降低发布门禁。

规范复核来源：Node.js 24 fs API 的 flush/fsync 说明，以及 OWASP Logging Cheat Sheet 的故障、篡改与删除验证建议。这些规范不是本实现测试结果的替代证据。

- https://r2.nodejs.org/docs/latest-v24.x/api/fs.html
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
