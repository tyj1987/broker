# 大规模差异拆分与预发布审查记录

## 1. 当前结论

**部署结论：NO-GO。** 本轮完成了可恢复基线、五组原始差异包、补丁重放校验、部署配置修正、专项/全量质量门禁，以及远端 Docker Compose 的配置校验。新增的隔离身份解析测试同时复现了三条不满足安全预期的转发路径，必须先修复并复审。

**人工 Review：PENDING。** 本文由 AI 辅助审查生成，不代表真人逐文件审查或签字。尚未完成全部差异的逐文件审查、纯格式化拆分、逐提交验证或真实预发布验收。测试脚本退出码为 0 不替代这些门禁。

本轮没有 commit、push、切换分支、重置原工作区、启动远端容器、修改生产服务或部署 `broker.52trz.com`。

## 2. 证据基线

- 授权目标：ROG / Windows，工作区 `E:\broker`。
- 分支：`codex/security-audit-hardening`。
- HEAD：`cee3e4cbea87b6011d61d618309528bdd96bbd33`。
- 原始范围：158 个已跟踪文件改动、28 个实际未跟踪文件，共 186 个差异条目；其中一个文件删除，因此现存文件为 185 个。
- 原暂存区为空，独立重放后原 index 的 SHA-256 仍匹配基线。
- 原始包：`E:\broker\.tmp\review-20260922T190304Z`。
- `baseline.json` SHA-256：`2d398c684ffe8b728f22919cf5caa5c11a364637d71f3a157d645a591c2c289e`。

包名中的 UTC 时间来自设备的实际执行记录，不应改写为聊天日期。TLS/TOTP 验收另须核对各测试节点的时钟和时区。

`baseline.json`、`head-to-worktree.patch`、`index.patch`、`worktree.patch`、`index.backup`、`status.z` 与 `tree/` 保存原始状态。未把 Git 忽略的生产凭据、PKI 私钥或 SOPS 解密材料纳入快照。恢复时应先在独立目录验证，不要对当前工作区盲目执行 reset/clean。

## 3. 差异拆分的实际完成程度

| 原始审查组 | 内容 | 结果 |
|---|---|---|
| 01-runtime-security | Broker/CLI 运行时代码与新增辅助模块 | 原始补丁已生成；安全语义仍需逐项审查 |
| 02-tests | 回归测试、Python SDK 测试入口 | 原始补丁已生成；不可与依赖的运行时代码割裂发布 |
| 03-supply-chain | Dockerfile、工作流、依赖清单、安装器、质量门禁 | 原始补丁已生成；发布链真实执行仍未验收 |
| 04-operations | Nginx、运维脚本、Git 忽略规则 | 原始补丁已生成；预发布运行未验收 |
| 05-documentation | README、VERIFY、用户文档、旧审计记录 | 原始补丁已生成；旧报告结论不能替代本轮事实 |
| 06-formatting-only | 经验证的纯格式变更 | **未完成**；归一化脚本执行被平台拦截，没有运行，也没有通过其他路径重试 |

共 33 个补丁文件。已将这些补丁应用到独立 `verify-source/`，逐文件比对全部 186 个基线条目，未发现缺失、哈希不符或额外文件。证据：`verify-packet.json`、`patch-hashes.json`。

这属于“可复核的审查包拆分”，**不是已经生成独立可发布提交**。格式化仍混在部分原始补丁中；`git diff -w` 只是阅读辅助，不能证明语义等价。生成的 `normalize-review.cjs` 不能当作已经执行过的证据。

运行时代码及其回归测试应作为耦合审查单元。后续组织提交时，必须明确每个提交的依赖及可执行测试，不应机械按目录切出无法运行的提交。

本轮新增修复另存 `review-fixes/` 和 `review-fixes.json`，不覆盖原始基线。该增量包的生成、哈希和重放结果应以文件中的实际证据为准。

## 4. 已修正的部署配置问题

本轮修改了四个源文件：`Dockerfile`、`docker-compose.yml`、`.dockerignore`、`broker-test/test-release-workflow.js`，另新增本文。

### 4.1 Compose 解析与健康检查

初始严格 YAML 解析在第 78 行报 `DUPLICATE_KEY`，原因是同一服务重复声明 `restart`。已移除重复声明。

健康检查已改成显式 `CMD` 列表，明确请求 `/health`，读取挂载 CA，并使用配置的 TLS 服务器名称校验证书，不再使用 `rejectUnauthorized:false`。

临时目录从错误的命名卷访问模式 `broker-tmp:/tmp:size=64M` 改为有容量限制的 tmpfs，删除过时的临时命名卷。

### 4.2 启动变量和证书模块导入

`broker/server.js` 实际读取 `PORT`、`CONFIG_PATH`、`SECRETS_PATH`；原 Compose 使用的 `BROKER_CONFIG_PATH` 不会配置该路径。

`broker/cert-issuer.js` 在模块导入时就需要 `TLS_CA` 或 `CA_CERT_PATH`，仅给 `PKI_DIR` 不能满足该模块的初始化要求。

已让生产镜像与 Compose 显式提供实际使用的配置、CA、CA 私钥路径、age 私钥路径和端口变量。只设置路径，不写入或复制真实密钥。

### 4.3 最小可写范围

保留只读根文件系统以及所有能力丢弃。CA、服务器证书和 age 目录只读挂载；仅客户端证书/序列号目录与 SOPS 配置目录可写，满足证书轮换和同目录原子替换的路径要求。

绑定目录使用 `create_host_path:false`；实际启动前必须准备正确目录、节点 UID/GID 和文件访问权限。**未在本轮修改主机生产密钥权限。**

源站端口默认仅发布到宿主机回环地址，移除不必要的 `NET_BIND_SERVICE`。这不证明容器内观察到的对端地址是回环，仍必须解决第 5 节的转发信任问题。

### 4.4 构建上下文

显式排除递归 `node_modules`、PKI、age、常见密钥扩展名、`.tmp/`、`.worktrees/` 及本地恢复元数据，避免将宿主机依赖或审查快照带进构建上下文。

镜像实际内容、层历史、SBOM、非 root 权限及运行时工具仍未通过真实构建验证。可选监控 profiles 未完成部署审查，不包含在本轮 Compose 修正的运行验收范围中。

规范参考：Docker 官方 Compose services 文档 https://docs.docker.com/reference/compose-file/services/ 。本轮还执行了原生 Compose 配置校验，而不是仅做字符串断言。

## 5. 阻断项：转发身份的信任边界

来源：完整读取的 `broker/lib/mtls.js`、`broker-test/test-mtls.js` 和 Nginx vhost。证据：`forwarding-boundary-review.json`。

测试在本地以隔离请求对象执行，未连接任何生产服务、未使用真实账号或密钥。TLS 的 socket 授权状态为测试夹具；其中普通客户端冒充转发者的用例使用了注入的 X509 解析器。**这是身份解析模块的条件性复现，不是真实 TLS 握手或生产可利用性结论。**

### R-01：非回环转发回退为代理本身身份

向解析器传入 `X-SSL-Client-Verify: NONE` 和已授权的代理连接证书。回环地址对照组返回匿名；模拟容器网络的非回环地址 `172.30.0.2` 则进入直接 mTLS 分支，返回代理自身身份。

测试夹具把代理角色设为 admin，以显示最大影响。**没有读取或确认生产 `client.mavis` 的角色。** 若实际代理身份具有业务权限，外部匿名请求可能错误继承这些权限；具体影响取决于部署拓扑和代理配置。

关闭条件：明确区分直连客户端和转发连接；未受信任的转发头不能使请求回落成具有业务权限的代理身份。必须以真实容器链路验证无证书、错误证书、伪造转发头和有效证书四类请求。

### R-02：普通已登记证书被接受为转发方

`isTrustedForwardingPeer()` 仅检查回环、TLS 授权，以及对端指纹是否匹配任意已登记客户端，没有独立的转发代理白名单。

隔离用例中，普通 developer 客户端在回环连接上携带指向 admin 公共证书的转发头，解析结果变成 admin。这不能证明远程互联网请求可触发该路径；前提包括本地路径可达和有效普通客户端凭据。

关闭条件：可信代理需要显式地址与证书绑定，不应等同于所有已登记客户端。代理身份应与普通业务身份分离，并增加普通客户端转发、未登记代理、代理证书撤销/轮换的拒绝测试。

### R-03：回环转发 IP 不要求代理已认证

`clientIpFromRequest()` 对回环请求直接采用 `X-Real-IP`/`X-Forwarded-For`。隔离测试中，`socket.authorized:false` 的回环请求提供白名单 IP 后，API Key 身份被接受。

关闭条件：只有已验证的可信代理才能提供用于访问控制的客户端 IP；其他请求必须使用连接地址或拒绝。需要同时验证 IPv4、IPv6、IPv4-mapped IPv6、直接连接和容器网络拓扑。

以上三条是相关的失败路径，不应简单换算成三个互不相关的漏洞。当前未更改生产代理身份策略，也未用“允许所有容器 IP”或关闭 TLS 验证的方式绕过问题。

## 6. 实际验证结果

| 检查 | 本轮实际结果 | 证据 |
|---|---|---|
| 原始状态可恢复快照 | 完成 | baseline.json、index.backup、二进制补丁 |
| 五组补丁独立重放 | 33 个补丁、186 条目一致 | verify-packet.json |
| 修正前新增合同测试 | 130 通过、31 失败，退出码 1 | ChatLink 作业 boQ03uL_gBvd9c4GXL0bRwsPXJ3jpOmW4DAxzGF1-zs |
| 修正后发布/部署合同专项 | 161 通过、0 失败，退出码 0 | release-contract-after.log |
| 本轮完整 quality:gate | 退出码 0 | quality-gate.log；作业 jAYGnq40Zf3Nt-56fkkKTkibPHlkbBNBCqi5wDKiesA |
| MCP 脚本汇总 | 53 通过、0 失败 | quality-gate.log |
| Python SDK | 28 通过 | quality-gate.log |
| 原生 Docker Compose 配置校验 | 退出码 0，stderr 为空 | compose-native-validation.json |
| 转发身份隔离测试 | 1 个对照满足预期、3 条失败路径 | forwarding-boundary-review.json |
| 镜像构建、运行与 Nginx -t | 未执行 | 不得使用静态测试替代 |
| 真实 TLS/mTLS/MFA/API Key/Proxy/轮换/回滚 | 未执行 | 需完成前置门禁 |

修正前的 31 个失败断言中，多项由 YAML 解析失败连带触发，不能称为 31 个独立缺陷。

转发测试执行作业退出码为 0，表示测试探针正常运行；报告中的 `secure:false` 才表示安全预期未满足。现有质量门禁尚未覆盖这些新增拒绝路径，因此质量门禁通过与部署 NO-GO 不矛盾。

MCP 测试输出包含显式跳过的异常路径说明。本轮不将它记作已执行的异常路径验收。未额外执行 npm 依赖漏洞审计，旧报告中的零漏洞结论不作为本轮最新审计结果。

## 7. 预发布环境现状

| 目标 | 只读探测结果 | 不能由此推导的结论 |
|---|---|---|
| ROG 原生 Windows | 未发现 Docker/Nginx；已具备 Node、Git、Python | 不等于已具备完整预发布环境 |
| ROG / Ubuntu-24.04 WSL | 有 OpenSSL，未发现 Docker/Nginx | 未安装或启动额外服务 |
| SSH alias docker | hostname docker，root；Docker Server 29.7.2；Compose 5.5.0；未发现宿主机 Nginx | 仅是候选执行主机，不代表预发布已获验收 |
| SSH alias test-env | SSH 连接超时 | 未读取到环境信息 |

原生 Compose 校验仅经 SSH stdin 传入当前 YAML，执行 `config --quiet`；没有拉取镜像、创建容器、重启服务或修改宿主机配置。Nginx 容器化拓扑、隔离网络、项目名、端口、临时 PKI、独立状态卷仍须确定并验证。

## 8. 进入真实预发布前的验收矩阵

| 门禁 | 必须取得的证据 | 当前状态 |
|---|---|---|
| 差异与人工 Review | 当前候选哈希、每组 reviewer、格式化等价证明、阻断项关闭记录、逐提交测试 | PENDING |
| 环境隔离 | 主机身份、独立命名空间/网络/端口/卷、非生产测试身份、时钟一致性、失败清理边界 | NOT_RUN |
| 镜像 | 实际 production 构建成功、digest、非 root、工具可用、无宿主依赖/私钥、SBOM/签名与同一 digest 绑定 | NOT_RUN |
| Nginx/TLS | 完整配置含依赖的 nginx -t；CA/SAN/SNI 正向握手；错域名、过期、非受信 CA 拒绝 | NOT_RUN |
| mTLS/身份转发 | 无证书匿名、不可信证书拒绝、有效客户端正确归属；R-01/R-02/R-03 真实链路负向测试 | BLOCKED |
| MFA | 密码后挑战、错误/过期挑战拒绝、恢复码一次性、持久化失败恢复、会话撤销；确认密码回退策略 | NOT_RUN |
| API Key | Owner ACL 与委派权限交集、过期/撤销、限流、IP 策略、无账户管理权限、主子 Key 边界 | NOT_RUN |
| Proxy | 仅使用隔离上游；Origin/端口/凭据头不可越界；超限拒绝、响应头、超时/断连、审计脱敏 | NOT_RUN |
| 证书轮换 | 新证书生效、旧证书及旧指纹会话失效、私钥仅返回一次、持久化失败恢复、并发轮换 | NOT_RUN |
| 回滚 | 锁定旧/新镜像 digest，兼容配置/状态快照；失败恢复旧实例；撤销凭据不因回滚复活；审计连续 | NOT_RUN |

回滚不是简单恢复旧文件：不能把已撤销证书或已消费恢复码重新激活。必须事先确定安全状态与业务数据的恢复边界，并进行可重复的失败注入与复验。

生产部署是独立后续步骤，不包含在本轮配置校验内。

## 9. 人工签字与审查覆盖

| 项目 | 签字/结论 |
|---|---|
| 运行时身份与权限 reviewer | PENDING |
| 发布/容器/Nginx reviewer | PENDING |
| 测试与失败路径 reviewer | PENDING |
| 纯格式化拆分 reviewer | PENDING |
| 候选版本/哈希确认 | 以 current-candidate.json 为准，待人工确认 |
| 允许进入预发布 | 未放行 |

本轮完整阅读了身份解析、会话、MFA 辅助、证书生命周期、SOPS、浏览器请求边界、API Key 路由策略、Proxy 辅助、相关测试、Docker/Compose/Nginx、主要发布工作流和既有审计文档。`broker/server.js` 本轮读取了启动与配置部分（1–420 行），并未据此宣称其全部 3953 行已完成审查；其他未逐文件检查的差异仍保留待审状态。

后续优先顺序：关闭转发信任失败路径并加入强制回归；完成差异/格式拆分与真人 Review；再在隔离 Docker/Nginx 环境逐项取得运行验收和回滚证据。不要直接使用本报告替代人工放行或生产部署授权。
