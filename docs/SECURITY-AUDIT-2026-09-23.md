# Secret Broker v4.9.0 安全与工程审计报告

**审计日期：2026-09-23**  
**本地工作区：`E:\broker`**  
**审计分支：`codex/security-audit-hardening`**  
**目标版本：4.9.0**  
**线上观察对象：`https://broker.52trz.com`**

## 1. 结论摘要

本轮对 Broker 服务端、Dashboard、MCP Server、CLI、SDK 测试入口、Nginx 配置、容器构建、GitHub Actions、发布签名/SBOM、凭据轮转脚本和当前用户文档进行了联合审查与实际修改。

本地代码已经达到以下状态：

- 完整 `npm run quality:gate` 通过，最终退出码为 0；
- ESLint 无错误，Prettier 检查通过；
- Node.js、MCP、SSH、WebSocket、Workload Identity 和 Python SDK 回归通过；
- 生产依赖 `npm audit --omit=dev --audit-level=high` 报告 0 个漏洞；
- `git diff --check` 通过；
- 受 Git 跟踪的敏感扩展名检查无结果；
- 自定义凭据特征扫描未发现测试夹具/文档占位符之外的异常命中；
- 发布与供应链专项回归 127/127 通过；
- 线上公共健康检查返回 HTTPS 200 和 `{"status":"ok"}`。

该结果表示：**当前本地分支未发现已知测试失败或高危依赖漏洞，具备进入发布候选评审的条件。**

但不能据此宣称“绝对没有任何 Bug 或漏洞”。以下门禁仍未完成：

1. ROG 未安装 Docker，真实 `production` 镜像尚未在本机完成构建和运行时检查；
2. ROG 未安装 Nginx，新的虚拟主机配置尚未执行真实 `nginx -t`；
3. 本地修改尚未提交、推送或部署；
4. 线上实例仍运行旧代码/旧边缘策略，需要预发布部署和回滚演练；
5. 当前差异面较大，不适合未经拆分评审直接作为单一提交发布。

## 2. 审计范围

### 2.1 身份与会话

审查并加固：

- mTLS、反向代理转发证书和 API Key 身份优先级；
- Cookie Session 的同源写操作边界；
- 登录、退出、密码修改和会话撤销；
- 滑动过期与绝对最长会话寿命；
- 登录失败锁定和高基数内存消耗；
- 管理员角色、ACL、密码策略变化后的旧会话处理。

### 2.2 MFA 与高风险操作

审查并加固：

- TOTP 设置、验证和禁用；
- 恢复码一次性消费及持久化失败回滚；
- MFA pending token 容量与生命周期；
- 管理员创建/修改/删除客户端；
- 客户端证书签发、轮换、撤销和兼容下载；
- API Key 与 Master Key 创建、撤销和子 Key 签发。

### 2.3 凭据与证书生命周期

审查并加固：

- 客户端密码在配置边界的哈希处理；
- 客户端私钥一次性返回；
- 一次性 ZIP 的路径安全和文件权限；
- 证书签发/轮换的文件系统与配置事务；
- 旧证书指纹会话撤销；
- SOPS 原子写入；
- 阿里云 AccessKey 轮转脚本。

### 2.4 Proxy、SSH 与网络边界

审查并加固：

- Upstream URL 和 SSRF；
- 请求头覆盖与响应头泄漏；
- Upstream 响应体限制；
- API Key 路由权限；
- Health 信息最小披露；
- SSH 输入错误、Secret 配置错误和系统错误的分类；
- 浏览器 Origin、Cookie Session 与 CSRF 边界；
- Nginx 到本机 Broker 的 TLS 验证。

### 2.5 工程、发布与供应链

审查并加固：

- Node.js 运行时基线；
- Dockerfile 单一来源和锁文件构建；
- GitHub Actions 权限最小化；
- SBOM 针对实际镜像 digest 生成；
- Cosign 精确工作流身份验证；
- SOPS/age 固定版本和 SHA-256 验证；
- CI、双云部署、Release 和 SDK 工作流；
- 用户文档与当前代码的一致性。

## 3. 主要问题与修复

## 3.1 高风险：浏览器 Cookie 会话缺少统一同源写操作边界

**风险：** 攻击站点可能诱导浏览器携带 Broker Cookie 发起状态变更请求。

**修复：**

- 新增 `broker/lib/browser-request.js`；
- Cookie Session 的非安全方法要求精确同源 `Origin`；
- 使用 `Sec-Fetch-Site` 拒绝 cross-site/same-site 不同源请求；
- 浏览器登录响应不再返回可读取的 Session Token；
- CLI 等非浏览器客户端继续支持显式 Token；
- 登录、MFA 登录和退出纳入 Origin 检查。

## 3.2 高风险：管理员客户端密码可能以明文进入配置

**风险：** 管理 API 直接合并密码字段时，可能把明文密码写入 SOPS 配置的解密内存对象，甚至持久化。

**修复：**

- 新增 `broker/lib/client-config.js`；
- API 边界立即将密码转换为 scrypt 哈希；
- 密码最小长度为 12，限制超长输入；
- 启用密码登录时必须存在密码；
- 显式清除密码时同步清除相关时间戳；
- 角色、密码和 ACL 变化后撤销旧会话。

## 3.3 高风险：客户端私钥长期保存在 Broker 主机并可重复下载

**风险：** Broker 主机被入侵、备份泄漏或管理员账号被盗后，可批量导出所有客户端私钥。

**修复：**

- 安全默认下，签发/轮换响应只返回一次 `key_pem` 和一次性 ZIP；
- ZIP 在内存中构建，客户端名称严格校验；
- 返回后删除 Broker 主机上的客户端私钥文件；
- Dashboard 使用内存 Base64 下载，不再使用可重复 GET URL；
- 关闭窗口或五分钟到期后清除敏感 DOM；
- 兼容保留模式仅在 `BROKER_RETAIN_CLIENT_PRIVATE_KEYS=1` 时启用；
- 兼容下载改为 POST，并要求二次验证。

## 3.4 高风险：证书轮换缺少跨文件系统与配置的事务回滚

**风险：** OpenSSL 已替换证书文件、但配置持久化失败时，磁盘证书与允许指纹不一致，导致中断或错误信任状态。

**修复：**

- 轮换前保存旧证书/私钥内存快照；
- 配置持久化失败时恢复原配置和原文件；
- 清除临时 CSR/ext 文件；
- 轮换成功后撤销使用旧指纹创建的会话；
- 客户端删除同步清理其 API Key 和 Session。

## 3.5 高风险：恢复码消费不是持久化事务

**风险：** 恢复码在内存中删除但持久化失败，或操作失败后恢复码状态不一致。

**修复：**

- `verifyMfaCode()` 返回内部恢复元数据；
- 新增 `restoreConsumedRecoveryCode()`；
- 登录、高风险管理操作、证书与 API Key 路径统一执行消费/持久化/回滚；
- 新增 `verifyStepUp()` 统一 TOTP、恢复码和管理员密码验证。

## 3.6 高风险：SSRF、代理头和响应边界

**修复：**

- 新增 `broker/lib/upstream-url.js`，限制协议、Origin、端口和嵌入式凭据；
- 新增 `broker/lib/proxy-headers.js`，阻止客户端覆盖 Host、Authorization、Connection、Transfer-Encoding 和 Broker 注入头；
- 新增响应头过滤，删除 `Set-Cookie` 和 hop-by-hop 头；
- 新增 `broker/lib/proxy-body.js`，限制上游响应体；
- API Key 权限使用 delegated allowlist、Owner Role 与客户端 ACL 的交集。

## 3.7 中高风险：无界内存结构

**风险：** 高基数请求可使限流桶、登录失败、Session 或 MFA pending Map 持续增长。

**修复：**

- 普通请求限流、API Key 限流、Session、登录失败和 MFA pending 均增加容量上限；
- 定期清理过期项；
- 容量耗尽时对新身份失败关闭，不淘汰活跃限流状态；
- Session 增加 8 小时绝对最长寿命。

## 3.8 中风险：MCP HTTP 边界与异常泄漏

**修复：**

- 请求体限制复用共享 HTTP 助手；
- 413 响应显式关闭连接，避免后续 RPC 出现不确定连接状态；
- JSON-RPC batch 默认限制为 50；
- Broker 上游响应默认限制为 16 MiB；
- 上游请求增加超时；
- 工具异常不再把内部路径/错误细节返回给 MCP 客户端；
- 非回环明文监听必须显式配置认证和不安全远程开关。

## 3.9 中风险：阿里云凭据轮转脚本鼓励硬编码并回显密文内容

**修复：**

- 删除脚本内 AccessKey 赋值占位方式；
- 使用隐藏交互输入或环境变量；
- 禁用 Shell trace，使用 `umask 077`；
- 凭据写入受保护临时文件，不进入命令行参数；
- SOPS 加密后原子替换；
- 退出时安全清理明文；
- 验证只检查字段存在，不打印解密值；
- 服务重启后强制检查 active 状态。

## 3.10 中风险：Nginx 共享安全头覆盖 Broker 的路由专用 CSP，且 Origin TLS 未校验

**修复：**

- 移除 Broker vhost 对共享 `_security-headers.conf` 的依赖；
- 边缘层显式统一 DENY、no-referrer、COOP/CORP、Permissions-Policy 和 HSTS；
- CSP 继续由 Broker 根据 HTML、JSON、SSE 类型生成；
- 隐藏 Upstream Server/X-Powered-By；
- `proxy_ssl_verify on`；
- 启用 SNI，并将验证名称固定为 `broker.52trz.com`；
- 使用 Broker CA 作为显式信任链；
- 公共代理配置从四个 location 提取到 server 级。

## 3.11 发布供应链问题

**修复：**

- 生产、开发和依赖阶段统一到 Node.js 24；
- `package.json` 最低版本改为 Node.js 22；
- Docker 构建强制 `package-lock.json + npm ci`；
- 删除过时的 `broker/Dockerfile`，统一根 Dockerfile；
- SOPS 固定 3.13.3，age 固定 1.3.2，并验证哈希；
- Release SBOM 扫描实际镜像 digest；
- Cosign 使用精确仓库、工作流和 Git ref 身份；
- 发布写权限仅授予发布 Job；
- prerelease 不覆盖 `latest`；
- 工作流 YAML 全部纳入解析测试。

## 4. 验证证据

| 验证项 | 结果 |
|---|---|
| `npm run quality:gate` | PASS，退出码 0 |
| ESLint | PASS，无错误 |
| Prettier | PASS |
| MCP 集成回归 | PASS，53/53 |
| HTTP 边界回归 | PASS，48/48 |
| 发布/供应链/Nginx 专项 | PASS，127/127 |
| Python SDK | PASS，28/28 |
| `npm audit --omit=dev --audit-level=high` | PASS，0 vulnerabilities |
| `git diff --check` | PASS |
| Bash 语法：Aliyun 轮转脚本 | PASS |
| Nginx 静态括号与 TLS 不变量 | PASS |
| 受跟踪敏感扩展名检查 | PASS，无输出 |
| 凭据特征扫描 | PASS，无异常生产文件命中 |
| 当前文档相对链接检查 | PASS |
| 线上 `/health` | HTTPS 200，`{"status":"ok"}` |

## 5. 与线上 `broker.52trz.com` 的差异

线上公共健康检查在审计时正常，但返回的安全头仍显示旧策略：

| Header | 线上观察 | 本地加固目标 |
|---|---|---|
| `X-Frame-Options` | `SAMEORIGIN` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `no-referrer` |
| CSP | 通用 `default-src 'self'`，允许 inline script | HTML/JSON/SSE 分类型策略，JSON 为 `default-src 'none'` |
| COOP | 未观察到 | `same-origin` |
| CORP | 未观察到 | `same-origin` |
| Nginx → Broker TLS | 旧配置关闭验证 | 校验 CA、SNI 和域名 |

这说明线上实例尚未部署本轮代码和 Nginx 配置。线上健康正常不能替代新版本的预发布验收。

## 6. 尚未完成的发布门禁

### 6.1 真实生产镜像

ROG 没有 Docker，因此尚未执行：

```bash
docker build --target production -t secret-broker:verify .
```

必须由 CI 或具备 Docker/BuildKit 的环境验证：

- 非 root 用户；
- SOPS/OpenSSL/SSH/Git 等运行时工具存在；
- 镜像中没有 `.key/.pem/.p12/.pfx`；
- 生产入口可启动；
- SBOM、签名和 attestation 对应实际 digest。

### 6.2 Nginx 真实语法和握手

ROG 没有 Nginx，因此仍需在部署机执行：

```bash
nginx -t
```

还必须确认本机 Broker 服务端证书 SAN 包含 `broker.52trz.com`，再 reload Nginx，并验证 Nginx 到 Origin 的 TLS 握手成功。

### 6.3 预发布与回滚

部署前需要：

1. 备份 SOPS 密文、PKI 公共材料、审计链和服务配置；
2. 在预发布实例应用代码和 Nginx 配置；
3. 验证公共 Health、mTLS、Session、MFA、API Key、Proxy、SSH、SSE/WebSocket 和审计；
4. 验证旧证书会话在轮换后立即失效；
5. 验证一次性私钥下载后服务器不再保留客户端 Key；
6. 完成回滚演练后再部署生产。

## 7. 工作区与提交建议

当前工作区包含大量功能修改、测试新增和全局格式化，不能把“测试通过”理解为“适合作为一个提交”。

建议至少拆分为：

1. **Runtime security**：身份、Session、MFA、证书、Proxy、SSH、MCP；
2. **Tests**：新增和更新的回归测试；
3. **Supply chain**：Docker、CI、Release、SBOM、Cosign、工具安装；
4. **Operations**：Nginx、Aliyun 轮转脚本、Gitignore；
5. **Documentation**：README、Quickstart、FAQ、VERIFY；
6. **Formatting-only**：与逻辑无关的 Prettier 变化。

提交前应使用 `git diff -w`、`git add -p` 和逐提交质量门禁减少评审噪声。当前没有任何文件被暂存，也没有执行 commit、push 或部署。

## 8. 最终判定

**本地代码判定：有条件通过，进入发布候选评审。**

通过条件已经满足：

- 代码、格式、全量自动测试、依赖审计和静态安全检查均通过；
- 本轮发现的高风险身份、凭据、证书、Proxy 和发布链问题已有修复与防回归测试。

生产发布仍受以下条件约束：

- Docker 真实镜像构建与运行检查；
- Nginx `-t` 和 Origin TLS 验证；
- 预发布 smoke、回滚和数据兼容验证；
- 大规模差异拆分与人工 Review；
- 明确批准后才能提交、推送或部署。
