# ChatLink 自托管 GitLab Adapter：Broker 配置候选

状态：离线候选，未导入服务配置、未读取或创建 secret、未改 Broker 运行代码和现有权限。
实现位于 ChatLink runtime-stability 的 `packages/gitlab-adapter/`，不合并商业分支。
参见 [候选配置片段](examples/chatlink-gitlab-read.example.json)。这不是可直接部署的完整 Broker 配置。

## 已核对的现有接口

- `broker/server.js`：`POST /api/v1/proxy/:service` 接受 method/path/query/body；
  校验 service.allow_methods、service.allow_paths、client.allowed_proxy 后才注入凭据。
- `broker/lib/upstream-url.js`：absolute path 会从 origin 根解析；固定 upstream 为
  `https://gitlab.52trz.com`，适配器传完整 `/api/v4/projects/<numeric-id>/...`。
  不放宽 encoded slash、跨 origin、TLS、重定向或错误脱敏限制。
- `broker/can-proxy.js`：`allow_paths: []` 意味着不限制路径，所以候选使用 `(?!)`（拒绝一切）并附离线测试。
- 现有 GitLab 模板默认 GitLab.com；不能把它当作自托管配置已确认。

## 后续只读接入条件

通过现有受权读取确认实例及数字 project ID；每个候选 ID 必须记录实际 API 项目 URL。
绑定 Broker 已管理的只读凭据引用，不把凭据值复制到 ChatLink 或 workflow。
为指定 ChatLink 宿主选择非管理员 mTLS 身份，只允许 `gitlab_rog_read` 服务、GET 方法和确切项目路径。
service 与 client 两层 ACL 都必须限定；不要对现有广泛授权身份只追加新规则而误以为权限收窄。
候选最初 `(?!)` 在两层均拒绝；待确认数字 ID 后可逐条生成严格锚定模式，例如：

```text
^/api/v4/projects/17/(?:issues(?:/[1-9][0-9]*)?|merge_requests(?:/[1-9][0-9]*)?|pipelines(?:/[1-9][0-9]*)?|jobs(?:/[1-9][0-9]*(?:/trace)?)?|releases(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)?|search|milestones(?:/[1-9][0-9]*)?|deployments(?:/[1-9][0-9]*)?)$
```

这里的 17 只是离线测试 ID，绝不是 ROG 真实项目 ID。候选 JSON 不采用此 ID。
上游响应要求 `Accept-Encoding: identity`；压缩响应被适配器明确拒绝。
不要授予 resolve 明文凭据权限；不得在请求/日志/配置中放 PAT。

只读联调也必须分开核验：TLS 身份 → service/ACL → 数字 project ID → 分页与错误行为 → 内容审查。
本次 Git refs 查询不证明这条 API 链路已通。Broker 现有 WIP 保留，未启动服务或接触生产配置。
新公开工具和写操作需要另做宿主鉴权、批准回执、幂等账本和结果读回。
Issue/MR 的创建、关闭、MR 合并、pipeline 触发、job retry/play、release/deployment 写入在本候选均不执行。


## v2 实际接入（取代上文离线候选状态）
本轮用户授权独立演示项目实际验收。GitLab 3–9 已配置项目级 Reporter/read_api token，项目 10 为独立演示 Maintainer/api token。凭据仅存 Broker，通过 Windows 证书库 mTLS + PoP 访问，不导出私钥，不在 workflow 中保存 token。
服务名 gitlab-pc-<数字ID>，严格匹配各自 /api/v4/projects/<ID> 路径。运行版本实际字段是 allowed_methods；3–9 为 GET，10 为 GET/POST/PUT，已读回确认。上文 allow_methods 是本地开发分支字段，不能直接假定适用于当前部署。
入口 E:\Workspaces\Project-Control.ps1；ChatLink 通过现有命令执行能力运行，不新增公开 MCP 工具。实现和测试见 runtime-stability/packages/gitlab-adapter/ENABLED-ROG.md。用户对本轮测试的授权不扩大既有生产项目写权限。
当前复用已有管理员 Windows 证书；服务/项目token限制此集成调用，但并未将该身份的全部权限降为最小权限。后续独立自动化身份应走正常 Broker 身份注册及二次认证，不通过修改服务器配置绕过。



## Final live authorization finding (2026-09-23)
The running Broker admin client bypasses service path ACLs. A cross-project GET through gitlab-pc-3 reached GitLab and returned 404 because its project token cannot view project 4. Thus path ACL configuration is not claimed as an enforced boundary for this identity. The adapter fixes request paths, Broker enforces allowed_methods, and project tokens enforce project/read scopes. A dedicated non-admin identity or a separately reviewed Broker hardening deployment is still needed for independent Broker path enforcement. No security policy was disabled.
