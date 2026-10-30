

<!-- project-control-v1:start -->
## Project Control Protocol（2026-09-23）

本段合并本次用户治理决定，仅取代旧文中工程任务/主远端/镜像的冲突约定；其余规则和技术证据保留。
开始工作读取 `.workflow/project.json`、`state.json`、`handoff.json` 以及
`E:\Workspaces\PROJECT-CONTROL-PROTOCOL.md`。具体绑定以 project.json 为准；未确认项为 needs_review，禁止猜测远端。
已确认项目由自托管 GitLab 统一管理 Issue/Milestone/MR/CI/CD/Release/Deployment，GitLab 为主远端，
GitHub 为配置中的镜像或外部协作入口；不复制维护工程任务状态。配置不代表已开启自动镜像。
ChatLink 负责本地执行，Broker 负责凭据/权限，仓库 docs/ 负责技术文档；Notion 仅跨项目/业务知识，Figma 仅设计。
旧 STATUS/ROADMAP/验收文件仍是技术证据入口；未来任务状态引用 GitLab 对象。state/handoff 仅本地缓存/接续，不是第二看板。
不从本地测试推导已提交、已上传、CI 成功、发布或部署。凭据不得写入 workflow；本段不授权生产操作。
本次治理不迁移数据、不创建/关闭真实 Issue/MR、不触发 CI/部署、不改 Git remote、不提交或推送。
<!-- project-control-v1:end -->
