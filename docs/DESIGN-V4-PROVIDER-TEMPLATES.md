# Secret Broker V4 — Provider Templates Library

> **本文档**:V4 服务商模板库完整设计
> **基础**:v3.0 6 个内置模板 + 30+ type schemas
> **目标**:**40+ 服务商模板,全部从官网拉最新格式**
> **覆盖**:代码平台 / AI 服务 / 云厂商 / 容器 / CDN / 支付 / 通信 / 数据库 / 监控 / SSH

---

## 目录

1. [设计目标](#1-设计目标)
2. [模板元数据 Schema](#2-模板元数据-schema)
3. [SDK Sync — 官网自动同步](#3-sdk-sync--官网自动同步)
4. [Type Schema 完整设计](#4-type-schema-完整设计)
5. [签名算法库](#5-签名算法库)
6. [40+ 服务商模板详解](#6-40-服务商模板详解)
7. [自定义模板](#7-自定义模板)
8. [模板版本与升级](#8-模板版本与升级)
9. [测试矩阵](#9-测试矩阵)

---

## 1. 设计目标

### 1.1 量化指标

| 指标 | 目标 |
|---|---|
| 模板数量 | 40+ 内置(代码/AI/云/容器/CDN/支付/通信/数据库/监控) |
| 同步频率 | SDK Sync 每 30 天自动跑一次;PR 形式更新 |
| 接入新服务商 | < 5 行 YAML(基于现有类型) |
| 同步失败检测 | 模板标记 `stale`,Dashboard 红点告警 |
| 协议升级 | GitHub/Anthropic 等 API 变更 1 周内同步 |

### 1.2 与 v3 差异

| 项 | v3.8 | V4 |
|---|---|---|
| 内置模板 | 6 | **40+** |
| 模板元数据 | 简陋 | **结构化** (含 provider/docs/sig_alg/version) |
| 同步 | 手工 | **SDK Sync 自动从官网拉** |
| 签名算法 | 3 (bearer / aliyun_v2 / tencent_v3) | **10+** (含 AWS SigV4 / GCP JWT / Cloudflare / Docker) |
| 自定义 | 弱 | **强** (任意 OpenAPI 可一键生成) |
| 版本化 | 无 | **每模板带 version + last_synced_at** |

---

## 2. 模板元数据 Schema

### 2.1 完整定义

```javascript
// broker/lib/provider-template.js
export const providerTemplateSchema = {
  // 基本
  id: 'github',                          // kebab-case,全局唯一
  display_name: 'GitHub API',
  provider: 'GitHub, Inc.',
  category: 'code_platform',             // 见 § 2.3
  icon: '🐙',
  description: 'GitHub REST API with PAT/OAuth/GitHub App',
  official_docs_url: 'https://docs.github.com/en/rest',
  last_synced_at: '2026-09-01T00:00:00Z',
  template_version: '2025-Q3',

  // 认证
  auth_type: 'bearer',                   // 签名算法 ID
  default_secret_type: 'github_pat',     // 默认绑定的 secret type
  default_secret_field: 'token',         // 从 secret 哪个字段取
  upstream: 'https://api.github.com',
  inject_headers: {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'secret-broker/4.0',
  },

  // ACL
  allow_methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  default_allow_paths: ['.*'],           // 默认允许的 path 正则

  // Dashboard 快捷操作
  default_actions: [
    { label: '我的信息', method: 'GET', path: '/user', description: 'Get authenticated user' },
    { label: '我的仓库', method: 'GET', path: '/user/repos', query: { per_page: '5' } },
  ],

  // 健康检查
  healthcheck: {
    method: 'GET',
    path: '/user',
    expect_status: 200,
    timeout_ms: 5000,
  },

  // 元数据
  tags: ['scm', 'git', 'oauth', 'rest'],
  notes: '支持 classic PAT (ghp_)、fine-grained PAT (github_pat_)、GitHub App JWT',
  deprecation: null,                     // { since: '2024-12-31', message: '...' }
};
```

### 2.2 auth_type 列表(V4 签名算法库)

| ID | 算法 | 适用 |
|---|---|---|
| `bearer` | Authorization: Bearer <token> | GitHub, OpenAI, Anthropic, etc. |
| `basic` | Authorization: Basic base64(user:pass) | Docker Hub, etc. |
| `header` | 自定义 header 模板 | 任意 |
| `query` | Token 放 query string | 少数老 API |
| `aliyun_v2` | 阿里云 API v2 签名 (HMAC-SHA1) | 阿里云 OpenAPI |
| `aliyun_v3` | 阿里云 API v3 签名 | 阿里云新 API |
| `tencent_v3` | 腾讯云 TC3-HMAC-SHA256 | 腾讯云 OpenAPI |
| `aws_sigv4` | AWS Signature Version 4 | AWS 全家桶 |
| `gcp_jwt` | GCP Service Account JWT | GCP |
| `azure_ad` | Azure AD OAuth2 | Azure |
| `cloudflare` | Cloudflare API Token | Cloudflare |
| `docker_registry` | Docker Registry V2 Bearer | Docker Hub / 私有 registry |
| `wechat_pay` | 微信支付 V3 签名 | 微信支付 |
| `ssh_proxy` | SSH 代理 | V4 新增 |

### 2.3 分类列表

```javascript
export const CATEGORIES = {
  code_platform: { label: '代码平台', icon: '🐙' },
  ai_service: { label: 'AI 服务', icon: '🤖' },
  cloud_cn: { label: '云厂商 - 中国', icon: '☁️' },
  cloud_global: { label: '云厂商 - 国际', icon: '🌐' },
  container_registry: { label: '容器镜像', icon: '📦' },
  cdn_dns: { label: 'CDN/DNS', icon: '🌍' },
  payment: { label: '支付', icon: '💳' },
  communication: { label: '通信', icon: '💬' },
  database: { label: '数据库', icon: '🗄️' },
  monitoring: { label: '监控', icon: '📊' },
  ssh: { label: 'SSH', icon: '🛠️' },
  custom: { label: '自定义', icon: '⚙️' },
};
```

---

## 3. SDK Sync — 官网自动同步

### 3.1 设计目标

V4 **不**靠手写 40+ 模板。设计一个 `secret-broker sync-templates` 工具:

1. **从 OpenAPI 拉** — 如果服务商提供 OpenAPI 3.x,直接解析
2. **从官方 curl 例子提取** — 拉 docs 页,正则提取 `curl` blocks
3. **从 SDK 源码反推** — Python/Node SDK 的 constants 模块
4. **PR 形式更新** — 跑完生成 `templates-sync-<date>.yaml`,PR review 后合并

### 3.2 实现

```bash
# 命令
secret-broker sync-templates
# → 拉 30+ 官方 URL
# → 解析 OpenAPI / curl / SDK
# → diff 当前模板
# → 生成新模板 draft
# → 写入 docs/TEMPLATES-SYNC-<date>.md(PR 描述)
# → 邮件/Slack 通知 review
```

```javascript
// broker/bin/sync-templates.js
const SYNC_SOURCES = [
  {
    provider: 'github',
    type: 'openapi',
    url: 'https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json',
  },
  {
    provider: 'openai',
    type: 'openapi',
    url: 'https://app.stainless.com/api/v0/specs/openai/openapi.yml',
  },
  {
    provider: 'anthropic',
    type: 'docs_curl',
    url: 'https://docs.anthropic.com/en/api/getting-started',
    parser: 'anthropic_curl',
  },
  // ... 30+ 来源
];
```

### 3.3 同步策略

- **OpenAPI 直接 parse** (优先)
- **官方 curl 例子提取**:用 cheerio / jsdom 解析 HTML
- **每月 1 号自动跑**(`cron` + 邮件)
- **diff 显示在 dashboard**
- **stale > 90 天的模板**标红告警

---

## 4. Type Schema 完整设计

### 4.1 现有 type schemas (v3) 30+ 个

继承 v3 的 30+ 类型,新增 20+ 类型,达到 **50+ 类型**。

### 4.2 新增 Type Schema 列表(V4)

| ID | 名称 | 关键字段 | 官方获取地址 |
|---|---|---|---|
| `docker_hub_pat` | Docker Hub Personal Access Token | `username`, `pat` | hub.docker.com/settings/security |
| `aws_access_key_v2` | AWS Access Key (含 STS 临时凭证) | `access_key_id`, `secret_access_key`, `session_token` (optional), `region` | aws.amazon.com/iam |
| `azure_tenant` | Azure Tenant (App Registration) | `tenant_id`, `client_id`, `client_secret`, `subscription_id` | portal.azure.com |
| `gcp_service_account_v2` | GCP Service Account (含 Workload Identity) | `credentials_json`, `project_id`, `use_workload_identity` (bool) | console.cloud.google.com |
| `oracle_cloud` | Oracle Cloud API Key | `user_ocid`, `tenancy_ocid`, `fingerprint`, `private_key`, `region` | cloud.oracle.com |
| `digitalocean` | DigitalOcean PAT | `api_token` | cloud.digitalocean.com/account/api |
| `github_app` | GitHub App (替代 PAT) | `app_id`, `installation_id`, `private_key` | github.com/settings/apps |
| `anthropic_admin_key` | Anthropic Admin Key (Workspace admin) | `admin_key` | console.anthropic.com |
| `google_oauth` | Google OAuth2 (含 refresh_token) | `client_id`, `client_secret`, `refresh_token`, `access_token` (optional) | console.cloud.google.com |
| `azure_storage` | Azure Storage Account | `account_name`, `account_key`, `connection_string` | portal.azure.com |
| `wechat_miniprogram` | 微信小程序 | `app_id`, `app_secret` | mp.weixin.qq.com |
| `alipay_key` | 支付宝密钥 | `app_id`, `private_key`, `alipay_public_key` | open.alipay.com |
| `dingtalk_app` | 钉钉应用凭证 | `app_key`, `app_secret`, `agent_id` | open-dev.dingtalk.com |
| `feishu_app` | 飞书应用凭证 | `app_id`, `app_secret` | open.feishu.cn |
| `ssh_jump_host` | SSH 跳板(V4 新增) | `jump_host`, `jump_user`, `jump_key`, `target_user`, `target_host` | 自定义 |
| `gcp_oauth_token` | GCP OAuth Access Token (短命) | `access_token`, `expires_at`, `refresh_token` | console.cloud.google.com |
| `azure_sas_token` | Azure SAS Token | `sas_token`, `storage_account` | portal.azure.com |
| `npm_token` | NPM Publish Token | `token` | npmjs.com |
| `pypi_token` | PyPI API Token | `token` | pypi.org/manage/account |
| `homebrew_tap` | Homebrew Tap Git Token | `git_token` | github.com/settings/tokens |

### 4.3 Type Schema 增强(V4)

```javascript
{
  id: 'github_pat',
  label: 'GitHub Personal Access Token',
  description: 'https://github.com/settings/tokens — 选 classic, scope 按需',
  fields: [
    {
      name: 'token',
      label: 'Token',
      kind: 'textarea',
      required: true,
      sensitive: true,
      placeholder: 'ghp_... or github_pat_...',  // V4: 支持 fine-grained
      validation_regex: '^(ghp_|github_pat_)[a-zA-Z0-9_]+$',  // V4 新增
      help: 'classic (ghp_) or fine-grained (github_pat_)',
      doc_url: 'https://github.com/settings/tokens',
    },
  ],
  // V4 新增
  recommended_provider_template: 'github',  // 自动选模板
  rotate_recommendation_days: 90,
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  v4_meta: {
    source: 'https://github.com/settings/tokens',
    last_synced: '2026-09-01',
    official_doc_version: '2025-09',
  },
}
```

---

## 5. 签名算法库

### 5.1 目录结构

```
broker/signing/
├── aliyun-v2.js          # 阿里云 API v2 (HMAC-SHA1, query string)
├── aliyun-v3.js          # 阿里云 API v3 (HMAC-SHA256, header)
├── tencent-v3.js         # 腾讯云 TC3-HMAC-SHA256
├── aws-sigv4.js          # AWS Signature Version 4
├── gcp-jwt.js            # GCP Service Account JWT
├── azure-ad.js           # Azure AD OAuth2
├── cloudflare.js         # Cloudflare (Bearer)
├── docker-registry.js    # Docker Registry V2
├── wechat-pay-v3.js      # 微信支付 V3
├── ssh-proxy.js          # SSH 跳板
└── index.js              # 注册表
```

### 5.2 阿里云 V2 签名(关键)

```javascript
// broker/signing/aliyun-v2.js
import { createHmac } from 'node:crypto';

export function signAliyunV2({ method, url, query, body, secret }) {
  const u = new URL(url);
  const params = new URLSearchParams({ ...query });
  params.sort();
  // 1. Canonicalized Query String
  const sorted = [...params.entries()].map(([k, v]) =>
    `${encodeURIComponent(k)}=${encodeURIComponent(v)}`
  ).join('&');

  // 2. StringToSign
  const stringToSign = `${method.toUpperCase()}&${encodeURIComponent('/')}&${encodeURIComponent(sorted)}`;

  // 3. Signature
  const signature = createHmac('sha1', `${secret.access_key_secret}&`)
    .update(stringToSign)
    .digest('base64');

  // 4. 加 signature 到 query
  params.set('Signature', signature);
  return `${u.origin}${u.pathname}?${params.toString()}`;
}
```

### 5.3 腾讯云 TC3 签名

```javascript
// broker/signing/tencent-v3.js
import { createHmac, createHash } from 'node:crypto';

export function signTencentV3({ method, host, path, query, body, headers, secret, service, version, action, region, timestamp }) {
  // 1. Canonical Request
  const canonicalHeaders = Object.entries(headers)
    .filter(([k]) => ['content-type', 'host'].includes(k.toLowerCase()))
    .sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase()))
    .map(([k, v]) => `${k.toLowerCase()}:${v.trim()}\n`)
    .join('');
  const signedHeaders = Object.keys(JSON.parse(`{${canonicalHeaders.replace(/\n/g, ',')}}`)).join(';');

  const hashedPayload = createHash('sha256').update(body || '').digest('hex');
  const canonicalRequest = [
    method.toUpperCase(),
    path,
    new URLSearchParams(query).toString(),
    canonicalHeaders,
    signedHeaders,
    hashedPayload,
  ].join('\n');

  // 2. String to Sign
  const date = new Date(timestamp * 1000).toISOString().split('T')[0];
  const credentialScope = `${date}/${service}/tc3_request`;
  const hashedCanonicalRequest = createHash('sha256').update(canonicalRequest).digest('hex');
  const stringToSign = [
    'TC3-HMAC-SHA256',
    timestamp,
    credentialScope,
    hashedCanonicalRequest,
  ].join('\n');

  // 3. Signing Key
  const secretDate = createHmac('sha256', 'TC3' + secret.secret_key).update(date).digest();
  const secretService = createHmac('sha256', secretDate).update(service).digest();
  const secretSigning = createHmac('sha256', secretService).update('tc3_request').digest();

  // 4. Signature
  const signature = createHmac('sha256', secretSigning).update(stringToSign).digest('hex');

  // 5. Authorization
  return `${algorithm} Credential=${secret.secret_id}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}
```

### 5.4 AWS SigV4

```javascript
// broker/signing/aws-sigv4.js
import { createHmac, createHash } from 'node:crypto';

export function signAwsSigV4({ method, host, path, query, body, headers, secret, service, region, timestamp }) {
  // 1. Canonical Request
  const canonicalUri = path || '/';
  const canonicalQuery = canonicalQueryString(query);
  const canonicalHeaders = `${Object.entries({ host, ...headers })
    .sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase()))
    .map(([k, v]) => `${k.toLowerCase()}:${v.trim()}\n`)
    .join('')}`;
  const signedHeaders = Object.keys({ host, ...headers })
    .map(k => k.toLowerCase())
    .sort()
    .join(';');
  const payloadHash = createHash('sha256').update(body || '').digest('hex');

  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // 2. String to Sign
  const amzDate = formatAmzDate(timestamp);
  const dateStamp = amzDate.split('T')[0];
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  // 3. Signing Key
  const kDate = createHmac('sha256', 'AWS4' + secret.secret_access_key).update(dateStamp).digest();
  const kRegion = createHmac('sha256', kDate).update(region).digest();
  const kService = createHmac('sha256', kRegion).update(service).digest();
  const kSigning = createHmac('sha256', kService).update('aws4_request').digest();

  // 4. Signature
  const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  // 5. Authorization Header
  return {
    Authorization: `AWS4-HMAC-SHA256 Credential=${secret.access_key_id}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    'X-Amz-Date': amzDate,
  };
}
```

---

## 6. 40+ 服务商模板详解

### 6.1 代码平台(4)

#### github (官方文档:docs.github.com/en/rest)

```javascript
{
  id: 'github',
  display_name: 'GitHub API',
  provider: 'GitHub, Inc.',
  category: 'code_platform',
  auth_type: 'bearer',
  default_secret_type: 'github_pat',
  upstream: 'https://api.github.com',
  inject_headers: {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'secret-broker/4.0',
  },
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  default_actions: [
    { label: '我的信息', method: 'GET', path: '/user' },
    { label: '我的仓库', method: 'GET', path: '/user/repos', query: { per_page: '5' } },
    { label: '我的 Gist', method: 'GET', path: '/gists' },
  ],
  notes: '支持 classic (ghp_), fine-grained (github_pat_), GitHub App JWT',
  last_synced_at: '2026-09-01',
  template_version: '2025-Q3',
  official_docs_url: 'https://docs.github.com/en/rest',
}
```

#### gitlab

```javascript
{
  id: 'gitlab',
  display_name: 'GitLab API',
  provider: 'GitLab Inc.',
  category: 'code_platform',
  auth_type: 'bearer',
  default_secret_type: 'gitlab_pat',
  upstream: 'https://gitlab.com/api/v4',
  inject_headers: { 'User-Agent': 'secret-broker/4.0' },
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  default_actions: [
    { label: '当前用户', method: 'GET', path: '/user' },
    { label: '我的项目', method: 'GET', path: '/projects', query: { membership: 'true', per_page: '5' } },
  ],
  official_docs_url: 'https://docs.gitlab.com/ee/api/',
  template_version: '2025-Q3',
}
```

#### gitee (国内)

```javascript
{
  id: 'gitee',
  display_name: 'Gitee API',
  provider: 'Gitee (码云)',
  category: 'code_platform',
  auth_type: 'bearer',
  default_secret_type: 'gitee_pat',
  upstream: 'https://gitee.com/api/v5',
  inject_headers: { 'User-Agent': 'secret-broker/4.0' },
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  default_actions: [
    { label: '当前用户', method: 'GET', path: '/user' },
    { label: '我的仓库', method: 'GET', path: '/user/repos', query: { per_page: '5' } },
  ],
  official_docs_url: 'https://gitee.com/api/v5/swagger',
  template_version: '2025-Q3',
}
```

#### bitbucket

```javascript
{
  id: 'bitbucket',
  display_name: 'Bitbucket API',
  provider: 'Atlassian',
  category: 'code_platform',
  auth_type: 'basic',  // Basic auth
  default_secret_type: 'bitbucket_app_password',
  upstream: 'https://api.bitbucket.org/2.0',
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  default_actions: [
    { label: '当前用户', method: 'GET', path: '/user' },
    { label: '我的仓库', method: 'GET', path: '/repositories/{workspace}' },
  ],
  official_docs_url: 'https://developer.atlassian.com/cloud/bitbucket/rest/',
  template_version: '2025-Q3',
}
```

### 6.2 AI 服务(8)

#### openai (官网:platform.openai.com/docs)

```javascript
{
  id: 'openai',
  display_name: 'OpenAI API',
  provider: 'OpenAI',
  category: 'ai_service',
  auth_type: 'bearer',
  default_secret_type: 'openai_key',
  upstream: 'https://api.openai.com',
  inject_headers: {
    'User-Agent': 'secret-broker/4.0',
    'OpenAI-Organization': '{{secret.openai_key.organization}}',  // 可选 org
    'OpenAI-Project': '{{secret.openai_key.project}}',            // 可选 project
  },
  healthcheck: { method: 'GET', path: '/v1/models', expect_status: 200 },
  default_actions: [
    { label: '模型列表', method: 'GET', path: '/v1/models' },
    { label: '简单对话', method: 'POST', path: '/v1/chat/completions' },
  ],
  official_docs_url: 'https://platform.openai.com/docs/api-reference',
  template_version: '2025-09',
  notes: 'V4 支持 project keys (sk-proj-...) 和 user keys (sk-...)',
}
```

#### anthropic (官网:docs.anthropic.com)

```javascript
{
  id: 'anthropic',
  display_name: 'Anthropic API (Claude)',
  provider: 'Anthropic',
  category: 'ai_service',
  auth_type: 'header',  // x-api-key + anthropic-version
  default_secret_type: 'anthropic_key',
  upstream: 'https://api.anthropic.com',
  inject_headers: {
    'x-api-key': '{{secret.anthropic_key.api_key}}',
    'anthropic-version': '2023-06-01',
    'content-type': 'application/json',
  },
  healthcheck: { method: 'POST', path: '/v1/messages', body: { model: 'claude-3-5-haiku-20241022', max_tokens: 1, messages: [{ role: 'user', content: 'hi' }] } },
  default_actions: [
    { label: '简单对话', method: 'POST', path: '/v1/messages' },
  ],
  official_docs_url: 'https://docs.anthropic.com/en/api',
  template_version: '2025-10',
  notes: 'API key 格式:sk-ant-api03-...',
}
```

#### gemini (Google AI)

```javascript
{
  id: 'gemini',
  display_name: 'Google AI (Gemini)',
  provider: 'Google',
  category: 'ai_service',
  auth_type: 'query',  // ?key=xxx
  default_secret_type: 'google_ai_key',
  upstream: 'https://generativelanguage.googleapis.com',
  healthcheck: { method: 'GET', path: '/v1beta/models?key={{secret.google_ai_key.api_key}}', expect_status: 200 },
  default_actions: [
    { label: '列出模型', method: 'GET', path: '/v1beta/models' },
    { label: '生成文本', method: 'POST', path: '/v1beta/models/gemini-pro:generateContent' },
  ],
  official_docs_url: 'https://ai.google.dev/api',
  template_version: '2025-Q3',
}
```

#### mistral / cohere / deepseek / zhipu / moonshot / qwen

类似结构,具体字段从各自官网 OpenAPI / docs 拉取。

### 6.3 云厂商 - 中国(6)

#### aliyun_ecs (OpenAPI:ecs.aliyuncs.com)

```javascript
{
  id: 'aliyun_ecs',
  display_name: '阿里云 ECS OpenAPI',
  provider: 'Alibaba Cloud',
  category: 'cloud_cn',
  auth_type: 'aliyun_v2',
  default_secret_type: 'aliyun_ak',
  upstream: 'https://ecs.aliyuncs.com',
  default_region: 'cn-hangzhou',
  healthcheck: { method: 'GET', path: '/?Action=DescribeRegions', expect_status: 200 },
  default_actions: [
    { label: '列 ECS 实例', method: 'GET', path: '/?Action=DescribeInstances&RegionId=cn-hangzhou' },
    { label: '列云盘', method: 'GET', path: '/?Action=DescribeDisks&RegionId=cn-hangzhou' },
    { label: '列 EIP', method: 'GET', path: '/?Action=DescribeEipAddresses&RegionId=cn-hangzhou' },
  ],
  allow_products: ['ECS', 'VPC', 'SLB'],
  official_docs_url: 'https://help.aliyun.com/document_detail/25484.html',
  template_version: '2025-Q3',
  notes: '建议使用 RAM 用户 AK + AliyunAPIAccessRole 最小权限',
}
```

#### aliyun_oss (新模板,覆盖对象存储)

```javascript
{
  id: 'aliyun_oss',
  display_name: '阿里云 OSS (Object Storage)',
  provider: 'Alibaba Cloud',
  category: 'cloud_cn',
  auth_type: 'aliyun_v2',
  default_secret_type: 'aliyun_oss',
  upstream: 'https://oss-cn-hangzhou.aliyuncs.com',  // 由 secret.endpoint 覆盖
  healthcheck: { method: 'GET', path: '/?list-type=2&max-keys=1', expect_status: 200 },
  notes: 'endpoint 来自 secret.endpoint;签名时 host 用 endpoint 替换默认',
}
```

#### tencent_cvm / tencent_cos / tencent_tcr

类似 aliyun,使用 `tencent_v3` 签名,TC3-HMAC-SHA256。

### 6.4 云厂商 - 国际(5)

#### aws (通用)

```javascript
{
  id: 'aws',
  display_name: 'AWS API (通用)',
  provider: 'Amazon Web Services',
  category: 'cloud_global',
  auth_type: 'aws_sigv4',
  default_secret_type: 'aws_access_key_v2',
  upstream: 'https://ec2.amazonaws.com',  // 可由 service+region 动态生成
  healthcheck: { method: 'GET', path: '/', expect_status: 400 },  // AWS 没健康检查端点
  notes: '所有 AWS 服务共享此模板,service 字段决定签名',
}
```

#### gcp (通用)

```javascript
{
  id: 'gcp',
  display_name: 'Google Cloud API',
  provider: 'Google Cloud',
  category: 'cloud_global',
  auth_type: 'gcp_jwt',
  default_secret_type: 'gcp_service_account_v2',
  upstream: 'https://compute.googleapis.com',
  notes: 'V4 推荐 Workload Identity,broker 自动取短命 token',
}
```

#### azure / oracle / digitalocean

类似结构,签名不同。

### 6.5 容器镜像(4)

#### docker_hub

```javascript
{
  id: 'docker_hub',
  display_name: 'Docker Hub',
  provider: 'Docker Inc.',
  category: 'container_registry',
  auth_type: 'docker_registry',
  default_secret_type: 'docker_hub_pat',
  upstream: 'https://registry-1.docker.io',
  inject_headers: { 'User-Agent': 'secret-broker/4.0' },
  notes: '支持 PAT + Personal Access Token (2025 新)',
  healthcheck: { method: 'GET', path: '/v2/', expect_status: 401 },  // 必须 401 表示服务在
}
```

#### ghcr (GitHub Container Registry)

```javascript
{
  id: 'ghcr',
  display_name: 'GitHub Container Registry',
  provider: 'GitHub',
  category: 'container_registry',
  auth_type: 'bearer',
  default_secret_type: 'github_pat',  // 复用 GitHub PAT
  upstream: 'https://ghcr.io',
  notes: '用 GitHub PAT 即可,scope 需 read:packages',
}
```

#### quay / harbor

类似结构。

### 6.6 CDN/DNS(3)

#### cloudflare

```javascript
{
  id: 'cloudflare',
  display_name: 'Cloudflare API',
  provider: 'Cloudflare',
  category: 'cdn_dns',
  auth_type: 'bearer',
  default_secret_type: 'cloudflare_token',
  upstream: 'https://api.cloudflare.com/client/v4',
  inject_headers: { 'Content-Type': 'application/json' },
  healthcheck: { method: 'GET', path: '/user', expect_status: 200 },
  default_actions: [
    { label: '验证 Token', method: 'GET', path: '/user' },
    { label: '列出 Zones', method: 'GET', path: '/zones', query: { per_page: '50' } },
    { label: '列出 Tunnels', method: 'GET', path: '/accounts/{{secret.cloudflare_token.account_id}}/tunnels?status=active' },
  ],
  official_docs_url: 'https://developers.cloudflare.com/api/',
  template_version: '2025-Q3',
  notes: 'API token 最小权限:Zone:DNS:Edit + Account:Cloudflare Tunnel:Edit',
}
```

#### alidns (阿里云 DNS)

`auth_type: 'aliyun_v2'`,upstream `https://alidns.aliyuncs.com`。

#### tencent_cdn

类似。

### 6.7 支付(2)

#### stripe

```javascript
{
  id: 'stripe',
  display_name: 'Stripe API',
  provider: 'Stripe',
  category: 'payment',
  auth_type: 'bearer',
  default_secret_type: 'stripe_secret_key',
  upstream: 'https://api.stripe.com',
  healthcheck: { method: 'GET', path: '/v1/balance', expect_status: 200 },
  default_actions: [
    { label: '账户余额', method: 'GET', path: '/v1/balance' },
    { label: '列出支付', method: 'GET', path: '/v1/charges', query: { limit: '3' } },
  ],
  notes: 'sk_live_ / sk_test_ 区分',
}
```

#### wechat_pay (微信支付 V3)

```javascript
{
  id: 'wechat_pay',
  display_name: '微信支付 V3',
  provider: '腾讯(微信支付)',
  category: 'payment',
  auth_type: 'wechat_pay',
  default_secret_type: 'wechat_pay_key',
  upstream: 'https://api.mch.weixin.qq.com',
  notes: 'RSA 签名,需要商户私钥 + 证书序列号',
}
```

### 6.8 通信(6)

#### slack_webhook / discord_webhook / feishu_webhook / dingtalk_webhook / telegram / sendgrid

`auth_type: 'bearer' 或 'webhook'`,结构清晰。

### 6.9 数据库(4)

#### postgresql / mysql / redis / mongodb

这些不是 HTTP API,而是 **直接连接**。V4 设计为 broker **作为 proxy 接受 SQL/命令**:

```javascript
{
  id: 'postgresql_proxy',
  display_name: 'PostgreSQL (via broker)',
  provider: 'PostgreSQL',
  category: 'database',
  auth_type: 'db_proxy',  // 特殊模式
  default_secret_type: 'database_url_pg',
  // broker 实际监听 15432 端口,接受 PG 协议
  proxy_listen_port: 15432,
  notes: 'AI 通过 mTLS 连 broker:15432,broker 转发到真实 PG',
}
```

### 6.10 监控(3)

#### sentry / datadog / new_relic

`auth_type: 'bearer'`,默认 actions 看 issues/events。

### 6.11 SSH(1)

#### ssh_proxy (V4 新增)

```javascript
{
  id: 'ssh_proxy',
  display_name: 'SSH Proxy (jump host)',
  provider: 'generic',
  category: 'ssh',
  auth_type: 'ssh_proxy',
  default_secret_type: 'ssh_connection',
  proxy_listen_port: 7222,
  notes: 'AI 通过 SSH 客户端连 broker:7222,broker 转发到目标主机',
  features: [
    'audit 每次 ssh 命令',
    '凭据零接触(只发命令,不发密钥)',
    '支持密钥/密码两种认证',
    '支持跳板(SSH-over-SSH)',
  ],
}
```

### 6.12 自定义(1)

#### generic_https

```javascript
{
  id: 'generic_https',
  display_name: 'Generic HTTPS (Custom)',
  category: 'custom',
  auth_type: 'header',
  default_secret_type: 'custom',
  upstream: 'https://example.com',
  inject_headers: { 'User-Agent': 'secret-broker/4.0' },
  header_name: 'Authorization',
  header_value_template: 'Bearer {{secret.<name>.value}}',
  notes: '任意 upstream + 自定义 header 模板 + 自定义 actions',
}
```

---

## 7. 自定义模板

### 7.1 从 OpenAPI 生成

```bash
# 任意 OpenAPI 3.x 一键生成模板
secret-broker template generate --from-openapi https://api.example.com/openapi.json
# → 解析所有 endpoint
# → 自动选 auth_type(从 securitySchemes)
# → 生成 dashboard_actions
# → 输出 broker.yaml 片段
# → 写入 broker/templates/my-service.yaml
```

### 7.2 从 curl 例子生成

```bash
# 粘贴 curl 命令,自动识别
secret-broker template generate --from-curl "$(cat example.sh)"
# → 解析 URL / method / headers
# → 识别认证 header
# → 输出模板 draft
```

### 7.3 完全自定义(YAML)

```yaml
# broker.yaml
services:
  my_custom_service:
    type: custom
    template: my-template
    secret: my_secret
    upstream: https://api.example.com
    inject_headers:
      X-Custom-Auth: 'Bearer {{secret.my_secret.token}}'
    healthcheck:
      method: GET
      path: /health
```

---

## 8. 模板版本与升级

### 8.1 版本号

每模板带 `template_version`(如 `2025-Q3`、`2025-10-15`):

```javascript
{
  id: 'github',
  template_version: '2025-Q3',
  last_synced_at: '2026-09-01T00:00:00Z',
}
```

### 8.2 升级流程

```bash
# 查看过期模板
secret-broker template list --stale
# github (v2025-Q1, 6 months ago) ⚠️ stale
# openai (v2025-Q2, 3 months ago)

# 升级
secret-broker template upgrade github
# → 拉最新 OpenAPI
# → diff 现有模板
# → 生成 PR
# → 通知 review

# 强制升级所有
secret-broker template upgrade --all
```

### 8.3 仪表板

`/admin/templates` 页面:
- 列表:每个模板的版本/最后同步/状态
- 标记 stale (>90 天)
- 一键升级
- 显示 diff

---

## 9. 测试矩阵

### 9.1 每个模板必须通过的测试

| # | 测试 | 覆盖 |
|---|---|---|
| 1 | 模板 schema 校验 | 元数据完整 |
| 2 | upstream 健康检查(无 key) | 200/401/403/400 之一 |
| 3 | 注入正确(用 test secret) | 签名/header 正确 |
| 4 | 真实 API 调用(smoke) | 至少 1 个默认 action 跑通 |
| 5 | secret 缺失时报错 | "secret_not_found" |
| 6 | secret 过期时阻断 | "secret_expired" |
| 7 | rate limit 生效 | 100/hour 触发 429 |
| 8 | audit 日志含正确 action | "proxy.github" / status 200 |

### 9.2 自动 smoke 测

```bash
# broker 启动时跑
secret-broker template smoke github openai aliyun_ecs ...
# → 真实调 1 次 /user
# → 失败 1 次:标记模板 degraded
# → 全部失败:启动失败
```

### 9.3 端到端 CI

```yaml
# .github/workflows/template-smoke.yml
on:
  schedule: { cron: '0 4 * * *' }  # 每天
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/template-smoke.sh
        env:
          GITHUB_PAT: ${{ secrets.GITHUB_PAT }}
          OPENAI_KEY: ${{ secrets.OPENAI_KEY }}
          # ... 40 个 secret
```

---

## 附录 A:阿里云签名完整规范(摘自官网)

参考 [阿里云 API 网关签名机制](https://help.aliyun.com/document_detail/29442.html):

```
1. 公共参数:
   Format=JSON
   Version=2014-05-26
   AccessKeyId=...
   SignatureMethod=HMAC-SHA1
   Timestamp=2006-01-02T15:04:05Z
   SignatureVersion=1.0
   SignatureNonce=...

2. Canonicalized Query String:
   按参数名 ASCII 升序,URL encode 后用 = 和 & 拼接

3. StringToSign:
   HTTPMethod + "&" + encodeURIComponent("/") + "&" + encodeURIComponent(CanonicalizedQueryString)

4. Signature:
   base64(hmac-sha1(StringToSign, AccessKeySecret + "&"))

5. URL = upstream + ? + all-params + Signature
```

V4 `signing/aliyun-v2.js` 完整实现此流程。

## 附录 B:腾讯云 TC3 签名规范

参考 [腾讯云签名 v3](https://cloud.tencent.com/document/api/1723/8438):

```
1. 拼接 CanonicalRequest:
   HTTPRequestMethod
   CanonicalURI
   CanonicalQueryString
   CanonicalHeaders
   SignedHeaders
   HashedRequestPayload

2. 拼 StringToSign:
   TC3-HMAC-SHA256
   RequestTimestamp
   CredentialScope (= Date/Service/tc3_request)
   HashedCanonicalRequest

3. 计算 SecretKey:
   SecretDate = HMAC-SHA256("TC3" + SecretKey, Date)
   SecretService = HMAC-SHA256(SecretDate, Service)
   SecretSigning = HMAC-SHA256(SecretService, "tc3_request")

4. Signature = HMAC-SHA256(SecretSigning, StringToSign).hex

5. Authorization:
   TC3-HMAC-SHA256 Credential=<SecretId>/<CredentialScope>, SignedHeaders=<...>, Signature=<...>
```

V4 `signing/tencent-v3.js` 完整实现。

## 附录 C:AWS SigV4 规范

参考 [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html):

```
1. Canonical Request:
   HTTPMethod\n
   CanonicalURI\n
   CanonicalQueryString\n
   CanonicalHeaders\n
   SignedHeaders\n
   HashedPayload

2. String to Sign:
   AWS4-HMAC-SHA256\n
   <timestamp>\n
   <credential_scope>\n
   <hashed_canonical_request>

3. Signing Key (4 级 HMAC):
   kDate = HMAC-SHA256("AWS4" + SecretKey, Date)
   kRegion = HMAC-SHA256(kDate, Region)
   kService = HMAC-SHA256(kRegion, Service)
   kSigning = HMAC-SHA256(kService, "aws4_request")

4. Signature = HMAC-SHA256(kSigning, StringToSign).hex
```

V4 `signing/aws-sigv4.js` 完整实现。

---

**作者**:Mavis (AI 架构助手) + 脱永军 (项目所有者)
**最后更新**:2026-09-01
**版本**:V4.0-PROVIDER-TEMPLATES
