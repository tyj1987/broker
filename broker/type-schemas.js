// broker/type-schemas.js
// Phase 1.1: Define schema for each secret type.
// Each schema tells the admin UI which fields to render, and tells the broker
// what shape to expect when services reference this secret.
//
// Field kinds: 'text' | 'textarea' | 'password' | 'number' | 'select' | 'checkbox'
// Field options:
//   - name:        (required) field key inside the secret's `fields` object
//   - label:       human-readable label for the form
//   - kind:        input kind (default: 'text')
//   - required:    boolean (default: false)
//   - sensitive:   boolean — UI masks the value, value still stored
//   - default:     default value (used when creating new secret)
//   - options:     for kind=select, array of {value, label}
//   - help:        hint text below the input
//   - show_when:   conditional display: { field: 'auth_method', equals: 'password' }
//                  shown only when referenced field has the given value
//   - placeholder: input placeholder
//
// To add a new type: add an entry here. The admin UI, API, and broker will all
// pick it up automatically.

export const TYPE_SCHEMAS = {
  // ---- 通用 ----
  custom: {
    label: '自定义 / Custom',
    description: '任意单值密钥。明文存储。',
    fields: [
      { name: 'value', label: '值 / Value', kind: 'textarea', required: true, sensitive: true,
        help: '明文存入 broker。任何字符串。' },
    ],
  },

  // ---- 代码平台 ----
  github_pat: {
    label: 'GitHub Personal Access Token',
    description: 'https://github.com/settings/tokens — classic (ghp_) 或 fine-grained (github_pat_)',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'Token', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'ghp_... 或 github_pat_...',
        help: 'Classic PAT 以 ghp_ 开头；fine-grained 以 github_pat_ 开头。Authorization 使用 token 方案。',
        validation_regex: '^(ghp_|github_pat_)[A-Za-z0-9_]+' },
    ],
  },
  gitlab_pat: {
    label: 'GitLab Personal Access Token',
    description: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    fields: [
      { name: 'token', label: 'Token', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'glpat-...' },
    ],
  },
  gitee_pat: {
    label: 'Gitee Personal Access Token',
    description: 'https://gitee.com/profile/personal_access_tokens',
    fields: [
      { name: 'token', label: 'Token', kind: 'textarea', required: true, sensitive: true },
    ],
  },

  // ---- AI 服务 ----
  openai_key: {
    label: 'OpenAI API Key',
    description: 'https://platform.openai.com/api-keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'sk-... 或 sk-proj-... 或 sk-svcacct-...',
        help: '平台密钥以 sk- / sk-proj- / sk-svcacct- 开头，长度不固定' },
      { name: 'organization', label: 'Organization ID (可选)', kind: 'text',
        help: '如有多个 org 需指定，否则留空' },
    ],
  },
  anthropic_key: {
    label: 'Anthropic API Key',
    description: 'https://console.anthropic.com/settings/keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'sk-ant-...' },
    ],
  },
  google_ai_key: {
    label: 'Google AI (Gemini) API Key',
    description: 'https://aistudio.google.com/app/apikey',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true },
    ],
  },
  mistral_key: {
    label: 'Mistral AI API Key',
    description: 'https://console.mistral.ai/api-keys/',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true },
    ],
  },
  cohere_key: {
    label: 'Cohere API Key',
    description: 'https://dashboard.cohere.com/api-keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true },
    ],
  },
  deepseek_key: {
    label: 'DeepSeek API Key',
    description: 'https://platform.deepseek.com/api_keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true },
    ],
  },
  zhipu_key: {
    label: '智谱 AI API Key',
    description: 'https://bigmodel.cn/usercenter/apikeys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true,
        placeholder: '格式如 xxx.xxx.xxx' },
    ],
  },
  moonshot_key: {
    label: '月之暗面 Kimi API Key',
    description: 'https://platform.moonshot.cn/console/api-keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'sk-...' },
    ],
  },
  qwen_key: {
    label: '通义千问 (DashScope) API Key',
    description: 'https://dashscope.console.aliyun.com/apiKey',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'sk-...' },
    ],
  },

  // ---- 云厂商（双字段为主）----
  aliyun_ak: {
    label: '阿里云 AccessKey (RAM 用户)',
    description: 'https://ram.console.aliyun.com/users — 创建 RAM 用户并生成 AccessKey',
    fields: [
      { name: 'access_key_id', label: 'AccessKey ID', kind: 'text', required: true,
        placeholder: 'LTAI...', help: '以 LTAI 开头的 24 字符' },
      { name: 'access_key_secret', label: 'AccessKey Secret', kind: 'password', required: true, sensitive: true,
        help: '创建时只显示一次，请妥善保存' },
      { name: 'region', label: '默认 Region (可选)', kind: 'text', placeholder: 'cn-hangzhou',
        help: '如不填，使用 ECS/RAM 默认' },
    ],
  },
  tencent_sk: {
    label: '腾讯云 SecretKey',
    description: 'https://console.cloud.tencent.com/cam/capi — 云 API 密钥',
    fields: [
      { name: 'secret_id', label: 'SecretId', kind: 'text', required: true,
        placeholder: 'AKID...' },
      { name: 'secret_key', label: 'SecretKey', kind: 'password', required: true, sensitive: true },
      { name: 'region', label: '默认 Region (可选)', kind: 'text', placeholder: 'ap-guangzhou' },
    ],
  },
  aws_access_key: {
    label: 'AWS Access Key',
    description: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    fields: [
      { name: 'access_key_id', label: 'Access Key ID', kind: 'text', required: true,
        placeholder: 'AKIA...' },
      { name: 'secret_access_key', label: 'Secret Access Key', kind: 'password', required: true, sensitive: true },
      { name: 'region', label: '默认 Region', kind: 'text', default: 'us-east-1',
        placeholder: 'us-east-1' },
    ],
  },
  gcp_service_account: {
    label: 'GCP Service Account (JSON key)',
    description: 'https://console.cloud.google.com/iam-admin/serviceaccounts — 创建并下载 JSON key',
    fields: [
      { name: 'credentials_json', label: 'Service Account JSON (完整粘贴)', kind: 'textarea', required: true, sensitive: true,
        help: '从 GCP 下载的 .json 文件完整内容' },
      { name: 'project_id', label: 'Project ID (从 JSON 提取)', kind: 'text', required: true },
    ],
  },
  cloudflare_token: {
    label: 'Cloudflare API Token',
    description: 'https://dash.cloudflare.com/profile/api-tokens',
    fields: [
      { name: 'api_token', label: 'API Token', kind: 'password', required: true, sensitive: true },
      { name: 'account_id', label: 'Account ID (可选)', kind: 'text',
        help: 'Workers/R2 需要；纯 DNS 可不填' },
    ],
  },
  aliyun_oss: {
    label: '阿里云 OSS (Bucket 访问)',
    description: '需要 AccessKey + Endpoint + Bucket 名',
    fields: [
      { name: 'access_key_id', label: 'AccessKey ID', kind: 'text', required: true },
      { name: 'access_key_secret', label: 'AccessKey Secret', kind: 'password', required: true, sensitive: true },
      { name: 'endpoint', label: 'Endpoint', kind: 'text', required: true,
        placeholder: 'oss-cn-hangzhou.aliyuncs.com',
        help: '格式：oss-<region>.aliyuncs.com（内网用 oss-<region>-internal.aliyuncs.com）' },
      { name: 'bucket', label: 'Bucket 名称', kind: 'text', required: true },
    ],
  },
  tencent_cos: {
    label: '腾讯云 COS (Bucket 访问)',
    description: '需要 SecretId/SecretKey + Region + Bucket',
    fields: [
      { name: 'secret_id', label: 'SecretId', kind: 'text', required: true },
      { name: 'secret_key', label: 'SecretKey', kind: 'password', required: true, sensitive: true },
      { name: 'region', label: 'Region', kind: 'text', required: true, placeholder: 'ap-guangzhou' },
      { name: 'bucket', label: 'Bucket 名称', kind: 'text', required: true,
        help: '格式：<BucketName>-<AppId>，如 example-1250000000' },
    ],
  },

  // ---- 基础设施 ----
  ssh_connection: {
    label: 'SSH 连接配置',
    description: '一台机器的完整 SSH 凭据，service 模板可直接引用',
    fields: [
      { name: 'host', label: '主机 / IP', kind: 'text', required: true,
        placeholder: '192.168.2.30 或 vm.example.com' },
      { name: 'port', label: '端口', kind: 'number', default: 22,
        help: '默认 22，留空使用默认' },
      { name: 'username', label: '用户名', kind: 'text', required: true,
        placeholder: 'root' },
      { name: 'known_hosts', label: '受信任主机密钥', kind: 'textarea', required: true,
        placeholder: '[192.168.2.30]:22 ssh-ed25519 AAAA...',
        help: '必须通过独立可信渠道核验后填入OpenSSH known_hosts完整条目；SSH代理强制匹配，禁止首次连接自动接受。' },
      { name: 'auth_method', label: '认证方式', kind: 'select', required: true, default: 'private_key',
        options: [
          { value: 'private_key', label: '私钥 / Private Key' },
          { value: 'password', label: '密码 / Password（运行时未支持）' },
        ],
        help: 'sshExec/sshTunnel 仅支持 private_key（BatchMode + -i）。password / passphrase 尚未实现。' },
      { name: 'password', label: '密码（未支持）', kind: 'password', sensitive: true,
        show_when: { field: 'auth_method', equals: 'password' },
        help: '运行时未实现：请改用 private_key。保留字段仅兼容旧配置。' },
      { name: 'private_key', label: '私钥内容 (PEM 全文)', kind: 'textarea', sensitive: true, file_upload: true,
        show_when: { field: 'auth_method', equals: 'private_key' },
        placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----\n...',
        help: '当 auth=private_key 且无 key_path 时必填。也可以直接上传 .pem 文件。' },
      { name: 'private_key_path', label: '私钥文件路径 (替代粘贴)', kind: 'text',
        show_when: { field: 'auth_method', equals: 'private_key' },
        placeholder: '/root/.ssh/id_ed25519',
        help: 'broker 端使用私钥时会读这个路径。优先级：private_key > private_key_path' },
      { name: 'passphrase', label: '私钥密码 (可选)', kind: 'password', sensitive: true,
        show_when: { field: 'auth_method', equals: 'private_key' },
        help: '如果私钥文件本身有密码保护' },
    ],
  },
  ssh_private_key: {
    label: 'SSH 私钥 (裸)',
    description: '一个 PEM 私钥字符串，不带连接信息',
    fields: [
      { name: 'key', label: '私钥内容', kind: 'textarea', required: true, sensitive: true, file_upload: true,
        placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----\n...', help: '可粘贴全文，或上传 .pem 文件' },
      { name: 'passphrase', label: '密码 (可选)', kind: 'password', sensitive: true },
    ],
  },
  ssh_public_key: {
    label: 'SSH 公钥',
    description: '部署到服务器 ~/.ssh/authorized_keys',
    fields: [
      { name: 'key', label: '公钥内容', kind: 'textarea', required: true, file_upload: true,
        placeholder: 'ssh-ed25519 AAAA...', help: '可粘贴全文，或上传 .pub 文件' },
    ],
  },

  database_url_pg: {
    label: 'PostgreSQL 连接',
    description: 'Postgres 完整连接信息（broker 拼成 URL）',
    fields: [
      { name: 'host', label: 'Host', kind: 'text', required: true, placeholder: 'localhost' },
      { name: 'port', label: 'Port', kind: 'number', default: 5432 },
      { name: 'username', label: 'Username', kind: 'text', required: true },
      { name: 'password', label: 'Password', kind: 'password', required: true, sensitive: true },
      { name: 'database', label: 'Database', kind: 'text', required: true },
      { name: 'sslmode', label: 'SSL Mode', kind: 'select', default: 'prefer',
        options: [
          { value: 'disable', label: 'disable' },
          { value: 'prefer', label: 'prefer' },
          { value: 'require', label: 'require' },
          { value: 'verify-ca', label: 'verify-ca' },
          { value: 'verify-full', label: 'verify-full' },
        ] },
    ],
  },
  database_url_mysql: {
    label: 'MySQL 连接',
    description: 'MySQL 完整连接信息',
    fields: [
      { name: 'host', label: 'Host', kind: 'text', required: true },
      { name: 'port', label: 'Port', kind: 'number', default: 3306 },
      { name: 'username', label: 'Username', kind: 'text', required: true },
      { name: 'password', label: 'Password', kind: 'password', required: true, sensitive: true },
      { name: 'database', label: 'Database', kind: 'text', required: true },
    ],
  },
  redis_url: {
    label: 'Redis 连接',
    description: 'Redis 完整连接信息（可选用户名，Redis 6+ ACL）',
    fields: [
      { name: 'host', label: 'Host', kind: 'text', required: true },
      { name: 'port', label: 'Port', kind: 'number', default: 6379 },
      { name: 'username', label: 'Username (Redis 6+ ACL, 可选)', kind: 'text', default: 'default' },
      { name: 'password', label: 'Password', kind: 'password', sensitive: true,
        help: '无密码留空' },
      { name: 'db', label: 'DB 编号', kind: 'number', default: 0,
        help: '默认 0，范围 0-15' },
      { name: 'tls', label: '启用 TLS', kind: 'checkbox', default: false },
    ],
  },
  mongodb_url: {
    label: 'MongoDB 连接',
    description: 'MongoDB 完整连接信息',
    fields: [
      { name: 'host', label: 'Host', kind: 'text', required: true },
      { name: 'port', label: 'Port', kind: 'number', default: 27017 },
      { name: 'username', label: 'Username', kind: 'text' },
      { name: 'password', label: 'Password', kind: 'password', sensitive: true },
      { name: 'database', label: 'Database (auth source)', kind: 'text', default: 'admin' },
    ],
  },

  // ---- 邮件 ----
  smtp_password: {
    label: 'SMTP 邮件',
    description: '发邮件用的 SMTP 配置（broker 可代发邮件）',
    fields: [
      { name: 'host', label: 'SMTP Host', kind: 'text', required: true, placeholder: 'smtp.gmail.com' },
      { name: 'port', label: 'Port', kind: 'number', default: 587 },
      { name: 'username', label: 'Username', kind: 'text', required: true },
      { name: 'password', label: 'Password / App Password', kind: 'password', required: true, sensitive: true,
        help: 'Gmail 等需要用 App Password，不是登录密码' },
      { name: 'encryption', label: '加密方式', kind: 'select', default: 'starttls',
        options: [
          { value: 'starttls', label: 'STARTTLS (推荐 587)' },
          { value: 'tls', label: 'TLS/SSL (465)' },
          { value: 'none', label: '明文 (仅内网)' },
        ] },
      { name: 'from', label: '发件人地址', kind: 'text', required: true,
        placeholder: '"Name" <user@example.com>' },
    ],
  },
  sendgrid_key: {
    label: 'SendGrid API Key',
    description: 'https://app.sendgrid.com/settings/api_keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'password', required: true, sensitive: true,
        placeholder: 'SG....' },
      { name: 'from', label: '发件人 (verified sender)', kind: 'text', required: true,
        placeholder: 'noreply@example.com' },
    ],
  },
  mailgun_key: {
    label: 'Mailgun API Key',
    description: 'https://app.mailgun.com/app/account/security/api_keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'password', required: true, sensitive: true },
      { name: 'domain', label: 'Domain', kind: 'text', required: true, placeholder: 'mg.example.com' },
    ],
  },

  // ---- 通知 webhook ----
  slack_webhook: {
    label: 'Slack Webhook',
    description: 'https://api.slack.com/messaging/webhooks',
    fields: [
      { name: 'url', label: 'Webhook URL', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'https://hooks.slack.com/services/...' },
      { name: 'channel', label: '默认 Channel (可选)', kind: 'text', placeholder: '#alerts' },
      { name: 'username', label: '默认 Bot 用户名 (可选)', kind: 'text', default: 'Broker Bot' },
    ],
  },
  discord_webhook: {
    label: 'Discord Webhook',
    description: 'Server Settings → Integrations → Webhooks',
    fields: [
      { name: 'url', label: 'Webhook URL', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'https://discord.com/api/webhooks/...' },
    ],
  },
  feishu_webhook: {
    label: '飞书机器人 Webhook',
    description: '群设置 → 群机器人 → 添加机器人 → 自定义机器人',
    fields: [
      { name: 'url', label: 'Webhook URL', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'https://open.feishu.cn/open-apis/bot/v2/hook/...' },
      { name: 'secret', label: '签名校验密钥 (可选)', kind: 'password', sensitive: true,
        help: '启用签名校验时必填' },
    ],
  },
  dingtalk_webhook: {
    label: '钉钉机器人 Webhook',
    description: '群设置 → 群机器人 → 添加机器人 → 自定义机器人',
    fields: [
      { name: 'url', label: 'Webhook URL', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'https://oapi.dingtalk.com/robot/send?access_token=...' },
      { name: 'secret', label: '加签密钥 (可选)', kind: 'password', sensitive: true,
        help: '启用加签时必填' },
    ],
  },
  telegram_bot_token: {
    label: 'Telegram Bot Token',
    description: '@BotFather → /newbot',
    fields: [
      { name: 'bot_token', label: 'Bot Token', kind: 'password', required: true, sensitive: true,
        placeholder: '123456:ABC-DEF...' },
      { name: 'chat_id', label: '默认 Chat ID (可选)', kind: 'text',
        help: '私聊时填 user ID，群组时填 -100 开头的群 ID' },
    ],
  },

  // ---- 监控 ----
  sentry_dsn: {
    label: 'Sentry DSN',
    description: 'https://sentry.io/settings/→ Projects → Client Keys (DSN)',
    fields: [
      { name: 'dsn', label: 'DSN', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'https://<key>@o<org>.ingest.sentry.io/<project>' },
    ],
  },
  datadog_key: {
    label: 'Datadog API Key',
    description: 'https://app.datadoghq.com/organization-settings/application-keys',
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'password', required: true, sensitive: true },
      { name: 'app_key', label: 'Application Key', kind: 'password', sensitive: true,
        help: '某些 API 需要' },
      { name: 'site', label: 'Site', kind: 'select', default: 'datadoghq.com',
        options: [
          { value: 'datadoghq.com', label: 'US (datadoghq.com)' },
          { value: 'datadoghq.eu', label: 'EU (datadoghq.eu)' },
          { value: 'us3.datadoghq.com', label: 'US3' },
          { value: 'ap1.datadoghq.com', label: 'AP1' },
        ] },
    ],
  },

  // ---- 支付 ----
  stripe_secret_key: {
    label: 'Stripe Secret Key',
    description: 'https://dashboard.stripe.com/apikeys',
    fields: [
      { name: 'secret_key', label: 'Secret Key', kind: 'password', required: true, sensitive: true,
        placeholder: 'sk_live_... 或 sk_test_...' },
      { name: 'webhook_secret', label: 'Webhook Signing Secret (可选)', kind: 'password', sensitive: true,
        placeholder: 'whsec_...' },
    ],
  },
  wechat_pay_key: {
    label: '微信支付 API Key',
    description: '商户平台 → API安全 → APIv3 密钥',
    fields: [
      { name: 'app_id', label: 'AppID', kind: 'text', required: true },
      { name: 'mch_id', label: '商户号', kind: 'text', required: true },
      { name: 'api_v3_key', label: 'APIv3 密钥', kind: 'password', required: true, sensitive: true },
      { name: 'cert_serial', label: '证书序列号', kind: 'text', required: true },
      { name: 'private_key', label: '商户私钥 (apiclient_key.pem 内容)', kind: 'textarea', required: true, sensitive: true, file_upload: true, help: '可粘贴全文，或上传 .pem 文件' },
    ],
  },

  // ---- 杂项 ----
  jwt_secret: {
    label: 'JWT 签名密钥',
    description: 'HS256 用的随机字符串',
    fields: [
      { name: 'value', label: 'Secret', kind: 'textarea', required: true, sensitive: true,
        help: '建议至少 32 字符随机' },
    ],
  },
  oauth_client: {
    label: 'OAuth Client',
    description: 'OAuth2 / OIDC 客户端凭据',
    fields: [
      { name: 'client_id', label: 'Client ID', kind: 'text', required: true },
      { name: 'client_secret', label: 'Client Secret', kind: 'password', required: true, sensitive: true },
      { name: 'redirect_uri', label: 'Redirect URI', kind: 'text',
        placeholder: 'https://app.example.com/oauth/callback' },
      { name: 'scopes', label: 'Scopes (空格分隔)', kind: 'text', placeholder: 'openid profile email' },
      { name: 'token_url', label: 'Token URL (可选)', kind: 'text' },
      { name: 'auth_url', label: 'Authorize URL (可选)', kind: 'text' },
    ],
  },
  random_string: {
    label: '随机字符串',
    description: '通用随机 token / API key',
    fields: [
      { name: 'value', label: '字符串', kind: 'textarea', required: true, sensitive: true },
    ],
  },
};

// ----- 派生：单字段 type 列表（值就是 value），用于向后兼容 -----
export const SINGLE_FIELD_TYPES = new Set();
for (const [type, schema] of Object.entries(TYPE_SCHEMAS)) {
  if (schema.fields.length === 1 && schema.fields[0].name === 'value') {
    SINGLE_FIELD_TYPES.add(type);
  }
}

// ----- helper: get schema by type, fallback to 'custom' -----
export function getTypeSchema(type) {
  const raw = TYPE_SCHEMAS[type] || TYPE_SCHEMAS.custom;
  // 浅拷贝 + 字段深拷贝,把 validation_regex 字符串转 RegExp,避免调用方还需 new RegExp
  const fields = raw.fields.map(f => {
    if (typeof f.validation_regex === 'string') {
      return { ...f, validation_regex: new RegExp(f.validation_regex) };
    }
    return { ...f };
  });
  return { ...raw, fields };
}

// ----- helper: 渲染默认值（创建 secret 时） -----
export function defaultFieldsFor(type) {
  const schema = getTypeSchema(type);
  const out = {};
  for (const f of schema.fields) {
    if (f.default !== undefined) out[f.name] = f.default;
    else if (f.kind === 'checkbox') out[f.name] = false;
    else if (f.kind === 'number') out[f.name] = null;
    else out[f.name] = '';
  }
  return out;
}

// ----- helper: 校验 fields 是否符合 schema -----
export function validateFields(type, fields) {
  const schema = getTypeSchema(type);
  const errors = [];
  // 1. 检查所有 required 字段都有值
  // 条件显示的字段如果当前不可见，跳过校验
  const visibleFields = schema.fields.filter(f => {
    if (!f.show_when) return true;
    return fields[f.show_when.field] === f.show_when.equals;
  });
  for (const f of visibleFields) {
    if (f.required) {
      const v = fields[f.name];
      if (v === undefined || v === null || v === '') {
        errors.push(`字段 "${f.label}" 必填`);
      }
    }
  }
  // 2. 检查字段名是否在 schema 中
  for (const k of Object.keys(fields || {})) {
    if (!schema.fields.find(f => f.name === k)) {
      errors.push(`未知字段: ${k}`);
    }
  }
  return errors;
}

// ============================================================
// V4 增量: 20 个新增 type schemas
// 来自 DESIGN-V4-PROVIDER-TEMPLATES.md § 4.2
// ============================================================

const V4_TYPE_SCHEMAS = {
  // ---- 容器镜像 ----
  docker_hub_pat: {
    label: 'Docker Hub Personal Access Token',
    description: 'https://hub.docker.com/settings/security — Personal Access Token (2025 新)',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'username', label: 'Username', kind: 'text', required: true },
      { name: 'pat', label: 'Personal Access Token', kind: 'textarea', required: true, sensitive: true,
        placeholder: 'dckr_pat_...',
        validation_regex: '^dckr_pat_[A-Za-z0-9_-]{20,}$',
        help: 'Docker Hub 2025 起推荐 PAT(取代密码)' },
    ],
  },
  ghcr_pat: {
    label: 'GitHub Container Registry Token',
    description: '用 GitHub PAT 推拉 ghcr.io,需 packages:read/write scope',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'GitHub PAT', kind: 'textarea', required: true, sensitive: true,
        help: 'ghp_/github_pat_ + packages scope' },
    ],
  },
  // ---- 云厂商 - 国际 ----
  aws_access_key_v2: {
    label: 'AWS Access Key (含 STS 临时凭证支持)',
    description: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'access_key_id', label: 'Access Key ID', kind: 'text', required: true,
        validation_regex: '^(AKIA|ASIA)[A-Z0-9]{12,}$' },
      { name: 'secret_access_key', label: 'Secret Access Key', kind: 'password', required: true, sensitive: true },
      { name: 'session_token', label: 'Session Token (仅 STS)', kind: 'textarea', sensitive: true,
        help: 'STS AssumeRole 返回的临时 token,留空表示长期 AK' },
      { name: 'region', label: '默认 Region', kind: 'text', default: 'us-east-1',
        placeholder: 'us-east-1' },
    ],
  },
  azure_tenant: {
    label: 'Azure Tenant (App Registration)',
    description: 'https://portal.azure.com → App registrations',
    rotate_recommendation_days: 180,
    fields: [
      { name: 'tenant_id', label: 'Tenant ID', kind: 'text', required: true,
        validation_regex: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
      { name: 'client_id', label: 'Client ID', kind: 'text', required: true,
        validation_regex: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
      { name: 'client_secret', label: 'Client Secret', kind: 'password', required: true, sensitive: true },
      { name: 'subscription_id', label: 'Subscription ID (可选)', kind: 'text' },
    ],
  },
  gcp_service_account_v2: {
    label: 'GCP Service Account (含 Workload Identity)',
    description: 'https://console.cloud.google.com/iam-admin/serviceaccounts',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'credentials_json', label: 'Service Account JSON (完整)', kind: 'textarea', required: true, sensitive: true,
        file_upload: true,
        help: '从 GCP 下载的 .json 文件完整内容' },
      { name: 'project_id', label: 'Project ID', kind: 'text', required: true,
        help: '从 credentials_json 提取的 project_id' },
      { name: 'use_workload_identity', label: '优先用 Workload Identity', kind: 'checkbox', default: false,
        help: 'GKE/Cloud Run 中勾选后,broker 用 metadata server 拿短命 token' },
    ],
  },
  digitalocean: {
    label: 'DigitalOcean PAT',
    description: 'https://cloud.digitalocean.com/account/api/tokens',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'api_token', label: 'API Token', kind: 'textarea', required: true, sensitive: true,
        validation_regex: '^dop_v1_[a-f0-9]{64}$' },
    ],
  },
  oracle_cloud: {
    label: 'Oracle Cloud API Key',
    description: 'https://cloud.oracle.com/identity/domains/my-profile/api-keys',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'user_ocid', label: 'User OCID', kind: 'text', required: true,
        placeholder: 'ocid1.user.oc1..aaaa...' },
      { name: 'tenancy_ocid', label: 'Tenancy OCID', kind: 'text', required: true,
        placeholder: 'ocid1.tenancy.oc1..aaaa...' },
      { name: 'fingerprint', label: 'API Key Fingerprint', kind: 'text', required: true },
      { name: 'private_key', label: 'Private Key (PEM)', kind: 'textarea', required: true, sensitive: true, file_upload: true },
      { name: 'region', label: 'Region', kind: 'text', default: 'us-ashburn-1' },
    ],
  },
  // ---- 代码平台 ----
  github_app: {
    label: 'GitHub App (替代 PAT)',
    description: 'https://github.com/settings/apps — 比 PAT 更细粒度',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'app_id', label: 'App ID', kind: 'number', required: true,
        help: '数字,GitHub App 详情页可见' },
      { name: 'installation_id', label: 'Installation ID', kind: 'number', required: true },
      { name: 'private_key', label: 'Private Key (.pem)', kind: 'textarea', required: true, sensitive: true, file_upload: true,
        placeholder: '-----BEGIN RSA PRIVATE KEY-----...' },
    ],
  },
  gitlab_pat: {
    label: 'GitLab Personal Access Token',
    description: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'Token', kind: 'textarea', required: true, sensitive: true,
        validation_regex: '^glpat-[A-Za-z0-9_\-]{20,}$' },
    ],
  },
  gitee_pat: {
    label: 'Gitee Personal Access Token',
    description: 'https://gitee.com/profile/personal_access_tokens',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'Token', kind: 'textarea', required: true, sensitive: true },
    ],
  },
  // ---- 通信 ----
  feishu_app: {
    label: '飞书应用凭证',
    description: 'https://open.feishu.cn/app — 应用凭证',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'app_id', label: 'App ID', kind: 'text', required: true,
        validation_regex: '^cli_[a-z0-9]{16,}$' },
      { name: 'app_secret', label: 'App Secret', kind: 'password', required: true, sensitive: true },
    ],
  },
  dingtalk_app: {
    label: '钉钉应用凭证',
    description: 'https://open-dev.dingtalk.com — 应用信息',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'app_key', label: 'AppKey', kind: 'text', required: true },
      { name: 'app_secret', label: 'AppSecret', kind: 'password', required: true, sensitive: true },
      { name: 'agent_id', label: 'AgentId', kind: 'text', required: true,
        help: '机器人或应用 ID' },
    ],
  },
  // ---- 支付 ----
  wechat_miniprogram: {
    label: '微信小程序凭证',
    description: 'https://mp.weixin.qq.com — 开发管理',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'app_id', label: 'AppID', kind: 'text', required: true,
        validation_regex: '^wx[a-f0-9]{16}$' },
      { name: 'app_secret', label: 'AppSecret', kind: 'password', required: true, sensitive: true },
    ],
  },
  alipay_key: {
    label: '支付宝密钥',
    description: 'https://open.alipay.com — 应用信息',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'app_id', label: 'App ID', kind: 'text', required: true,
        placeholder: '2021000000000000' },
      { name: 'private_key', label: '应用私钥 (PKCS8)', kind: 'textarea', required: true, sensitive: true, file_upload: true,
        placeholder: '-----BEGIN PRIVATE KEY-----...' },
      { name: 'alipay_public_key', label: '支付宝公钥', kind: 'textarea', required: true,
        placeholder: '-----BEGIN PUBLIC KEY-----...' },
    ],
  },
  // ---- 监控 ----
  datadog_v2: {
    label: 'Datadog API Key',
    description: 'https://app.datadoghq.com/organization-settings/application-keys',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'api_key', label: 'API Key', kind: 'password', required: true, sensitive: true },
      { name: 'app_key', label: 'Application Key', kind: 'password', sensitive: true,
        help: '某些 API 需要' },
      { name: 'site', label: 'Site', kind: 'select', default: 'datadoghq.com', options: [
        { value: 'datadoghq.com', label: 'US (datadoghq.com)' },
        { value: 'datadoghq.eu', label: 'EU (datadoghq.eu)' },
        { value: 'us3.datadoghq.com', label: 'US3' },
        { value: 'ap1.datadoghq.com', label: 'AP1' },
      ] },
    ],
  },
  // ---- 杂项 ----
  npm_token: {
    label: 'NPM Publish Token',
    description: 'https://www.npmjs.com/settings/[user]/tokens',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'NPM Token', kind: 'textarea', required: true, sensitive: true,
        validation_regex: '^npm_[A-Za-z0-9]{36}$' },
    ],
  },
  pypi_token: {
    label: 'PyPI API Token',
    description: 'https://pypi.org/manage/account/token/',
    rotate_recommendation_days: 90,
    fields: [
      { name: 'token', label: 'PyPI Token', kind: 'textarea', required: true, sensitive: true,
        validation_regex: '^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}$' },
    ],
  },
  // ---- SSH 跳板 (V4) ----
  ssh_jump_host: {
    label: 'SSH 跳板配置',
    description: '通过 broker 中转到目标主机,AI 不接触私钥',
    rotate_recommendation_days: 180,
    fields: [
      { name: 'jump_host', label: '跳板机地址', kind: 'text', required: true,
        placeholder: 'jump.example.com' },
      { name: 'jump_user', label: '跳板机用户', kind: 'text', required: true,
        placeholder: 'bastion' },
      { name: 'jump_key', label: '跳板机私钥', kind: 'textarea', required: true, sensitive: true, file_upload: true,
        placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----...' },
      { name: 'target_user', label: '目标机用户', kind: 'text', required: true,
        placeholder: 'app' },
      { name: 'target_host', label: '目标机地址', kind: 'text', required: true,
        placeholder: 'internal.example.com' },
      { name: 'target_port', label: '目标机端口', kind: 'number', default: 22 },
    ],
  },
  // ---- DB ----
  azure_storage: {
    label: 'Azure Storage Account',
    description: 'https://portal.azure.com → Storage accounts',
    rotate_recommendation_days: 365,
    fields: [
      { name: 'account_name', label: 'Account Name', kind: 'text', required: true },
      { name: 'account_key', label: 'Account Key', kind: 'password', required: true, sensitive: true,
        help: 'Shared Key,用于 Blob/Queue/Table/File' },
      { name: 'connection_string', label: 'Connection String (可选)', kind: 'textarea', sensitive: true,
        file_upload: true,
        help: '完整连接字符串,优先于 account_name + account_key' },
    ],
  },
};

// 合并 V4 schemas 到 TYPE_SCHEMAS
for (const [type, schema] of Object.entries(V4_TYPE_SCHEMAS)) {
  if (!TYPE_SCHEMAS[type]) {
    TYPE_SCHEMAS[type] = schema;
  }
}
