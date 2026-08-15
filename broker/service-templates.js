// service-templates.js — 6 built-in service templates for Phase 1.2 admin UI.
// Each template describes the static "skeleton" of a service (upstream, headers,
// dashboard_actions). The admin form pre-fills these on selection; user can tweak.
// Secret references use {{secret.name.field}} placeholders, resolved at proxy time.
//
// Why templates (vs free-form): the 80% case for a new service is "wire up to
// GitHub/OpenAI/Aliyun with a known shape". Letting the admin type all the YAML
// by hand is error-prone (typo in upstream = silent failure). Templates are a
// sensible starting point — "custom" template remains available for everything else.
export const SERVICE_TEMPLATES = {
  github: {
    label: 'GitHub API',
    icon: '🐙',
    description: 'Personal Access Token 自动注入到 Authorization header',
    type: 'github_token',
    upstream: 'https://api.github.com',
    inject_headers: {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'secret-broker/2.0 (proxy)',
    },
    secret_placeholder: '{{secret.<TOKEN_SECRET>.token}}',
    default_secret_field: 'token',
    secret_help: '使用 github_pat 类型的密钥 (含 token 字段)',
    dashboard_actions: [
      { label: '我的信息', method: 'GET', path: '/user' },
      { label: '我的仓库 (前 5)', method: 'GET', path: '/user/repos', query: { per_page: '5' } },
    ],
  },

  openai: {
    label: 'OpenAI API',
    icon: '🤖',
    description: 'Bearer Token 注入 Authorization',
    type: 'bearer',
    upstream: 'https://api.openai.com',
    inject_headers: {
      'User-Agent': 'secret-broker/2.0',
    },
    secret_placeholder: '{{secret.<TOKEN_SECRET>.value}}',
    default_secret_field: 'value',
    secret_help: '使用 openai_key 类型的密钥 (含 value 字段)',
    dashboard_actions: [
      { label: '列出模型', method: 'GET', path: '/v1/models' },
      { label: '简单对话', method: 'POST', path: '/v1/chat/completions' },
    ],
  },

  aliyun_ecs: {
    label: '阿里云 ECS',
    icon: '☁️',
    description: 'AccessKey + Aliyun v2 签名，调 DescribeInstances 等 ECS OpenAPI',
    type: 'aliyun_v2',
    upstream: 'https://ecs.aliyuncs.com',
    region: 'cn-beijing',
    inject_headers: {},
    secret_placeholder: 'aliyun_ak (含 access_key_id + access_key_secret 字段)',
    secret_help: '必须用 aliyun_ak 类型 (含 access_key_id + access_key_secret + region)',
    dashboard_actions: [
      { label: '列 ECS 实例', method: 'GET', path: '/?Action=DescribeInstances&RegionId=cn-beijing' },
      { label: '列云盘', method: 'GET', path: '/?Action=DescribeDisks&RegionId=cn-beijing' },
      { label: '列 EIP', method: 'GET', path: '/?Action=DescribeEipAddresses&RegionId=cn-beijing' },
    ],
  },

  aliyun_ram: {
    label: '阿里云 RAM (域名 / DNS)',
    icon: '☁️',
    description: 'AccessKey + Aliyun v2 签名，调 Alidns / Ram 等任意 OpenAPI',
    type: 'aliyun_v2',
    upstream: 'https://alidns.aliyuncs.com',
    region: 'cn-beijing',
    inject_headers: {},
    secret_placeholder: 'aliyun_ak (含 access_key_id + access_key_secret + region)',
    secret_help: '必须用 aliyun_ak 类型 (含 access_key_id + access_key_secret + region)',
    dashboard_actions: [
      { label: '列域名', method: 'GET', path: '/?Action=DescribeDomains' },
      { label: '列解析记录', method: 'GET', path: '/?Action=DescribeDomainRecords&DomainName=example.com' },
    ],
  },

  generic_https: {
    label: '通用 HTTPS (自定义)',
    icon: '🔌',
    description: '任意 upstream + 自定义 headers 模板 + 自定义 actions',
    type: 'header',
    upstream: 'https://example.com',
    inject_headers: {
      'User-Agent': 'secret-broker/2.0',
    },
    header_name: 'Authorization',
    header_value_template: 'Bearer {{secret.<TOKEN_SECRET>.value}}',
    secret_placeholder: '任意 secret (value 字段会替换占位符)',
    secret_help: 'headers 模板里写 {{secret.<名字>.<字段>}} 占位符',
    dashboard_actions: [
      { label: 'GET /', method: 'GET', path: '/' },
    ],
  },

  ssh_proxy: {
    label: 'SSH 命令代理 (计划中)',
    icon: '🛠️',
    description: 'broker 作为 SSH jump host，目前仅占位 (Phase 3 实现)',
    type: 'ssh_proxy',
    upstream: '',
    inject_headers: {},
    secret_placeholder: 'ssh_connection 类型 (含 host/port/user/private_key)',
    secret_help: '需要 broker 二进制增加 SSH 服务器模式，Phase 3 才完整实现',
    dashboard_actions: [],
    disabled: true,
    disabled_reason: 'SSH 代理模式在 Phase 3 实现，Phase 1.2 暂不开放',
  },

  // M3.5 (2026-08-15): Cloudflare API Token 注入
  // https://dash.cloudflare.com/profile/api-tokens
  // Scope 推荐: Zone:DNS:Edit + Account:Cloudflare Tunnel:Edit (改 ingress)
  // token_field=api_token 配合 cloudflare_token type secret
  cloudflare: {
    label: 'Cloudflare API',
    icon: '☁️',
    description: 'API Token 自动注入到 Authorization: Bearer (调 /zones, /accounts, /tunnels)',
    type: 'bearer',
    upstream: 'https://api.cloudflare.com/client/v4',
    token_field: 'api_token',
    inject_headers: {
      'Content-Type': 'application/json',
    },
    secret_placeholder: '{{secret.<CLOUDFLARE_SECRET>.api_token}}',
    default_secret_field: 'api_token',
    secret_help: '使用 cloudflare_token 类型的密钥 (含 api_token + account_id 字段)',
    dashboard_actions: [
      { label: '验证 Token', method: 'GET', path: '/user' },
      { label: '列出 Zones', method: 'GET', path: '/zones', query: { per_page: '50' } },
      { label: '列出 Tunnels', method: 'GET', path: '/accounts/{{account_id}}/tunnels?status=active' },
    ],
  },
};

// Helper for /api/v1/admin/service-templates: return a sanitized view for UI.
export function publicTemplateList() {
  const out = {};
  for (const [id, t] of Object.entries(SERVICE_TEMPLATES)) {
    out[id] = {
      label: t.label,
      icon: t.icon,
      description: t.description,
      type: t.type,
      disabled: !!t.disabled,
      disabled_reason: t.disabled_reason || null,
    };
  }
  return out;
}
