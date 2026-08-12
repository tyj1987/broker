// patch-broker-config.js
// Idempotently adds Dashboard "AI Actions" metadata to broker.yaml:
//   - description + dashboard_actions for github / openai / aliyun_ecs (if missing)
//   - allow_password_login: true for client.dashboard-admin
//   - rotates a weak/default dashboard-admin password (prints the new one)
// Usage: node patch-broker-config.js <broker.yaml plaintext path>
// Requires the broker's node_modules (yaml package) — run on the broker host.
const fs = require('fs');
const { execSync } = require('child_process');

const YAML = require('/opt/secret-broker/broker/node_modules/yaml');

const path = process.argv[2];
if (!path) { console.error('usage: node patch-broker-config.js <broker.yaml>'); process.exit(1); }

const doc = YAML.parse(fs.readFileSync(path, 'utf8'));
if (!doc || typeof doc !== 'object' || !doc.services) {
  console.error('ERROR: not a valid broker.yaml'); process.exit(1);
}

const ACTIONS = {
  github: {
    description: 'GitHub API · PAT 自动注入',
    actions: [
      { label: '查看我的信息', method: 'GET', path: '/user' },
      { label: '查看仓库详情', method: 'GET', path: '/repos/tyj1987/sops-age-template' },
      { label: '列出我的仓库', method: 'GET', path: '/user/repos', query: { per_page: '5' } },
    ],
  },
  openai: {
    description: 'OpenAI API · Bearer Key 自动注入',
    actions: [
      { label: '模型列表', method: 'GET', path: '/v1/models' },
      {
        label: '发起对话',
        method: 'POST',
        path: '/v1/chat/completions',
        body: { model: 'gpt-4o-mini', messages: [{ role: 'user', content: 'Hi, reply in one short sentence.' }] },
      },
    ],
  },
  aliyun_ecs: {
    description: '阿里云 ECS OpenAPI · 签名自动注入',
    actions: [
      { label: '查询可用区域', method: 'GET', path: '/', query: { Action: 'DescribeRegions' } },
      { label: '列出实例', method: 'GET', path: '/', query: { Action: 'DescribeInstances', RegionId: 'cn-hangzhou' } },
    ],
  },
};

for (const [name, meta] of Object.entries(ACTIONS)) {
  const svc = doc.services[name];
  if (!svc) continue;
  if (meta.description && !svc.description) svc.description = meta.description;
  if (!svc.dashboard_actions) svc.dashboard_actions = meta.actions;
}

const admin = doc.clients && doc.clients['client.dashboard-admin'];
if (admin) {
  admin.allow_password_login = true;
  if (!admin.password || admin.password === 'admin-2026-change-me') {
    const pw = execSync('openssl rand -hex 12').toString().trim();
    admin.password = pw;
    fs.writeFileSync('/opt/secret-broker/.dashboard-password', pw + '\n', { mode: 0o600 });
    console.log('NEW_DASHBOARD_PASSWORD=' + pw);
  }
}

const header = '# broker.yaml - Secret Broker 服务端配置（SOPS 加密）\n'
  + '# services = 可代理的外部 API；clients = 证书指纹 + 权限 + 登录密码\n';
let out = header + YAML.stringify(doc);
// SOPS (go-yaml) parses bare YYYY-MM-DD as time.Time and fails to walk it —
// re-quote date-like scalars and mustache templates after stringify.
out = out.replace(/^(\s*[^#].*?):\s*(\d{4}-\d{2}-\d{2})\s*$/gm, '$1: "$2"');
out = out.replace(/^(\s*[^#].*?):\s*(Bearer\s+\{\{secret\}\})\s*$/gm, '$1: "$2"');
fs.writeFileSync(path, out);
console.log('patched services:', Object.keys(doc.services).join(', '));
