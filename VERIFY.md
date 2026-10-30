# Secret Broker v4.9.0 验证指南

本文档用于验证当前仓库，而不是复现历史版本的固定测试数量。测试套件会持续增长，验收以命令退出码和发布门禁结果为准。

## 1. 环境要求

必需：

- Node.js **22 或更高版本**；CI 与生产镜像使用 Node.js 24
- npm（随 Node.js 安装）
- Python 3.9 或更高版本
- Git

发布前还必须具备：

- Docker/BuildKit
- Bash（用于检查 shell 脚本）
- SOPS 与 age（端到端加解密测试和实际部署）

```bash
node --version
npm --version
python --version
git --version
```

## 2. 确认版本与锁文件一致

```bash
node -e "const p=require('./broker/package.json');const l=require('./broker/package-lock.json');if(p.version!==l.version)throw new Error('package/package-lock version mismatch');console.log(p.version)"
```

预期输出当前版本 `4.9.0`，并以退出码 0 结束。

## 3. 可复现安装

```bash
cd broker
npm ci
```

生产构建必须存在 `package-lock.json`，不得回退到 `npm install`。

## 4. 完整质量门禁

```bash
cd broker
npm run quality:gate
```

该命令依次执行：

1. ESLint
2. Prettier 格式检查
3. Node.js 全量测试
4. MCP Server 集成回归
5. SSH、WebSocket、Workload Identity 等专项测试
6. Python SDK 测试

验收标准：最终退出码为 0，且没有失败测试。

## 5. 生产依赖漏洞审计

```bash
cd broker
npm audit --omit=dev --audit-level=high
```

验收标准：退出码为 0。任何 high/critical 漏洞都会阻止发布。

## 6. 发布、工作流和供应链检查

```bash
cd broker
npm run test:release-workflow
```

该测试验证：

- 所有 GitHub Actions YAML 可解析
- Release 和双云部署依赖完整质量门禁
- GitHub Actions 使用当前 Node 运行时兼容版本
- SBOM 扫描实际发布镜像 digest
- Cosign 使用精确工作流身份验证
- SOPS/age 安装包有固定版本与 SHA-256 校验
- Dockerfile 使用 Node.js 24、锁文件和非 root 用户
- 阿里云凭据轮转脚本不包含硬编码密钥、不回显解密值

Shell 语法检查：

```bash
bash -n scripts/ci/install-sops.sh
bash -n scripts/ci/install-age.sh
bash -n scripts/broker/inject-aliyun-ak.sh
```

## 7. Git 差异完整性

```bash
git diff --check
git status --short
```

`git diff --check` 必须无输出并返回 0。发布前必须人工审查 `git status --short` 中的每一个新增、修改和删除文件。

检查不应被跟踪的敏感扩展名：

```bash
git ls-files -- '*.key' '*.pem' '*.p12' '*.pfx' '.env' '*.env' \
  'age/key.txt' 'secrets/broker.yaml' 'secrets/common.env'
```

预期无输出。测试夹具中允许出现明显不可用的 token/PEM 占位符，但不得出现真实凭据。

已安装 gitleaks 时再执行：

```bash
gitleaks git --redact --no-banner
```

## 8. 生产镜像验证

发布前必须在可用的 Docker 环境执行：

```bash
docker build --target production -t secret-broker:verify .

docker run --rm --entrypoint sh secret-broker:verify -ec '
  test "$(id -u)" != "0"
  test -f /app/server.js
  test ! -e /app/.env
  for bin in node sops openssl ssh ssh-keygen git; do
    command -v "$bin" >/dev/null
  done
  if find /app -type f \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) | grep -q .; then
    echo "secret-like file found in production image" >&2
    exit 1
  fi
'
```

无法构建镜像时，不能把静态 Dockerfile 测试当作真实镜像验收的替代品。

## 9. SDK 独立验证

Python：

```bash
cd sdk/python
python -m pip install -r requirements-dev.txt
python run_tests.py
```

Go：

```bash
cd sdk/go
go vet ./broker/...
go test -race -count=1 -timeout=60s ./broker/...
```

VS Code 扩展：

```bash
cd sdk/vscode
npm ci
npx tsc -p . --noEmit
```

## 10. TLS 与线上健康检查

公共生产健康检查必须验证正式证书，禁止使用 `-k/--insecure`：

```bash
curl --fail --show-error --silent https://broker.52trz.com/health
```

预期返回：

```json
{"status":"ok"}
```

本地开发环境使用自建 CA 时，应显式指定 CA：

```bash
curl --fail --show-error \
  --cacert pki/ca/ca.crt \
  https://localhost:8443/health
```

认证接口还需提供对应客户端证书和私钥：

```bash
curl --fail --show-error \
  --cacert pki/ca/ca.crt \
  --cert ~/.broker/client.crt \
  --key ~/.broker/client.key \
  https://localhost:8443/api/v1/identity
```

## 11. 客户端私钥验收

安全默认下，管理员签发或轮换客户端证书时：

1. API/Dashboard 只返回一次 `key_pem` 和一次性 ZIP；
2. Broker 随后删除服务器上的客户端私钥文件；
3. 重复下载接口默认返回 410；
4. 只有显式设置 `BROKER_RETAIN_CLIENT_PRIVATE_KEYS=1` 才进入兼容保留模式；
5. 轮换后使用旧证书指纹建立的会话必须立即失效。

一次性私钥或 ZIP 不得写入日志、Git、聊天记录或长期浏览器存储。

## 12. 最终发布判定

只有以下项目全部通过，才可以创建发布 tag 或部署：

- `npm run quality:gate`
- `npm audit --omit=dev --audit-level=high`
- `npm run test:release-workflow`
- Shell 语法检查
- `git diff --check`
- 敏感文件与 gitleaks 检查
- 真实生产 Docker 镜像构建及运行时检查
- 在预发布环境完成 TLS、mTLS、API Key、MFA、代理和审计 smoke test

任何一项缺失都应明确标记为“未验证”，而不是推断通过。
