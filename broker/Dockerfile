# Dockerfile for Secret Broker
# 多阶段构建：先安装 sops 工具到 slim 镜像
FROM node:20-slim AS runtime

# 安装 sops 和 age（broker 启动时要解密 SOPS 加密的配置）
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates gnupg age openssl \
    && curl -fsSL https://github.com/getsops/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64 \
       -o /usr/local/bin/sops \
    && chmod +x /usr/local/bin/sops \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户跑 broker
RUN groupadd -r broker && useradd -r -g broker -d /opt/broker -s /sbin/nologin broker

WORKDIR /opt/broker

# 安装依赖（缓存层）
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# 复制代码
COPY server.js ./
COPY dashboard ./dashboard

# 准备数据目录（pki/secrets/audit 挂载进来）
RUN mkdir -p /opt/broker/data/secrets /opt/broker/data/pki /opt/broker/data/audit /opt/broker/data/age \
    && chown -R broker:broker /opt/broker

USER broker

ENV NODE_ENV=production \
    PORT=8443 \
    HOST=0.0.0.0 \
    CONFIG_PATH=/opt/broker/data/secrets/broker.yaml \
    SECRETS_PATH=/opt/broker/data/secrets/common.env \
    PKI_DIR=/opt/broker/data/pki \
    AUDIT_DIR=/opt/broker/data/audit \
    AGE_KEY_FILE=/opt/broker/data/age/key.txt

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('node:https').get({host:'localhost',port:process.env.PORT,rejectUnauthorized:false,requestCert:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))" || exit 1

CMD ["node", "server.js"]
