# Multi-stage Dockerfile for Secret Broker V4.1
# Targets:
#   dev        — full toolchain, hot reload, source mounted from host
#   production — Debian slim, non-root, with the runtime tools required by enabled features

# ============================================================
# Stage 1: install production dependencies
# ============================================================
FROM node:24-bookworm-slim AS deps
WORKDIR /build

# Require the lockfile: production builds must be deterministic.
COPY broker/package.json broker/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ============================================================
# Stage 2: standalone SOPS runtime binary
# ============================================================
FROM alpine:3.22 AS tools
ARG SOPS_VERSION=3.13.3
ARG TARGETARCH=amd64
RUN apk add --no-cache ca-certificates coreutils curl
COPY scripts/ci/install-sops.sh /tmp/install-sops.sh
RUN SOPS_VERSION="$SOPS_VERSION" SOPS_ARCH="$TARGETARCH" \
      sh /tmp/install-sops.sh /usr/local/bin/sops \
    && rm -f /tmp/install-sops.sh

# ============================================================
# Stage 3: dev (hot reload)
# ============================================================
FROM node:24-alpine AS dev
WORKDIR /app
RUN apk add --no-cache curl openssl

# Install all deps (including dev for test:verify, lint, etc.) from the lockfile.
COPY broker/package.json broker/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Copy source
COPY broker/ ./

# Generate ephemeral self-signed certs for dev convenience
# (override by mounting PKI_DIR=/pki at runtime for real certs)
RUN mkdir -p pki/server pki/ca pki/clients audit secrets && \
    openssl req -x509 -newkey rsa:2048 -nodes -keyout pki/ca/ca.key -out pki/ca/ca.crt -days 365 -subj '/CN=broker-dev-ca' && \
    openssl genrsa -out pki/server/server.key 2048 && \
    openssl req -new -key pki/server/server.key -out /tmp/server.csr -subj '/CN=localhost' && \
    openssl x509 -req -in /tmp/server.csr -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial -out pki/server/server.crt -days 365 && \
    touch pki/ca/crl.pem && \
    rm /tmp/server.csr pki/ca/ca.key pki/ca/ca.srl

EXPOSE 8443
ENV BROKER_BIND=0.0.0.0 \
    BROKER_PORT=8443 \
    NODE_ENV=development \
    PKI_DIR=/app/pki \
    AUDIT_DIR=/app/audit \
    SECRETS_DETAIL_PATH=/app/secrets/secrets-detail.json

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -kfsS https://127.0.0.1:8443/health || exit 1

CMD ["node", "server.js"]

# ============================================================
# Stage 4: production (minimal Debian, non-root)
# ============================================================
# The broker intentionally exposes certificate issuance, SSH proxying, SOPS
# decryption and git-backed rollback. Those features require openssl, ssh,
# ssh-keygen, sops and git at runtime, so a pure distroless image is incomplete.
FROM node:24-bookworm-slim AS production

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
      openssh-client \
      openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Keep production dependencies ABI-compatible with the Debian runtime.
COPY --from=deps --chown=node:node /build/node_modules ./node_modules
COPY --from=tools /usr/local/bin/sops /usr/local/bin/sops
COPY --chown=node:node broker/ ./

# Credentials and PKI are runtime mounts; the image contains no certificate,
# private key or decrypted secret material. Pre-create writable state paths.
RUN mkdir -p \
      /run/secrets/broker/pki \
      /var/lib/broker/audit \
      /var/lib/broker/secrets \
    && chown -R node:node /app /run/secrets/broker /var/lib/broker

ENV NODE_ENV=production \
    BROKER_BIND=0.0.0.0 \
    PORT=8443 \
    PKI_DIR=/run/secrets/broker/pki \
    TLS_CA=/run/secrets/broker/pki/ca/ca.crt \
    CA_KEY_PATH=/run/secrets/broker/pki/ca/ca.key \
    AUDIT_DIR=/var/lib/broker/audit \
    CONFIG_PATH=/var/lib/broker/secrets/broker.yaml \
    SECRETS_PATH=/var/lib/broker/secrets/common.env \
    SECRETS_DETAIL_PATH=/var/lib/broker/secrets/secrets-detail.json \
    SOPS_AGE_KEY_FILE=/run/secrets/broker/age/key.txt

USER node
EXPOSE 8443
ENTRYPOINT ["node", "server.js"]

# ============================================================
# Image metadata
# ============================================================
LABEL org.opencontainers.image.title="secret-broker" \
      org.opencontainers.image.description="AI-first mTLS secret broker with zero-credential-leakage" \
      org.opencontainers.image.source="https://github.com/tyj1987/broker" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="tyj1987"
