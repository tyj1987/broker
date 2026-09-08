# Multi-stage Dockerfile for Secret Broker V4.1
# Targets:
#   dev        — full toolchain, hot reload, source mounted from host
#   production — distroless, runs as non-root, minimal attack surface

# ============================================================
# Stage 1: install production dependencies
# ============================================================
FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS deps
WORKDIR /build

# Copy ONLY the manifest first for better Docker layer cache
COPY broker/package.json broker/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# ============================================================
# Stage 2: dev (hot reload)
# ============================================================
FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS dev
WORKDIR /app
RUN apk add --no-cache curl openssl

# Install all deps (including dev for test:verify, lint, etc.)
COPY broker/package.json broker/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

# Copy source
COPY broker/ ./

# Generate ephemeral self-signed certs for dev convenience
# (override by mounting PKI_DIR=/pki at runtime for real certs)
RUN mkdir -p pki/server pki/ca pki/clients audit secrets && \
    openssl req -x509 -newkey rsa:2048 -nodes -keyout pki/ca/ca.key -out pki/ca/ca.crt -days 365 -subj '/CN=broker-dev-ca' && \
    openssl genrsa -out pki/server/server.key 2048 && \
    openssl req -new -key pki/server/server.key -out /tmp/server.csr -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' && \
    openssl x509 -req -in /tmp/server.csr -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial -out pki/server/server.crt -days 365 -copy_extensions copy && \
    openssl genrsa -out pki/clients/client.health.key 2048 && \
    openssl req -new -key pki/clients/client.health.key -out /tmp/client.csr -subj '/CN=health-probe' && \
    openssl x509 -req -in /tmp/client.csr -CA pki/ca/ca.crt -CAkey pki/ca/ca.key -CAcreateserial -out pki/clients/client.health.crt -days 365 && \
    touch pki/ca/crl.pem && \
    rm /tmp/server.csr /tmp/client.csr pki/ca/ca.key pki/ca/ca.srl

EXPOSE 8443
ENV BROKER_BIND=0.0.0.0 \
    BROKER_PORT=8443 \
    NODE_ENV=development \
    PKI_DIR=/app/pki \
    AUDIT_DIR=/app/audit \
    SECRETS_DETAIL_PATH=/app/secrets/secrets-detail.json

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent --show-error --cacert pki/ca/ca.crt --cert pki/clients/client.health.crt --key pki/clients/client.health.key https://localhost:8443/health || exit 1

CMD ["node", "server.js"]

# ============================================================
# Stage 3: verified SOPS binary
# ============================================================
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS sops
ARG SOPS_VERSION=3.13.3
ARG SOPS_SHA256=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
RUN apk add --no-cache ca-certificates curl \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.amd64" \
      --output /usr/local/bin/sops \
    && echo "${SOPS_SHA256}  /usr/local/bin/sops" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/sops

# ============================================================
# Stage 4: Go policy core
# ============================================================
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS core-build
WORKDIR /src
COPY core/go.mod ./
COPY core/ ./
RUN CGO_ENABLED=0 go test ./... \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/secret-broker-policy ./cmd/policy-server

# ============================================================
# Stage 5: production (non-root; runtime supplies read-only rootfs)
# ============================================================
FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS production

WORKDIR /app

# Copy production node_modules from deps stage
COPY --from=deps /build/node_modules ./node_modules
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops
COPY --from=core-build /out/secret-broker-policy /app/bin/secret-broker-policy

# Copy broker source
COPY broker/ ./

ENV NODE_ENV=production \
    PKI_DIR=/run/secrets/broker/pki \
    AUDIT_DIR=/var/lib/broker/audit \
    BROKER_HEALTH_BIND=127.0.0.1:9080 \
    SECRETS_DETAIL_PATH=/var/lib/broker/secrets/secrets-detail.json

EXPOSE 8443

# distroless has no shell/curl — healthcheck must be ENTRYPOINT-side
# or use a separate probe. The helm chart uses startup + readiness probes.

USER 65532:65532
CMD ["node", "server.js"]

# ============================================================
# Image metadata
# ============================================================
LABEL org.opencontainers.image.title="secret-broker" \
      org.opencontainers.image.description="Policy-enforced credential broker for typed operations" \
      org.opencontainers.image.source="https://github.com/tyj1987/broker" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="tyj1987"
