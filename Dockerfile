# Multi-stage Dockerfile for Secret Broker V4.1
# Targets:
#   dev        — full toolchain, hot reload, source mounted from host
#   production — pinned Alpine runtime, non-root, reduced attack surface

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
COPY tools/ ./tools/

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
# Stage 3: SOPS built from a verified source archive and patched dependencies
# ============================================================
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS sops-build
ARG SOPS_VERSION=3.13.3
ARG SOPS_SOURCE_SHA256=49811c5ed80f6b4d4e98cef98e3f7378406aa692fd773dfb72ad1b4dfb940448
RUN apk add --no-cache ca-certificates curl tar \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/getsops/sops/archive/refs/tags/v${SOPS_VERSION}.tar.gz" \
      --output /tmp/sops.tar.gz \
    && echo "${SOPS_SOURCE_SHA256}  /tmp/sops.tar.gz" | sha256sum -c - \
    && mkdir /src \
    && tar -xzf /tmp/sops.tar.gz --strip-components=1 -C /src \
    && rm /tmp/sops.tar.gz
WORKDIR /src
# The upstream v3.13.3 binaries predate these security releases. Build the
# signed tag with patched direct dependencies and the repository's pinned Go.
RUN go mod edit \
      -require=golang.org/x/crypto@v0.55.0 \
      -require=google.golang.org/grpc@v1.83.1 \
    && CGO_ENABLED=0 go build -mod=mod -trimpath -buildvcs=false \
      -ldflags='-s -w' -o /out/sops ./cmd/sops \
    && /out/sops --version

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
# Stage 5: production (non-root; deployment supplies a read-only rootfs)
# ============================================================
FROM node:24.20.0-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS production

WORKDIR /app

# Apply Alpine security fixes available for the pinned release and remove the
# package-manager toolchain, which is unnecessary at runtime.
RUN apk upgrade --no-cache libcrypto3 libssl3 \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Copy production node_modules from deps stage
COPY --from=deps /build/node_modules ./node_modules
COPY --from=sops-build /out/sops /usr/local/bin/sops
COPY --from=core-build /out/secret-broker-policy /app/bin/secret-broker-policy

# Copy broker source
COPY broker/ ./
COPY tools/ ./tools/
RUN rm -f package-lock.json

ENV NODE_ENV=production \
    PKI_DIR=/run/secrets/broker/pki \
    AUDIT_DIR=/var/lib/broker/audit \
    BROKER_HEALTH_BIND=127.0.0.1:9080 \
    SECRETS_DETAIL_PATH=/var/lib/broker/secrets/secrets-detail.json

EXPOSE 8443

# Health checks are supplied by the deployment. The Helm chart defines startup
# and readiness probes without embedding credentials in the image.

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
