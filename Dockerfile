# Multi-stage Dockerfile for Secret Broker V4.1
# Targets:
#   dev        — full toolchain, hot reload, source mounted from host
#   production — distroless, runs as non-root, minimal attack surface

# ============================================================
# Stage 1: install production dependencies
# ============================================================
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS deps
WORKDIR /build

# Copy ONLY the manifest first for better Docker layer cache
COPY broker/package.json broker/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ============================================================
# Stage 2: dev (hot reload)
# ============================================================
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS dev
WORKDIR /app
RUN apk add --no-cache curl openssl

# Install all deps (including dev for test:verify, lint, etc.)
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
# Stage 3: production (distroless, non-root)
# ============================================================
FROM ghcr.io/getsops/sops:v3.13.3@sha256:857f5a151ac0b2bfc55c1e4e5581d66fb8e268e4d106b38e74191f3bac9d58ea AS sops

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:774b7d020b24214835769e24c3544835526cd0288f0b094eae48e8b2c2429a79 AS production

WORKDIR /app

# Copy production node_modules from deps stage
COPY --from=deps /build/node_modules ./node_modules
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops

# Copy broker source
COPY broker/ ./

# Copy CA certs/clients templates (caller mounts PKI_DIR for runtime certs)
COPY --chown=nonroot:nonroot pki/ ./pki-template/

ENV NODE_ENV=production \
    PKI_DIR=/run/secrets/broker/pki \
    AUDIT_DIR=/var/lib/broker/audit \
    SECRETS_DETAIL_PATH=/var/lib/broker/secrets/secrets-detail.json \
    HEALTH_SOCKET_PATH=/tmp/broker-health.sock

EXPOSE 8443

# distroless has no shell/curl — healthcheck must be ENTRYPOINT-side
# or use a separate probe. The helm chart uses startup + readiness probes.

# nonroot is the default user in distroless nonroot variant
CMD ["server.js"]

# ============================================================
# Image metadata
# ============================================================
LABEL org.opencontainers.image.title="secret-broker" \
      org.opencontainers.image.description="AI-first mTLS secret broker with zero-credential-leakage" \
      org.opencontainers.image.source="https://github.com/tyj1987/broker" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="tyj1987"
