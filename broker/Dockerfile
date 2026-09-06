# Compatibility build entrypoint for callers using `docker build broker/`.
# The repository-root Dockerfile is canonical for release builds.
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS deps
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM ghcr.io/getsops/sops:v3.13.3@sha256:857f5a151ac0b2bfc55c1e4e5581d66fb8e268e4d106b38e74191f3bac9d58ea AS sops

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:774b7d020b24214835769e24c3544835526cd0288f0b094eae48e8b2c2429a79 AS production
WORKDIR /app
COPY --from=deps /build/node_modules ./node_modules
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops
COPY . ./

ENV NODE_ENV=production \
    CONFIG_PATH=/run/secrets/broker/broker.yaml \
    PKI_DIR=/run/secrets/broker/pki \
    AUDIT_DIR=/var/lib/broker/audit \
    SECRETS_DETAIL_PATH=/var/lib/broker/secrets/secrets-detail.json \
    HEALTH_SOCKET_PATH=/tmp/broker-health.sock

EXPOSE 8443
CMD ["server.js"]
