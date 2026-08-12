# Multi-stage Dockerfile.
# `dev` target: full toolchain, hot reload, source mounted from host.
# `production` target: minimal runtime, distroless, runs as non-root.

# -------- dev stage --------
FROM node:20-alpine AS dev
WORKDIR /app
RUN apk add --no-cache curl
COPY app/package*.json ./
RUN npm install
COPY app/ ./app/
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:3000/health || exit 1
CMD ["node", "--watch", "app/index.js"]

# -------- production deps --------
FROM node:20-alpine AS deps
WORKDIR /app
COPY app/package*.json ./
RUN npm ci --omit=dev

# -------- production runtime --------
FROM gcr.io/distroless/nodejs20-debian12 AS production
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY app/ ./app/
EXPOSE 3000
USER nonroot
CMD ["app/index.js"]
