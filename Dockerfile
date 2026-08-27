# Pinned to an exact patch version so builds are reproducible.
FROM node:22.11.0-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src/ ./src/
COPY tsconfig.json ./
RUN npm run build

FROM node:22.11.0-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist/ ./dist/
# The OAuth store defaults to ./.easypanel-mcp-oauth.json, so /app must be writable
# by the unprivileged user the container runs as.
RUN chown -R node:node /app
# HTTP mode requires MCP_API_KEY at runtime (bearer auth); the server refuses to
# start without it instead of serving every tool unauthenticated.
ENV EASYPANEL_MCP_MODE=http
ENV PORT=3000
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" > /dev/null || exit 1
CMD ["node", "dist/index.js"]
