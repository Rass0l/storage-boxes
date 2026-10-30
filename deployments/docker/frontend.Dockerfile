FROM node:25-alpine AS build
WORKDIR /app
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY web/package.json ./
COPY web/package-lock.json* ./
COPY web/ ./
RUN npm ci --no-fund --no-audit && npm run build

FROM nginx:1.30.6-alpine
COPY deployments/docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/storage-boxes/
LABEL org.opencontainers.image.licenses="Apache-2.0" org.opencontainers.image.version="0.5.0"
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1/_edge_healthz || exit 1
