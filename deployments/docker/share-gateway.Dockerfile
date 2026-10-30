FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o /out/share-gateway ./cmd/share-gateway

FROM alpine:3.24.3
WORKDIR /app
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/share-gateway /app/share-gateway
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/storage-boxes/
LABEL org.opencontainers.image.licenses="Apache-2.0" org.opencontainers.image.version="0.5.0"
EXPOSE 8084
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8084/readyz || exit 1
ENTRYPOINT ["/app/share-gateway"]
