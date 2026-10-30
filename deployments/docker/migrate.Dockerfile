FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o /out/migrate ./cmd/migrate

FROM alpine:3.24.3
WORKDIR /app
RUN apk add --no-cache ca-certificates postgresql16-client
COPY --from=build /out/migrate /app/migrate
COPY migrations /app/migrations
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/storage-boxes/
LABEL org.opencontainers.image.licenses="Apache-2.0" org.opencontainers.image.version="0.5.0"
ENTRYPOINT ["/app/migrate"]
