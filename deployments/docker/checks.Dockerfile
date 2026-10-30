FROM golang:1.27.3-alpine
RUN apk add --no-cache bash tar coreutils postgresql-client
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
CMD ["bash", "scripts/ci-verify.sh"]
