#!/usr/bin/env bash
# Lightweight lint: gofmt diff + go vet. Real linters (staticcheck/golangci)
# can be layered on later without breaking this contract.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> gofmt"
diff=$(gofmt -l $(find . -name '*.go' -not -path './vendor/*' -not -path './web/node_modules/*'))
if [ -n "$diff" ]; then
  echo "gofmt diff:" >&2
  echo "$diff" >&2
  exit 1
fi

echo "==> go vet"
CGO_ENABLED=0 go vet ./...

echo "==> go vet compose_e2e tag (offline compile check)"
CGO_ENABLED=0 go vet -tags=compose_e2e ./...
