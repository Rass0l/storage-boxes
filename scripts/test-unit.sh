#!/usr/bin/env bash
# Fast docker-less Go suite. Uses the memory-mode stores.
set -euo pipefail

cd "$(dirname "$0")/.."

CGO_ENABLED=0 go test ./cmd/... ./internal/... ./test/helpers/...
