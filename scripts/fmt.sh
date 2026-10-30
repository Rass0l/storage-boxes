#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

gofmt -w $(find . -name '*.go' -not -path './vendor/*' -not -path './web/node_modules/*')
