#!/usr/bin/env bash
# Backend CI: lint, build, test. Frontend checks live in their own CI job
# (see .github/workflows/ci.yml) so Go runners don't need Node.
set -euo pipefail

cd "$(dirname "$0")/.."

bash ./scripts/lint.sh

echo "==> go build"
CGO_ENABLED=0 go build ./...

bash ./scripts/test-unit.sh
bash ./scripts/test-integration.sh
bash ./scripts/test-migrations.sh
