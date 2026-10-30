#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
test -f web/package.json
test -f web/src/App.tsx

if [ ! -d web/node_modules ]; then
  echo "installing web dependencies…"
  (cd web && npm install --no-fund --no-audit >/dev/null)
fi

(cd web && npm run typecheck)
(cd web && npm test -- --run)
echo "web checks passed"
