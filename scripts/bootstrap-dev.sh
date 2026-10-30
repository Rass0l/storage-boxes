#!/usr/bin/env bash
# Prepare the repo for a local developer: copy .env if missing, announce
# the canonical next steps.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "created .env from .env.example"
else
  echo ".env already present; leaving it alone"
fi

cat <<'TXT'
Next steps:
  make compose-up        # build + start the full stack
  make web-check         # typecheck + Vitest flows
  make compose-e2e       # full compose-backed Go e2e
  make compose-ui-e2e    # Playwright flows (requires compose-up)
TXT
