#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
total=$(find "$ROOT" -type f   -not -path '*/.git/*'   -not -path '*/dist/*'   -not -path '*/tmp/*'   -not -path '*/node_modules/*'   -not -path '*/coverage/*' | wc -l | tr -d ' ')
first_party=$(find "$ROOT" -type f   -not -path '*/.git/*'   -not -path '*/dist/*'   -not -path '*/tmp/*'   -not -path '*/node_modules/*'   -not -path '*/coverage/*'   -not -path '*/vendor/*' | wc -l | tr -d ' ')
echo "total=$total"
echo "first_party=$first_party"
test "$total" -ge 200
test "$first_party" -ge 120
