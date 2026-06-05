#!/usr/bin/env bash
# Run npm audit across prod+dev dependencies and fail on moderate+ findings.
# Set NPM_AUDIT_OMIT=dev to temporarily return to prod-only scanning.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

LEVEL="${NPM_AUDIT_LEVEL:-moderate}"
OMIT="${NPM_AUDIT_OMIT:-}"

args=(--audit-level="$LEVEL")
if [ -n "$OMIT" ]; then
  args+=(--omit="$OMIT")
fi

echo "Running npm audit (${args[*]})..."
npm audit "${args[@]}"
