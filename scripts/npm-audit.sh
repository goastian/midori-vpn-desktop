#!/usr/bin/env bash
# Run npm audit on production dependencies and fail on high/critical findings.
# This mirrors the posture of scripts/cargo-audit.sh and scripts/govulncheck.sh
# so all three toolchains (Node, Rust, Go) are scanned consistently.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

LEVEL="${NPM_AUDIT_LEVEL:-high}"

echo "Running npm audit (--omit=dev --audit-level=$LEVEL)..."
npm audit --omit=dev --audit-level="$LEVEL"
