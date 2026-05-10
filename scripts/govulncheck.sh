#!/usr/bin/env bash
# Run govulncheck with a writable, deterministic cache.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
: "${GOCACHE:=/tmp/midori-vpn-core-go-cache}"
export GOCACHE
mkdir -p "$GOCACHE"

if [ -n "${GOVULNCHECK_BIN:-}" ]; then
  vuln_cmd="$GOVULNCHECK_BIN"
else
  vuln_cmd="$(go env GOPATH)/bin/govulncheck"
fi

cd "$ROOT_DIR/agent"
"$vuln_cmd" ./...
