#!/usr/bin/env bash
# Build the Go agent for multiple platforms and place binaries in agent/target/release/
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
DESKTOP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$AGENT_DIR/target/release"
mkdir -p "$OUT_DIR"

# ── Read AGENT_ALLOWED_ORIGIN from .env (optional) ───────────────────────────
# Priority: env var > .env.production > .env > hardcoded default.
# This value is baked into the binary at compile time via ldflags.
ALLOWED_ORIGIN="${AGENT_ALLOWED_ORIGIN:-}"
for envfile in "$DESKTOP_DIR/.env.production" "$DESKTOP_DIR/.env"; do
  if [[ -z "$ALLOWED_ORIGIN" && -f "$envfile" ]]; then
    val=$(grep -E '^AGENT_ALLOWED_ORIGIN=' "$envfile" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'" | tr -d "'")
    [[ -n "$val" ]] && ALLOWED_ORIGIN="$val"
  fi
done
ALLOWED_ORIGIN="${ALLOWED_ORIGIN:-tauri://localhost}"
echo "→ AllowedOrigin: $ALLOWED_ORIGIN"

echo "Building agent from $AGENT_DIR..."

build_agent() {
  local os=$1 arch=$2 out=$3
  echo "→ $os/$arch"
  # CGO disabled → fully static binary, portable across glibc versions.
  # -s -w → strip symbol table + DWARF, ~30% smaller binary.
  # -trimpath → reproducible builds, no $HOME leaked into stack traces.
  # AllowedOrigin baked via ldflags so it cannot be changed at runtime.
  (cd "$AGENT_DIR" && \
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -trimpath \
      -ldflags="-s -w -X github.com/goastian/midorivpn-agent/internal/config.AllowedOrigin=${ALLOWED_ORIGIN}" \
      -o "$out" ./cmd/agent)
}

# Linux AMD64 (primary — also used by Tauri sidecar)
build_agent linux amd64 "$OUT_DIR/agent"

# Linux ARM64
build_agent linux arm64 "$OUT_DIR/agent-linux-arm64"

# macOS ARM64 (Apple Silicon)
build_agent darwin arm64 "$OUT_DIR/agent-darwin-arm64"

# macOS AMD64
build_agent darwin amd64 "$OUT_DIR/agent-darwin-amd64"

# Windows AMD64
build_agent windows amd64 "$OUT_DIR/agent.exe"

echo "Done. Binaries in $OUT_DIR:"
ls -lh "$OUT_DIR"
