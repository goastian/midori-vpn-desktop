#!/usr/bin/env bash
# Build the Go agent for multiple platforms and place binaries in agent/target/release/
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
OUT_DIR="$AGENT_DIR/target/release"
mkdir -p "$OUT_DIR"

echo "Building agent from $AGENT_DIR..."

build_agent() {
  local os=$1 arch=$2 out=$3
  echo "→ $os/$arch"
  (cd "$AGENT_DIR" && GOOS=$os GOARCH=$arch go build -o "$out" ./cmd/agent)
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
