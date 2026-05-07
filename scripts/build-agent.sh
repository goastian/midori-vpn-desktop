#!/usr/bin/env bash
# Build the Go agent into agent/target/release/.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
OUT_DIR="$AGENT_DIR/target/release"
TARGET="${1:-host}"

: "${GOCACHE:=${TMPDIR:-/tmp}/midorivpn-go-build-cache}"
export GOCACHE

mkdir -p "$OUT_DIR"

usage() {
  cat <<'EOF'
Usage: scripts/build-agent.sh [target]

Targets:
  host           Build the current host target as the canonical Tauri resource
  linux-amd64    Build Linux x86_64 as agent
  linux-arm64    Build Linux arm64 as agent-linux-arm64
  darwin-arm64   Build macOS Apple Silicon as agent
  darwin-amd64   Build macOS Intel as agent
  windows-amd64  Build Windows x86_64 as agent.exe
  all            Build every supported target
EOF
}

build_agent() {
  local os=$1 arch=$2 out=$3
  echo "Building agent $os/$arch -> $out"
  (
    cd "$AGENT_DIR"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath \
        -ldflags="-s -w" \
        -o "$out" ./cmd/agent
  )
}

host_target() {
  local os arch out
  os="$(go env GOOS)"
  arch="$(go env GOARCH)"
  out="$OUT_DIR/agent"

  if [ "$os" = "windows" ]; then
    out="$OUT_DIR/agent.exe"
  fi

  build_agent "$os" "$arch" "$out"
  if [ "$os" = "windows" ]; then
    cp "$OUT_DIR/agent.exe" "$OUT_DIR/agent"
  fi
}

case "$TARGET" in
  host)
    host_target
    ;;
  linux-amd64)
    build_agent linux amd64 "$OUT_DIR/agent"
    ;;
  linux-arm64)
    build_agent linux arm64 "$OUT_DIR/agent-linux-arm64"
    ;;
  darwin-arm64)
    build_agent darwin arm64 "$OUT_DIR/agent"
    cp "$OUT_DIR/agent" "$OUT_DIR/agent-darwin-arm64"
    ;;
  darwin-amd64)
    build_agent darwin amd64 "$OUT_DIR/agent"
    cp "$OUT_DIR/agent" "$OUT_DIR/agent-darwin-amd64"
    ;;
  windows-amd64)
    build_agent windows amd64 "$OUT_DIR/agent.exe"
    cp "$OUT_DIR/agent.exe" "$OUT_DIR/agent"
    ;;
  all)
    build_agent linux amd64 "$OUT_DIR/agent"
    build_agent linux arm64 "$OUT_DIR/agent-linux-arm64"
    build_agent darwin arm64 "$OUT_DIR/agent-darwin-arm64"
    build_agent darwin amd64 "$OUT_DIR/agent-darwin-amd64"
    build_agent windows amd64 "$OUT_DIR/agent.exe"
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

echo "Done. Binaries in $OUT_DIR:"
ls -lh "$OUT_DIR"
