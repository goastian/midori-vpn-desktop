#!/usr/bin/env bash
# Build the Go agent into agent/target/release/.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
OUT_DIR="$AGENT_DIR/target/release"
TARGET="${1:-host}"

: "${GOCACHE:=${TMPDIR:-/tmp}/midorivpn-go-build-cache}"
export GOCACHE

mkdir -p "$OUT_DIR"

# When rebuilding, wipe the user-scoped state (tokens, keystore, settings).
# Avoids stale credentials / mesh keys leaking across iterations. Honour
# KEEP_USER_DATA=1 if a caller needs to preserve the directory.
if [ "${KEEP_USER_DATA:-0}" != "1" ]; then
  for dir in \
    "${XDG_CONFIG_HOME:-$HOME/.config}/midorivpn" \
    "${XDG_DATA_HOME:-$HOME/.local/share}/midorivpn" \
    "${XDG_STATE_HOME:-$HOME/.local/state}/midorivpn"
  do
    if [ -d "$dir" ]; then
      echo "Removing user state at $dir"
      rm -rf -- "$dir"
    fi
  done

  # Drop any lingering file capabilities on the installed agent so the next
  # run of the desktop app re-triggers the smart-grant prompt and re-applies
  # the correct cap set for the host's DNS backend. We do this best-effort
  # (no sudo prompt): only run if the user can already write the inode.
  installed="/usr/local/bin/midorivpn-agent"
  if [ -w "$installed" ] && command -v setcap >/dev/null 2>&1; then
    if getcap "$installed" 2>/dev/null | grep -q cap_; then
      echo "Clearing file capabilities on $installed"
      setcap -r "$installed" 2>/dev/null || true
    fi
  fi
fi

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

copy_if_distinct() {
  local src=$1 dst=$2

  if [ ! -e "$src" ]; then
    echo "copy_if_distinct: source missing: $src" >&2
    return 1
  fi

  # When src and dst already resolve to the same inode `cp` would error out
  # with "input and output are the same file". Skip in that case. On Windows
  # Git Bash `-ef` may behave differently, so we guard with `2>/dev/null`.
  if [ -e "$dst" ] && [ "$src" -ef "$dst" ] 2>/dev/null; then
    echo "copy_if_distinct: $dst already mirrors $src; skipping copy"
    return 0
  fi

  # Remove any pre-existing destination first to side-step Windows runners
  # where `cp -f` over an in-use file silently no-ops.
  rm -f "$dst"
  cp "$src" "$dst"
  echo "copy_if_distinct: copied $src -> $dst"
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
    copy_if_distinct "$OUT_DIR/agent.exe" "$OUT_DIR/agent"
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
    build_agent linux arm64 "$OUT_DIR/agent"
    cp "$OUT_DIR/agent" "$OUT_DIR/agent-linux-arm64"
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
    copy_if_distinct "$OUT_DIR/agent.exe" "$OUT_DIR/agent"
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
