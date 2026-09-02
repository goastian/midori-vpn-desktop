#!/usr/bin/env bash
# Build the Go agent into agent/target/release/.
set -Eeuo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/../agent" && pwd)"
OUT_DIR="$AGENT_DIR/target/release"
TARGET="${1:-host}"

: "${GOCACHE:=${TMPDIR:-/tmp}/midorivpn-go-build-cache}"
export GOCACHE

mkdir -p "$OUT_DIR"

# Rebuilding must be non-destructive by default: this script is used by normal
# local and CI package builds. Use RESET_MIDORIVPN_USER_DATA=1 for an explicit
# clean-room dev run that wipes user-scoped state (tokens, keystore, settings).
if [ "${RESET_MIDORIVPN_USER_DATA:-0}" = "1" ]; then
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
  host           Build the canonical Linux x86_64 agent
  linux-amd64    Build Linux x86_64 as agent
  linux-arm64    Build Linux arm64 as agent-linux-arm64
  all            Build Linux production targets only

Environment:
  RESET_MIDORIVPN_USER_DATA=1  Wipe local MidoriVPN user state before building
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
  build_agent linux amd64 "$OUT_DIR/agent"
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
  all)
    build_agent linux amd64 "$OUT_DIR/agent"
    build_agent linux arm64 "$OUT_DIR/agent-linux-arm64"
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
