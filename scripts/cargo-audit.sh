#!/usr/bin/env bash
# Run cargo-audit with the documented MidoriVPN advisory policy.
set -Eeuo pipefail

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/src-tauri"
POLICY_FILE="$TAURI_DIR/audit.toml"
PODMAN_RUNNER="$ROOT_DIR/../scripts/pod.sh"

[[ -f "$PODMAN_RUNNER" ]] || die "Podman runner not found: $PODMAN_RUNNER"

ignore_args=()
while IFS= read -r advisory_id; do
  ignore_args+=(--ignore "$advisory_id")
done < <(sed -n 's/^[[:space:]]*"\(RUSTSEC-[0-9-]*\)".*/\1/p' "$POLICY_FILE")

(
  cd "$TAURI_DIR"
  exec bash "$PODMAN_RUNNER" cargo audit --deny warnings "${ignore_args[@]}" "$@"
)
