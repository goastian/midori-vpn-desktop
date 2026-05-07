#!/usr/bin/env bash
# Run cargo-audit with the documented MidoriVPN advisory policy.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TAURI_DIR="$ROOT_DIR/src-tauri"
POLICY_FILE="$TAURI_DIR/audit.toml"

ignore_args=()
while IFS= read -r advisory_id; do
  ignore_args+=(--ignore "$advisory_id")
done < <(sed -n 's/^[[:space:]]*"\(RUSTSEC-[0-9-]*\)".*/\1/p' "$POLICY_FILE")

if [ -n "${CARGO_AUDIT_BIN:-}" ]; then
  audit_cmd=("$CARGO_AUDIT_BIN" audit)
elif command -v cargo-audit >/dev/null 2>&1; then
  audit_cmd=(cargo-audit audit)
else
  audit_cmd=(cargo audit)
fi

(
  cd "$TAURI_DIR"
  "${audit_cmd[@]}" --deny warnings "${ignore_args[@]}" "$@"
)
