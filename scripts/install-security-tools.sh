#!/usr/bin/env bash
# Install pinned security scanners used by CI and local release checks.
set -euo pipefail

tool="${1:-all}"

: "${CARGO_AUDIT_VERSION:=0.22.1}"
: "${GOVULNCHECK_VERSION:=v1.3.0}"

install_cargo_audit() {
  cargo install cargo-audit --version "$CARGO_AUDIT_VERSION" --locked
}

install_govulncheck() {
  go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
}

case "$tool" in
  all)
    install_cargo_audit
    install_govulncheck
    ;;
  cargo-audit)
    install_cargo_audit
    ;;
  govulncheck)
    install_govulncheck
    ;;
  *)
    echo "usage: $0 [all|cargo-audit|govulncheck]" >&2
    exit 2
    ;;
esac
